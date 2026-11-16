//! EAPOL-Key parsing, 4-way handshake assembly, PMKID capture and quality checks.
//!
//! Ported behaviour from ESP32 Marauder (`WiFiScan.cpp` EAPOL handling) and
//! GhostESP (`main/attacks/wifi/eapol_logoff.c`), rebuilt as a bounded state
//! machine with verification instead of fire-and-forget logging:
//!
//! * every message is validated (descriptor type, key-info flags, length);
//! * ANonce/SNonce/Replay/MIC are stored per (AP, client) pair;
//! * PMKID is extracted from the message-1 key-data KDE;
//! * the captured EAPOL is verified against a passphrase on device
//!   (`PBKDF2 -> PMK -> PTK -> MIC`), so "captured a handshake" is not confused
//!   with "the handshake is usable";
//! * exports a hashcat `WPA*01/02` line for offline workstations.

use alloc::string::String;
use alloc::vec::Vec;

use crate::net::MacAddr;
use crate::util::{hex_encode, read_u16_be};

use super::ap::Ssid;
use super::crypto::{
    PMKID_LEN, PairwiseKeys, compute_mic, derive_pmk, derive_pmkid, derive_ptk, mic_matches,
};

/// Offset of the MIC field inside an EAPOL-Key frame.
pub const MIC_OFFSET: usize = 81;
/// Offset of the key-data field length.
pub const KEY_DATA_LEN_OFFSET: usize = 97;
/// Minimum EAPOL-Key frame length (no key data).
pub const MIN_EAPOL_KEY_LEN: usize = 99;

/// `key_info` flag: access point acknowledges (messages 1 and 3).
pub const KEY_INFO_ACK: u16 = 0x0080;
/// `key_info` flag: MIC is present (messages 2, 3, 4).
pub const KEY_INFO_MIC: u16 = 0x0100;
/// `key_info` flag: install the pairwise key (message 3).
pub const KEY_INFO_INSTALL: u16 = 0x0040;
/// `key_info` flag: secure bit.
pub const KEY_INFO_SECURE: u16 = 0x0200;
/// `key_info` flag: key data is encrypted (message 3).
pub const KEY_INFO_ENCRYPTED: u16 = 0x1000;

/// PMKID KDE prefix: `dd 14 00 0f ac 04`.
pub const PMKID_KDE_PREFIX: [u8; 6] = [0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];

/// RSN key descriptor (WPA2).
pub const DESCRIPTOR_RSN: u8 = 2;
/// WPA key descriptor.
pub const DESCRIPTOR_WPA: u8 = 254;

/// Which 4-way-handshake message a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMessage {
    Message1,
    Message2,
    Message3,
    Message4,
    Unknown,
}

impl HandshakeMessage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Message1 => "M1",
            Self::Message2 => "M2",
            Self::Message3 => "M3",
            Self::Message4 => "M4",
            Self::Unknown => "??",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Message1 => 1 << 0,
            Self::Message2 => 1 << 1,
            Self::Message3 => 1 << 2,
            Self::Message4 => 1 << 3,
            Self::Unknown => 0,
        }
    }
}

/// Parsed EAPOL-Key frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EapolKey<'a> {
    pub descriptor: u8,
    pub key_info: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub key_data: &'a [u8],
    pub message: HandshakeMessage,
}

impl<'a> EapolKey<'a> {
    /// Parse and classify an EAPOL-Key frame. Returns `None` for anything that is
    /// not a well-formed EAPOL-Key (never panics on truncated input).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        // 802.1X header: version, packet type 3 (EAPOL-Key), 2-byte body length.
        if data.len() < MIN_EAPOL_KEY_LEN || data[1] != 3 {
            return None;
        }
        let body_len = usize::from(read_u16_be(data, 2)?);
        if body_len + 4 > data.len() {
            return None;
        }
        let key_info = read_u16_be(data, 5)?;
        let key_length = read_u16_be(data, 7)?;
        let mut replay_bytes = [0u8; 8];
        replay_bytes.copy_from_slice(&data[9..17]);
        let replay_counter = u64::from_be_bytes(replay_bytes);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[17..49]);
        let mut mic = [0u8; 16];
        mic.copy_from_slice(&data[MIC_OFFSET..MIC_OFFSET + 16]);
        let key_data_len = usize::from(read_u16_be(data, KEY_DATA_LEN_OFFSET)?);
        let key_data = data
            .get(MIN_EAPOL_KEY_LEN..MIN_EAPOL_KEY_LEN + key_data_len)
            .unwrap_or(&[]);

        let has_mic = key_info & KEY_INFO_MIC != 0;
        let ack = key_info & KEY_INFO_ACK != 0;
        let install = key_info & KEY_INFO_INSTALL != 0;
        let nonce_zero = nonce.iter().all(|b| *b == 0);
        let message = match (has_mic, ack, install, nonce_zero) {
            (false, true, _, _) => HandshakeMessage::Message1,
            (true, true, true, _) => HandshakeMessage::Message3,
            (true, false, false, true) => HandshakeMessage::Message4,
            (true, false, false, false) => HandshakeMessage::Message2,
            _ => HandshakeMessage::Unknown,
        };

        Some(Self {
            descriptor: data[4],
            key_info,
            key_length,
            replay_counter,
            nonce,
            mic,
            key_data,
            message,
        })
    }

    /// PMKID carried in message 1's key data, if present.
    pub fn pmkid(&self) -> Option<[u8; PMKID_LEN]> {
        let data = self.key_data;
        let mut idx = 0;
        while idx + 22 <= data.len() {
            if data[idx..idx + 6] == PMKID_KDE_PREFIX {
                let mut pmkid = [0u8; PMKID_LEN];
                pmkid.copy_from_slice(&data[idx + 6..idx + 22]);
                return Some(pmkid);
            }
            idx += 1;
        }
        None
    }
}

/// How useful a captured handshake is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeQuality {
    /// M1 + M2 (or M3) with a MIC: crackable and verifiable.
    Complete,
    /// M1 only: gives a PMKID but no PTK/MIC.
    PmkidOnly,
    /// Client MIC without the AP nonce.
    PartialClient,
    /// Nothing usable.
    Unusable,
}

impl HandshakeQuality {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PmkidOnly => "PMKID only",
            Self::PartialClient => "partial",
            Self::Unusable => "unusable",
        }
    }
}

/// Passphrase verification result for one captured handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    MicValid,
    MicInvalid,
    /// The capture is missing the material needed to compute a MIC.
    NeedMoreData,
}

/// One (AP, client) 4-way handshake under assembly.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub ap: MacAddr,
    pub client: MacAddr,
    pub ssid: Ssid,
    pub channel: u8,
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub mic: [u8; 16],
    pub replay_counter: u64,
    /// EAPOL frame used for MIC computation (message 2 when available).
    pub eapol: Vec<u8>,
    pub pmkid: Option<[u8; PMKID_LEN]>,
    /// Bitmask of the messages seen (bit0 = M1 .. bit3 = M4).
    pub messages: u8,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl Handshake {
    fn empty(ap: MacAddr, client: MacAddr, ssid: Ssid, channel: u8, now_ms: u64) -> Self {
        Self {
            ap,
            client,
            ssid,
            channel,
            anonce: [0; 32],
            snonce: [0; 32],
            mic: [0; 16],
            replay_counter: 0,
            eapol: Vec::new(),
            pmkid: None,
            messages: 0,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    pub fn has_anonce(&self) -> bool {
        self.messages & HandshakeMessage::Message1.bit() != 0
    }

    pub fn has_snonce(&self) -> bool {
        self.messages & HandshakeMessage::Message2.bit() != 0
    }

    pub fn has_mic(&self) -> bool {
        self.messages & (HandshakeMessage::Message2.bit() | HandshakeMessage::Message4.bit()) != 0
    }

    pub fn quality(&self) -> HandshakeQuality {
        if self.has_anonce() && self.has_mic() && !self.eapol.is_empty() {
            HandshakeQuality::Complete
        } else if self.pmkid.is_some() {
            HandshakeQuality::PmkidOnly
        } else if self.has_mic() {
            HandshakeQuality::PartialClient
        } else {
            HandshakeQuality::Unusable
        }
    }

    /// Messages seen, e.g. `"M1 M2"`.
    pub fn message_list(&self) -> String {
        let mut out = String::new();
        for (idx, msg) in [
            HandshakeMessage::Message1,
            HandshakeMessage::Message2,
            HandshakeMessage::Message3,
            HandshakeMessage::Message4,
        ]
        .iter()
        .enumerate()
        {
            if self.messages & (1 << idx) != 0 {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(msg.label());
            }
        }
        out
    }

    /// Verify a candidate passphrase against this capture, on device.
    pub fn verify_passphrase(&self, passphrase: &[u8]) -> Verification {
        if !self.has_anonce() || !self.has_mic() || self.eapol.len() < MIN_EAPOL_KEY_LEN {
            return Verification::NeedMoreData;
        }
        let pmk = derive_pmk(passphrase, self.ssid.as_bytes());
        let keys: PairwiseKeys = derive_ptk(
            &pmk,
            self.ap.as_bytes(),
            self.client.as_bytes(),
            &self.anonce,
            &self.snonce,
        );
        let mut frame = self.eapol.clone();
        if frame.len() < MIC_OFFSET + 16 {
            return Verification::NeedMoreData;
        }
        // The MIC field must be zeroed before computing the HMAC.
        for byte in &mut frame[MIC_OFFSET..MIC_OFFSET + 16] {
            *byte = 0;
        }
        let expected = compute_mic(&keys.kck, &frame);
        if mic_matches(&expected, &self.mic) {
            Verification::MicValid
        } else {
            Verification::MicInvalid
        }
    }

    /// Derive the PMKID for a candidate passphrase (lab verification helper).
    pub fn pmkid_for_passphrase(&self, passphrase: &[u8]) -> [u8; PMKID_LEN] {
        let pmk = derive_pmk(passphrase, self.ssid.as_bytes());
        derive_pmkid(&pmk, self.ap.as_bytes(), self.client.as_bytes())
    }

    /// hashcat 22000 line for this handshake, when the capture is usable.
    ///
    /// The message-pair byte follows the hcxtools convention: `00` for M1+M2,
    /// `01` when only M1+M4 was captured.
    pub fn hc22000(&self) -> Option<String> {
        if self.eapol.is_empty() || self.ssid.is_empty() || !self.has_anonce() {
            return None;
        }
        let has_m2 = self.messages & HandshakeMessage::Message2.bit() != 0;
        let pair = if has_m2 { "00" } else { "01" };
        Some(alloc::format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*{}",
            hex_encode(&self.mic),
            hex_encode(self.ap.as_bytes()),
            hex_encode(self.client.as_bytes()),
            hex_encode(self.ssid.as_bytes()),
            hex_encode(&self.anonce),
            hex_encode(&self.eapol),
            pair
        ))
    }

    /// hashcat 22000 line for the PMKID alone.
    pub fn pmkid_hc22000(&self) -> Option<String> {
        let pmkid = self.pmkid?;
        if self.ssid.is_empty() {
            return None;
        }
        Some(alloc::format!(
            "WPA*01*{}*{}*{}*{}***",
            hex_encode(&pmkid),
            hex_encode(self.ap.as_bytes()),
            hex_encode(self.client.as_bytes()),
            hex_encode(self.ssid.as_bytes()),
        ))
    }
}

/// Bounded store of handshakes keyed by (AP, client).
#[derive(Debug)]
pub struct HandshakeStore<const N: usize> {
    entries: [Option<Handshake>; N],
    dropped: u32,
    eapol_frames: u32,
}

impl<const N: usize> Default for HandshakeStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HandshakeStore<N> {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; N],
            dropped: 0,
            eapol_frames: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn eapol_frames(&self) -> u32 {
        self.eapol_frames
    }

    pub fn iter(&self) -> impl Iterator<Item = &Handshake> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }

    pub fn get(&self, ap: MacAddr, client: MacAddr) -> Option<&Handshake> {
        self.iter().find(|h| h.ap == ap && h.client == client)
    }

    /// Number of captures with a usable MIC (crackable/verifiable).
    pub fn complete_count(&self) -> usize {
        self.iter()
            .filter(|h| h.quality() == HandshakeQuality::Complete)
            .count()
    }

    pub fn pmkid_count(&self) -> usize {
        self.iter().filter(|h| h.pmkid.is_some()).count()
    }

    /// Feed one EAPOL-Key frame.
    ///
    /// `ap`/`client` must already be resolved by the caller (from the data-frame
    /// addresses and the known BSSID). `ssid` may be unknown for the first frame.
    pub fn on_eapol(
        &mut self,
        eapol: &[u8],
        ap: MacAddr,
        client: MacAddr,
        ssid: Option<&[u8]>,
        channel: u8,
        now_ms: u64,
    ) -> Option<usize> {
        let key = EapolKey::parse(eapol)?;
        if key.message == HandshakeMessage::Unknown {
            return None;
        }
        self.eapol_frames = self.eapol_frames.saturating_add(1);

        let idx = match self.entries.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|h| h.ap == ap && h.client == client)
        }) {
            Some(idx) => idx,
            None => {
                let idx = match self.entries.iter().position(|slot| slot.is_none()) {
                    Some(idx) => idx,
                    None => {
                        // Replace the oldest capture: newest evidence wins.
                        let mut oldest: Option<(usize, u64)> = None;
                        for (i, slot) in self.entries.iter().enumerate() {
                            if let Some(h) = slot {
                                if oldest.map(|(_, t)| h.last_seen_ms < t).unwrap_or(true) {
                                    oldest = Some((i, h.last_seen_ms));
                                }
                            }
                        }
                        let (i, _) = oldest?;
                        self.dropped = self.dropped.saturating_add(1);
                        i
                    }
                };
                self.entries[idx] = Some(Handshake::empty(
                    ap,
                    client,
                    Ssid::new(ssid.unwrap_or(&[])),
                    channel,
                    now_ms,
                ));
                idx
            }
        };

        let record = self.entries[idx].as_mut()?;
        record.last_seen_ms = now_ms;
        if !record.ssid.is_hidden() {
            // keep
        } else if let Some(name) = ssid {
            if !name.is_empty() {
                record.ssid = Ssid::new(name);
            }
        }
        if channel != 0 {
            record.channel = channel;
        }
        record.messages |= key.message.bit();

        match key.message {
            HandshakeMessage::Message1 => {
                record.anonce = key.nonce;
                record.replay_counter = key.replay_counter;
                if let Some(pmkid) = key.pmkid() {
                    record.pmkid = Some(pmkid);
                }
            }
            HandshakeMessage::Message2 => {
                record.snonce = key.nonce;
                record.mic = key.mic;
                record.replay_counter = key.replay_counter;
                record.eapol.clear();
                record.eapol.extend_from_slice(eapol);
            }
            HandshakeMessage::Message3 => {
                record.anonce = key.nonce;
                record.replay_counter = key.replay_counter;
                if record.eapol.is_empty() {
                    // M3 alone still allows a hashcat line (M1+M3 is not crackable
                    // but preserves the ANonce/MIC pair for later correlation).
                    record.mic = key.mic;
                }
            }
            HandshakeMessage::Message4 => {
                record.mic = key.mic;
            }
            HandshakeMessage::Unknown => {}
        }
        Some(idx)
    }

    pub fn clear(&mut self) {
        self.entries = [const { None }; N];
        self.dropped = 0;
        self.eapol_frames = 0;
    }
}

/// Build a minimal EAPOL-Key frame. Exposed for parity tests and for the
/// deauth/EAPOL-logoff tools which need a well-formed frame skeleton.
pub fn build_eapol_key(
    descriptor: u8,
    key_info: u16,
    replay_counter: u64,
    nonce: &[u8; 32],
    key_data: &[u8],
) -> Vec<u8> {
    let total = MIN_EAPOL_KEY_LEN + key_data.len();
    let mut frame = alloc::vec![0u8; total];
    frame[0] = 2; // 802.1X-2004
    frame[1] = 3; // EAPOL-Key
    let body_len = (total - 4) as u16;
    frame[2..4].copy_from_slice(&body_len.to_be_bytes());
    frame[4] = descriptor;
    frame[5..7].copy_from_slice(&key_info.to_be_bytes());
    frame[7..9].copy_from_slice(&16u16.to_be_bytes()); // key length (CCMP)
    frame[9..17].copy_from_slice(&replay_counter.to_be_bytes());
    frame[17..49].copy_from_slice(nonce);
    frame[KEY_DATA_LEN_OFFSET..KEY_DATA_LEN_OFFSET + 2]
        .copy_from_slice(&(key_data.len() as u16).to_be_bytes());
    frame[MIN_EAPOL_KEY_LEN..].copy_from_slice(key_data);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_to_vec;

    const AP: MacAddr = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const CLIENT: MacAddr = MacAddr([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    const SSID: &[u8] = b"CyberLab";
    const PASS: &[u8] = b"correct horse battery staple";

    fn anonce() -> [u8; 32] {
        [0x11; 32]
    }

    fn snonce() -> [u8; 32] {
        [0x22; 32]
    }

    /// Build a properly signed message 2 for the known passphrase.
    fn signed_message2() -> Vec<u8> {
        let mut frame = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_MIC | 0x0002, 1, &snonce(), &[]);
        let pmk = derive_pmk(PASS, SSID);
        let keys = derive_ptk(&pmk, &AP.0, &CLIENT.0, &anonce(), &snonce());
        let mic = compute_mic(&keys.kck, &frame);
        frame[MIC_OFFSET..MIC_OFFSET + 16].copy_from_slice(&mic);
        frame
    }

    #[test]
    fn classifies_all_four_messages() {
        let m1 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &[]);
        assert_eq!(
            EapolKey::parse(&m1).unwrap().message,
            HandshakeMessage::Message1
        );

        let m2 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_MIC, 1, &snonce(), &[]);
        assert_eq!(
            EapolKey::parse(&m2).unwrap().message,
            HandshakeMessage::Message2
        );

        let m3 = build_eapol_key(
            DESCRIPTOR_RSN,
            KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL | KEY_INFO_SECURE,
            2,
            &anonce(),
            &[0u8; 16],
        );
        assert_eq!(
            EapolKey::parse(&m3).unwrap().message,
            HandshakeMessage::Message3
        );

        let m4 = build_eapol_key(
            DESCRIPTOR_RSN,
            KEY_INFO_MIC | KEY_INFO_SECURE,
            2,
            &[0u8; 32],
            &[],
        );
        assert_eq!(
            EapolKey::parse(&m4).unwrap().message,
            HandshakeMessage::Message4
        );
    }

    #[test]
    fn parses_wire_format_fields() {
        // Realistic message-2 header, captured-style bytes.
        let raw = hex_to_vec(
            "0203007502010a0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016dd14000fac04",
        )
        .unwrap();
        // Pad to the minimum EAPOL-Key length with zeroed MIC area.
        let mut frame = raw.clone();
        frame.resize(MIN_EAPOL_KEY_LEN, 0);
        // Replay counter sits right after key length and is big-endian.
        frame[9..17].copy_from_slice(&0x10u64.to_be_bytes());
        // A message 2 always carries the supplicant nonce (M4 is recognised by a
        // zero nonce, so the fixture must be a real M2).
        for (i, byte) in frame[17..49].iter_mut().enumerate() {
            *byte = 0xA0 + i as u8;
        }
        frame[KEY_DATA_LEN_OFFSET..KEY_DATA_LEN_OFFSET + 2].copy_from_slice(&20u16.to_be_bytes());
        frame.resize(MIN_EAPOL_KEY_LEN + 20, 0);
        frame[MIN_EAPOL_KEY_LEN..MIN_EAPOL_KEY_LEN + 6].copy_from_slice(&PMKID_KDE_PREFIX);
        // Keep the EAPOL length field consistent with the padded frame.
        let eapol_len = (frame.len() - 4) as u16;
        frame[2..4].copy_from_slice(&eapol_len.to_be_bytes());
        let parsed = EapolKey::parse(&frame).expect("parses");
        assert_eq!(parsed.descriptor, DESCRIPTOR_RSN);
        assert!(parsed.key_info & KEY_INFO_MIC != 0);
        assert_eq!(parsed.replay_counter, 0x10);
        assert_eq!(parsed.message, HandshakeMessage::Message2);
    }

    #[test]
    fn rejects_truncated_and_non_eapol_frames() {
        assert!(EapolKey::parse(&[]).is_none());
        assert!(EapolKey::parse(&[0u8; 40]).is_none());
        let mut wrong_type = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_MIC, 1, &snonce(), &[]);
        wrong_type[1] = 0; // EAP-Packet, not EAPOL-Key
        assert!(EapolKey::parse(&wrong_type).is_none());
        // Length field larger than the buffer.
        let mut bad_len = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_MIC, 1, &snonce(), &[]);
        bad_len[2..4].copy_from_slice(&4096u16.to_be_bytes());
        assert!(EapolKey::parse(&bad_len).is_none());
    }

    #[test]
    fn extracts_pmkid_from_message1_kde() {
        let mut kde = alloc::vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&[0xAA; 16]);
        let m1 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &kde);
        let parsed = EapolKey::parse(&m1).unwrap();
        assert_eq!(parsed.pmkid(), Some([0xAA; 16]));
        // Garbage key data must not panic or produce a PMKID.
        let garbage = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &[0x00; 32]);
        assert_eq!(EapolKey::parse(&garbage).unwrap().pmkid(), None);
    }

    #[test]
    fn store_assembles_and_verifies_a_handshake() {
        let mut store: HandshakeStore<8> = HandshakeStore::new();
        let m1 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &[]);
        let m2 = signed_message2();
        store.on_eapol(&m1, AP, CLIENT, Some(SSID), 6, 100);
        store.on_eapol(&m2, AP, CLIENT, Some(SSID), 6, 110);

        let handshake = store.get(AP, CLIENT).expect("handshake stored");
        assert_eq!(handshake.message_list(), "M1 M2");
        assert_eq!(handshake.quality(), HandshakeQuality::Complete);
        assert_eq!(store.complete_count(), 1);
        assert_eq!(handshake.verify_passphrase(PASS), Verification::MicValid);
        assert_eq!(
            handshake.verify_passphrase(b"wrong passphrase"),
            Verification::MicInvalid
        );
        // PMKID derived on device matches a PMKID computed independently.
        let expected = derive_pmkid(&derive_pmk(PASS, SSID), AP.as_bytes(), CLIENT.as_bytes());
        assert_eq!(handshake.pmkid_for_passphrase(PASS), expected);
    }

    #[test]
    fn incomplete_capture_cannot_be_verified() {
        let mut store: HandshakeStore<4> = HandshakeStore::new();
        let m2 = signed_message2();
        store.on_eapol(&m2, AP, CLIENT, Some(SSID), 6, 1);
        let handshake = store.get(AP, CLIENT).unwrap();
        assert_eq!(handshake.quality(), HandshakeQuality::PartialClient);
        assert_eq!(
            handshake.verify_passphrase(PASS),
            Verification::NeedMoreData
        );
        assert!(handshake.hc22000().is_none());
    }

    #[test]
    fn exports_hc22000_lines_with_expected_shape() {
        let mut store: HandshakeStore<4> = HandshakeStore::new();
        let mut kde = alloc::vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&[0x5A; 16]);
        let m1 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &kde);
        let m2 = signed_message2();
        store.on_eapol(&m1, AP, CLIENT, Some(SSID), 6, 1);
        store.on_eapol(&m2, AP, CLIENT, Some(SSID), 6, 2);
        let handshake = store.get(AP, CLIENT).unwrap();

        let line = handshake.hc22000().expect("eapol line");
        let fields: Vec<&str> = line.split('*').collect();
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[0], "WPA");
        assert_eq!(fields[1], "02");
        assert_eq!(fields[2].len(), 32, "MIC hex");
        assert_eq!(fields[3], "001122334455");
        assert_eq!(fields[4], "66778899AABB");
        assert_eq!(fields[5], "43796265724C6162"); // "CyberLab"
        assert_eq!(fields[6].len(), 64, "ANonce hex");
        assert!(fields[7].starts_with("0203"));
        assert_eq!(fields[8], "00");

        let pmkid_line = handshake.pmkid_hc22000().expect("pmkid line");
        let pmkid_fields: Vec<&str> = pmkid_line.split('*').collect();
        assert_eq!(pmkid_fields.len(), 9);
        assert_eq!(pmkid_fields[1], "01");
        assert_eq!(pmkid_fields[2], "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A");
        assert_eq!(pmkid_fields[5], "43796265724C6162");
    }

    #[test]
    fn store_replaces_oldest_when_full_and_counts_drops() {
        let mut store: HandshakeStore<1> = HandshakeStore::new();
        let m1 = build_eapol_key(DESCRIPTOR_RSN, KEY_INFO_ACK, 1, &anonce(), &[]);
        store.on_eapol(&m1, AP, CLIENT, Some(SSID), 6, 1_000);
        store.on_eapol(&m1, AP, MacAddr([1; 6]), Some(SSID), 6, 2_000);
        assert_eq!(store.len(), 1);
        assert_eq!(store.dropped(), 1);
        assert!(store.get(AP, MacAddr([1; 6])).is_some());
    }

    #[test]
    fn unknown_messages_are_ignored() {
        let mut store: HandshakeStore<2> = HandshakeStore::new();
        // Neither ACK nor MIC: not part of a 4-way handshake.
        let odd = build_eapol_key(DESCRIPTOR_RSN, 0, 1, &snonce(), &[]);
        assert!(store.on_eapol(&odd, AP, CLIENT, Some(SSID), 6, 0).is_none());
        assert!(store.is_empty());
    }
}

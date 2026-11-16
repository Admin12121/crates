//! IEEE 802.11 management/data frame parsing and generation.
//!
//! Ported from the frame layouts used by ESP32 Marauder (`WiFiScan.cpp`,
//! `BeaconFrame.cpp`) and GhostESP (`main/attacks/wifi/*`): same fixed-field
//! offsets, same information-element walk, same management subtype constants.
//! The Rust version is bounded and fallible instead of pointer arithmetic, and it
//! is exercised by the host test suite.

use crate::net::MacAddr;
use crate::util::{read_u16_le, write_u16_le};

/// Management frame type value in the frame-control field.
pub const FRAME_TYPE_MGMT: u8 = 0;
/// Control frame type value.
pub const FRAME_TYPE_CTRL: u8 = 1;
/// Data frame type value.
pub const FRAME_TYPE_DATA: u8 = 2;
/// Extension frame type value.
pub const FRAME_TYPE_EXT: u8 = 3;

/// Management subtypes used by the tools.
pub mod subtype {
    pub const ASSOC_REQ: u8 = 0;
    pub const ASSOC_RESP: u8 = 1;
    pub const REASSOC_REQ: u8 = 2;
    pub const REASSOC_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOC: u8 = 10;
    pub const AUTH: u8 = 11;
    pub const DEAUTH: u8 = 12;
    pub const ACTION: u8 = 13;
    pub const ACTION_NO_ACK: u8 = 14;
}

/// Information element IDs referenced by the scanners/analysers.
pub mod ie {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const DS_PARAM: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY: u8 = 7;
    pub const ERP: u8 = 42;
    pub const HT_CAPABILITIES: u8 = 45;
    pub const RSN: u8 = 48;
    pub const EXT_SUPPORTED_RATES: u8 = 50;
    pub const EXTENDED_CAPABILITIES: u8 = 127;
    pub const VENDOR: u8 = 221;
}

/// WPS vendor IE: `00:50:F2` type 4.
pub const WPS_OUI: [u8; 3] = [0x00, 0x50, 0xF2];
/// Microsoft/WPA vendor IE type 1.
pub const WPA_OUI: [u8; 3] = [0x00, 0x50, 0xF2];

/// Parsed frame-control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: u8,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_management: bool,
    pub more_data: bool,
    pub protected: bool,
    pub order: bool,
}

impl FrameControl {
    pub fn parse(raw: u16) -> Self {
        Self {
            protocol_version: (raw & 0x0003) as u8,
            frame_type: ((raw >> 2) & 0x0003) as u8,
            subtype: ((raw >> 4) & 0x000F) as u8,
            to_ds: raw & 0x0100 != 0,
            from_ds: raw & 0x0200 != 0,
            more_fragments: raw & 0x0400 != 0,
            retry: raw & 0x0800 != 0,
            power_management: raw & 0x1000 != 0,
            more_data: raw & 0x2000 != 0,
            protected: raw & 0x4000 != 0,
            order: raw & 0x8000 != 0,
        }
    }

    pub fn encode(&self) -> u16 {
        let mut raw = (self.protocol_version & 0x03) as u16;
        raw |= (self.frame_type as u16 & 0x03) << 2;
        raw |= (self.subtype as u16 & 0x0F) << 4;
        raw |= (self.to_ds as u16) << 8;
        raw |= (self.from_ds as u16) << 9;
        raw |= (self.more_fragments as u16) << 10;
        raw |= (self.retry as u16) << 11;
        raw |= (self.power_management as u16) << 12;
        raw |= (self.more_data as u16) << 13;
        raw |= (self.protected as u16) << 14;
        raw |= (self.order as u16) << 15;
        raw
    }

    pub const fn is_management(&self) -> bool {
        self.frame_type == FRAME_TYPE_MGMT
    }

    pub const fn is_data(&self) -> bool {
        self.frame_type == FRAME_TYPE_DATA
    }

    pub fn is_subtype(&self, subtype: u8) -> bool {
        self.is_management() && self.subtype == subtype
    }

    pub fn name(&self) -> &'static str {
        match (self.frame_type, self.subtype) {
            (FRAME_TYPE_MGMT, subtype::BEACON) => "Beacon",
            (FRAME_TYPE_MGMT, subtype::PROBE_REQ) => "Probe Request",
            (FRAME_TYPE_MGMT, subtype::PROBE_RESP) => "Probe Response",
            (FRAME_TYPE_MGMT, subtype::AUTH) => "Authentication",
            (FRAME_TYPE_MGMT, subtype::ASSOC_REQ) => "Association Request",
            (FRAME_TYPE_MGMT, subtype::ASSOC_RESP) => "Association Response",
            (FRAME_TYPE_MGMT, subtype::REASSOC_REQ) => "Reassociation Request",
            (FRAME_TYPE_MGMT, subtype::REASSOC_RESP) => "Reassociation Response",
            (FRAME_TYPE_MGMT, subtype::DEAUTH) => "Deauthentication",
            (FRAME_TYPE_MGMT, subtype::DISASSOC) => "Disassociation",
            (FRAME_TYPE_MGMT, subtype::ACTION) => "Action",
            (FRAME_TYPE_CTRL, _) => "Control",
            (FRAME_TYPE_DATA, _) => "Data",
            (FRAME_TYPE_EXT, _) => "Extension",
            _ => "Management",
        }
    }
}

/// A parsed management/data frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader<'a> {
    pub fc: FrameControl,
    pub duration: u16,
    pub addr1: MacAddr,
    pub addr2: MacAddr,
    pub addr3: MacAddr,
    pub sequence: u16,
    /// Body after the (QoS-aware) header.
    pub body: &'a [u8],
}

impl<'a> FrameHeader<'a> {
    /// Parse a management or data frame. Control frames and runt frames return
    /// `None`; malformed input can never panic.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let fc = FrameControl::parse(read_u16_le(data, 0)?);
        if fc.frame_type == FRAME_TYPE_CTRL {
            return None;
        }
        let mut offset = 24;
        // QoS data frames carry an extra 2-byte QoS control field.
        if fc.is_data() && (fc.subtype & 0x08) != 0 {
            offset += 2;
        }
        // +HTC (order bit) adds 4 bytes for QoS data frames.
        if fc.is_data() && fc.order && (fc.subtype & 0x08) != 0 {
            offset += 4;
        }
        if data.len() < offset {
            return None;
        }
        Some(Self {
            fc,
            duration: read_u16_le(data, 2)?,
            addr1: MacAddr::new(data[4..10].try_into().ok()?),
            addr2: MacAddr::new(data[10..16].try_into().ok()?),
            addr3: MacAddr::new(data[16..22].try_into().ok()?),
            sequence: read_u16_le(data, 22)?,
            body: &data[offset..],
        })
    }

    /// Length of the subtype-specific fixed fields that precede the information
    /// elements in [`Self::body`].
    pub const fn ie_offset(&self) -> usize {
        if !self.fc.is_management() {
            return 0;
        }
        match self.fc.subtype {
            subtype::BEACON | subtype::PROBE_RESP => 12,
            subtype::ASSOC_REQ => 4,
            subtype::ASSOC_RESP | subtype::REASSOC_RESP | subtype::AUTH => 6,
            subtype::REASSOC_REQ => 10,
            _ => 0,
        }
    }

    /// Information-element area of a management frame.
    ///
    /// [`Self::body`] keeps the fixed fields (timestamp/capabilities) because the
    /// auth path needs them; every IE helper takes this slice instead.
    pub fn ies(&self) -> &'a [u8] {
        self.body.get(self.ie_offset()..).unwrap_or(&[])
    }

    /// Transmitter address for a captured frame (BSSID for beacons/probe responses).
    pub fn transmitter(&self) -> MacAddr {
        self.addr2
    }

    /// True when the frame is addressed to the broadcast/multicast group.
    pub fn is_broadcast(&self) -> bool {
        self.addr1.is_broadcast() || self.addr1.is_multicast()
    }
}

/// One information element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InformationElement<'a> {
    pub id: u8,
    pub body: &'a [u8],
}

impl<'a> InformationElement<'a> {
    /// Vendor OUI for vendor-specific elements.
    pub fn oui(&self) -> Option<[u8; 3]> {
        if self.id == ie::VENDOR && self.body.len() >= 3 {
            Some([self.body[0], self.body[1], self.body[2]])
        } else {
            None
        }
    }

    /// Vendor-specific data type (byte 3) for `00:50:F2` IEs.
    pub fn vendor_type(&self) -> Option<u8> {
        if self.id == ie::VENDOR && self.body.len() >= 4 && self.body[..3] == WPS_OUI {
            Some(self.body[3])
        } else {
            None
        }
    }
}

/// Bounded information-element walk; stops cleanly on a truncated tail.
#[derive(Debug, Clone, Copy)]
pub struct IeIter<'a> {
    rest: &'a [u8],
}

impl<'a> IeIter<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }
}

impl<'a> Iterator for IeIter<'a> {
    type Item = InformationElement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < 2 {
            return None;
        }
        let id = self.rest[0];
        let len = self.rest[1] as usize;
        if self.rest.len() < 2 + len {
            // Truncated element: stop instead of reading past the buffer.
            self.rest = &[];
            return None;
        }
        let body = &self.rest[2..2 + len];
        self.rest = &self.rest[2 + len..];
        Some(InformationElement { id, body })
    }
}

/// Walk the IEs of a management body.
pub fn elements(body: &[u8]) -> IeIter<'_> {
    IeIter::new(body)
}

/// SSID of a beacon/probe response/association body.
pub fn find_ssid(body: &[u8]) -> Option<&[u8]> {
    elements(body).find(|e| e.id == ie::SSID).map(|e| e.body)
}

/// Primary channel from the DS parameter set (beacons/probe responses).
pub fn find_channel(body: &[u8]) -> Option<u8> {
    elements(body)
        .find(|e| e.id == ie::DS_PARAM && !e.body.is_empty())
        .map(|e| e.body[0])
}

/// RSN information element body.
pub fn find_rsn(body: &[u8]) -> Option<&[u8]> {
    IeIter::new(body).find(|e| e.id == ie::RSN).map(|e| e.body)
}

/// WPA1 vendor element (Microsoft OUI, type 1).
pub fn find_wpa(body: &[u8]) -> Option<&[u8]> {
    IeIter::new(body)
        .find(|e| e.id == ie::VENDOR && e.vendor_type() == Some(1))
        .map(|e| &e.body[4..])
}

/// True when a WPS element is present.
pub fn has_wps(body: &[u8]) -> bool {
    IeIter::new(body).any(|e| e.id == ie::VENDOR && e.vendor_type() == Some(4))
}

/// WPS version/state summary from the WPS vendor IE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WpsInfo {
    pub version: u8,
    pub configured: bool,
    pub selected_registrar: bool,
    pub response_type: u8,
}

/// Parse the attributes of a WPS IE body (after the 4-byte OUI/type prefix).
pub fn parse_wps(body: &[u8]) -> Option<WpsInfo> {
    let ie = IeIter::new(body).find(|e| e.id == ie::VENDOR && e.vendor_type() == Some(4))?;
    let attrs = ie.body.get(4..)?;
    let mut info = WpsInfo {
        version: 0,
        configured: false,
        selected_registrar: false,
        response_type: 0,
    };
    let mut rest = attrs;
    while rest.len() >= 4 {
        let attr_type = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + len {
            break;
        }
        let value = &rest[4..4 + len];
        match attr_type {
            0x104A if !value.is_empty() => info.version = value[0],
            0x1044 if !value.is_empty() => info.configured = value[0] & 0x01 != 0,
            0x1041 if !value.is_empty() => info.selected_registrar = value[0] & 0x01 != 0,
            0x103B if !value.is_empty() => info.response_type = value[0],
            _ => {}
        }
        rest = &rest[4 + len..];
    }
    Some(info)
}

/// Security classification inferred from the beacon/probe-response IEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Open,
    Wep,
    Wpa,
    Wpa2Psk,
    Wpa2Enterprise,
    Wpa3Sae,
    Wpa2Wpa3Mixed,
    Owe,
    Unknown,
}

impl Security {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Wep => "WEP",
            Self::Wpa => "WPA",
            Self::Wpa2Psk => "WPA2-PSK",
            Self::Wpa2Enterprise => "WPA2-ENT",
            Self::Wpa3Sae => "WPA3-SAE",
            Self::Wpa2Wpa3Mixed => "WPA2/WPA3",
            Self::Owe => "OWE",
            Self::Unknown => "?",
        }
    }
}

/// Full security description for the AP table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityInfo {
    pub security: Security,
    pub privacy: bool,
    pub wps: bool,
    pub pmf_required: bool,
}

/// Classify the security of a beacon/probe response from its capabilities and IEs.
pub fn classify_security(body: &[u8], capability_privacy: bool) -> SecurityInfo {
    let rsn = find_rsn(body);
    let wpa = find_wpa(body);
    let mut security = if rsn.is_some() {
        Security::Wpa2Psk
    } else if wpa.is_some() {
        Security::Wpa
    } else if capability_privacy {
        Security::Wep
    } else {
        Security::Open
    };

    let mut pmf_required = false;
    if let Some(rsn) = rsn {
        let (has_psk, has_sae, has_8021x) = parse_akm_suites(rsn);
        let caps = rsn.get(rsn.len().saturating_sub(2)..).and_then(|tail| {
            if rsn.len() >= 2 {
                Some(u16::from_le_bytes([tail[0], tail[1]]))
            } else {
                None
            }
        });
        pmf_required = caps.map(|c| c & 0x0040 != 0).unwrap_or(false);
        security = match (has_sae, has_psk, has_8021x) {
            (true, true, _) => Security::Wpa2Wpa3Mixed,
            (true, false, _) => Security::Wpa3Sae,
            (false, true, false) => Security::Wpa2Psk,
            (false, false, true) => Security::Wpa2Enterprise,
            _ => Security::Wpa2Psk,
        };
        if !has_psk && !has_sae && !has_8021x {
            // OWE-only networks advertise AKM 18.
            security = Security::Owe;
        }
    }

    SecurityInfo {
        security,
        privacy: capability_privacy,
        wps: has_wps(body),
        pmf_required,
    }
}

/// Return `(psk, sae, 8021x)` from the AKM suite list of an RSN element.
fn parse_akm_suites(rsn: &[u8]) -> (bool, bool, bool) {
    // version(2) | group cipher(4) | pairwise count(2) | pairwise(n*4) |
    // akm count(2) | akm(n*4) | capabilities(2)
    if rsn.len() < 8 {
        return (false, false, false);
    }
    let pairwise_count = u16::from_le_bytes([rsn[6], rsn[7]]) as usize;
    let mut offset = 8 + pairwise_count * 4;
    if rsn.len() < offset + 2 {
        return (false, false, false);
    }
    let akm_count = u16::from_le_bytes([rsn[offset], rsn[offset + 1]]) as usize;
    offset += 2;
    let mut psk = false;
    let mut sae = false;
    let mut eap = false;
    for _ in 0..akm_count {
        if rsn.len() < offset + 4 {
            break;
        }
        let suite = &rsn[offset..offset + 4];
        let akm_type = suite[3];
        match akm_type {
            1 => eap = true,
            2 => psk = true,
            8 => sae = true,
            18 => {}
            _ => {}
        }
        offset += 4;
    }
    (psk, sae, eap)
}

/// Capability information field of a beacon/probe-response body.
pub fn capabilities(body: &[u8]) -> Option<u16> {
    if body.len() < 12 {
        return None;
    }
    Some(u16::from_le_bytes([body[10], body[11]]))
}

/// Timestamp field of a beacon.
pub fn beacon_timestamp(body: &[u8]) -> Option<u64> {
    if body.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(body[..8].try_into().ok()?))
}

/// Maximum size of a generated frame (covers a 32-byte SSID beacon with RSN/WPS).
pub const MAX_FRAME_LEN: usize = 320;

/// Fixed-capacity frame buffer used by every generator (no heap on TX paths).
#[derive(Debug, Clone)]
pub struct FrameBuffer {
    data: [u8; MAX_FRAME_LEN],
    len: usize,
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBuffer {
    pub const fn new() -> Self {
        Self {
            data: [0; MAX_FRAME_LEN],
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, bytes: &[u8]) {
        let end = (self.len + bytes.len()).min(MAX_FRAME_LEN);
        self.data[self.len..end].copy_from_slice(&bytes[..end - self.len]);
        self.len = end;
    }

    fn push_u16_le(&mut self, value: u16) {
        self.push(&value.to_le_bytes());
    }

    fn push_element(&mut self, id: u8, body: &[u8]) {
        let len = body.len().min(255);
        self.push(&[id, len as u8]);
        self.push(&body[..len]);
    }

    /// Rewrite the frame-control field (used after construction).
    fn set_fcf(&mut self, fc: FrameControl) {
        let raw = fc.encode();
        write_u16_le(&mut self.data, 0, raw);
    }

    fn set_sequence(&mut self, sequence: u16) {
        write_u16_le(&mut self.data, 22, sequence << 4);
    }

    fn begin_mgmt(&mut self, subtype: u8, addr1: MacAddr, addr2: MacAddr, addr3: MacAddr) {
        self.len = 0;
        self.push(&[0, 0]); // frame control, patched below
        self.push_u16_le(0); // duration
        self.push(addr1.as_bytes());
        self.push(addr2.as_bytes());
        self.push(addr3.as_bytes());
        self.push_u16_le(0); // sequence control
        let mut fc = FrameControl {
            protocol_version: 0,
            frame_type: FRAME_TYPE_MGMT,
            subtype,
            ..Default::default()
        };
        fc.retry = false;
        self.set_fcf(fc);
    }
}

/// Supported rates used by generated beacons (1,2,5.5,11,6,9,12,18 Mbps).
pub const DEFAULT_RATES: [u8; 8] = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];

/// Deauthentication reason codes (IEEE 802.11 Table 8-36 subset).
pub mod reason {
    pub const UNSPECIFIED: u16 = 1;
    pub const PREV_AUTH_NOT_VALID: u16 = 2;
    pub const STA_LEAVING: u16 = 3;
    pub const CLASS2_FROM_UNAUTH: u16 = 6;
    pub const CLASS3_FROM_UNASSOC: u16 = 7;
    pub const FOURWAY_TIMEOUT: u16 = 15;
}

/// Build a deauthentication frame (26 bytes).
pub fn deauth_frame(destination: MacAddr, bssid: MacAddr, reason_code: u16) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::DEAUTH, destination, bssid, bssid);
    frame.push_u16_le(reason_code);
    frame
}

/// Build a disassociation frame (26 bytes).
pub fn disassoc_frame(destination: MacAddr, bssid: MacAddr, reason_code: u16) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::DISASSOC, destination, bssid, bssid);
    frame.push_u16_le(reason_code);
    frame
}

/// Build a broadcast deauthentication frame (the classic `ff:ff:ff:ff:ff:ff` form).
pub fn broadcast_deauth(bssid: MacAddr, reason_code: u16) -> FrameBuffer {
    deauth_frame(MacAddr::BROADCAST, bssid, reason_code)
}

/// Build a probe request, optionally directed at one SSID.
pub fn probe_request(source: MacAddr, ssid: Option<&[u8]>) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(
        subtype::PROBE_REQ,
        MacAddr::BROADCAST,
        source,
        MacAddr::BROADCAST,
    );
    frame.push_element(ie::SSID, ssid.unwrap_or(&[]));
    frame.push_element(ie::SUPPORTED_RATES, &DEFAULT_RATES[..4]);
    frame
}

/// Build an authentication frame. `algorithm` 0 = open, 1 = shared key.
pub fn auth_frame(
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    algorithm: u16,
    sequence: u16,
    status: u16,
) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::AUTH, destination, source, bssid);
    frame.push_u16_le(algorithm);
    frame.push_u16_le(sequence);
    frame.push_u16_le(status);
    frame
}

/// Build an association request for the given SSID (used by client-side tests and
/// by the Evil Twin on-boarding path).
pub fn assoc_request(
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    ssid: &[u8],
) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::ASSOC_REQ, destination, source, bssid);
    // Capabilities: ESS + short slot + privacy off (open network).
    frame.push_u16_le(0x0401);
    frame.push_u16_le(10); // listen interval
    frame.push_element(ie::SSID, ssid);
    frame.push_element(ie::SUPPORTED_RATES, &DEFAULT_RATES);
    frame
}

/// Options for a generated beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconOptions {
    pub channel: u8,
    pub privacy: bool,
    /// Advertise an RSN element with PSK AKM (WPA2) to look like a real AP.
    pub wpa2: bool,
    pub hidden: bool,
    /// Beacon interval in TUs.
    pub interval: u16,
    /// Sequence-control value written into the frame.
    pub sequence: u16,
}

impl Default for BeaconOptions {
    fn default() -> Self {
        Self {
            channel: 1,
            privacy: false,
            wpa2: false,
            hidden: false,
            interval: 100,
            sequence: 0,
        }
    }
}

/// Standard RSN element body for WPA2-PSK/CCMP (as emitted by reference beacons).
pub const RSN_PSK_CCMP: [u8; 20] = [
    0x01, 0x00, // version
    0x00, 0x0F, 0xAC, 0x04, // group cipher CCMP
    0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // pairwise count 1, CCMP
    0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // AKM count 1, PSK
    0x00, 0x00, // capabilities
];

/// Build a beacon frame for `ssid`/`bssid`.
pub fn beacon_frame(ssid: &[u8], bssid: MacAddr, options: &BeaconOptions) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::BEACON, MacAddr::BROADCAST, bssid, bssid);
    frame.push(&[0u8; 8]); // timestamp (AP updates this in hardware; 0 is legal)
    frame.push_u16_le(options.interval);
    let mut caps: u16 = 0x0001; // ESS
    caps |= 0x0400; // short slot time
    if options.privacy {
        caps |= 0x0010;
    }
    frame.push_u16_le(caps);
    let ssid_body = if options.hidden { &[][..] } else { ssid };
    frame.push_element(ie::SSID, ssid_body);
    frame.push_element(ie::SUPPORTED_RATES, &DEFAULT_RATES);
    frame.push_element(ie::DS_PARAM, &[options.channel]);
    // TIM element with no buffered traffic.
    frame.push_element(ie::TIM, &[0x00, 0x01, 0x00, 0x00]);
    if options.wpa2 || options.privacy {
        frame.push_element(ie::RSN, &RSN_PSK_CCMP);
    }
    frame.set_sequence(options.sequence);
    frame
}

/// Build a probe response matching a probe request SSID.
pub fn probe_response(
    destination: MacAddr,
    bssid: MacAddr,
    ssid: &[u8],
    channel: u8,
    privacy: bool,
) -> FrameBuffer {
    let mut frame = FrameBuffer::new();
    frame.begin_mgmt(subtype::PROBE_RESP, destination, bssid, bssid);
    frame.push(&[0u8; 8]);
    frame.push_u16_le(100);
    let mut caps: u16 = 0x0001 | 0x0400;
    if privacy {
        caps |= 0x0010;
    }
    frame.push_u16_le(caps);
    frame.push_element(ie::SSID, ssid);
    frame.push_element(ie::SUPPORTED_RATES, &DEFAULT_RATES);
    frame.push_element(ie::DS_PARAM, &[channel]);
    if privacy {
        frame.push_element(ie::RSN, &RSN_PSK_CCMP);
    }
    frame
}

/// Fixtures shared with the other Wi-Fi module tests.
#[cfg(test)]
pub mod tests_support {
    use alloc::vec::Vec;

    /// Real-world shaped WPA2 beacon: channel 6, SSID `CyberLab`, CCMP/PSK RSN,
    /// short-slot capability, TIM with no buffered traffic.
    pub fn beacon_frame_bytes() -> Vec<u8> {
        let mut frame = Vec::with_capacity(87);
        frame.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // beacon, duration 0
        frame.extend_from_slice(&[0xFF; 6]); // broadcast destination
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // BSSID
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // source
        frame.extend_from_slice(&[0x10, 0x00]); // sequence control
        frame.extend_from_slice(&[0u8; 8]); // timestamp
        frame.extend_from_slice(&[0x64, 0x00]); // beacon interval 100 TU
        frame.extend_from_slice(&[0x11, 0x04]); // ESS | Privacy | ShortSlot
        frame.extend_from_slice(&[0x00, 0x08]);
        frame.extend_from_slice(b"CyberLab");
        frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
        frame.extend_from_slice(&[0x03, 0x01, 0x06]); // DS parameter: channel 6
        frame.extend_from_slice(&[0x05, 0x04, 0x00, 0x01, 0x00, 0x00]); // TIM
        frame.extend_from_slice(&[0x30, 0x14]); // RSN
        frame.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00,
        ]);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::beacon_frame_bytes;
    use super::*;

    #[test]
    fn parses_captured_wpa2_beacon() {
        let bytes = beacon_frame_bytes();
        let header = FrameHeader::parse(&bytes).expect("beacon parses");
        assert!(header.fc.is_management());
        assert_eq!(header.fc.subtype, subtype::BEACON);
        assert_eq!(header.fc.name(), "Beacon");
        assert_eq!(header.addr1, MacAddr::BROADCAST);
        let bssid = MacAddr::parse("00:11:22:33:44:55").unwrap();
        assert_eq!(header.addr2, bssid);
        assert_eq!(header.addr3, bssid);
        assert_eq!(find_ssid(header.ies()), Some(&b"CyberLab"[..]));
        assert_eq!(find_channel(header.ies()), Some(6));
        assert_eq!(beacon_timestamp(header.body), Some(0));

        let caps = capabilities(header.body).unwrap();
        assert_eq!(caps & 0x0001, 0x0001, "ESS bit");
        assert_eq!(caps & 0x0010, 0x0010, "privacy bit");
        let info = classify_security(header.ies(), caps & 0x0010 != 0);
        assert_eq!(info.security, Security::Wpa2Psk);
        assert!(!info.wps);
        assert!(!info.pmf_required);
    }

    #[test]
    fn element_walk_is_bounded_on_truncated_input() {
        let bytes = beacon_frame_bytes();
        let header = FrameHeader::parse(&bytes).unwrap();
        // Cut the body mid-element and ensure the walker stops instead of panicking.
        for cut in 0..header.body.len() {
            let body = &header.body[..cut];
            let count = elements(body).count();
            assert!(count <= 8, "unexpected element count {count} at cut {cut}");
        }
    }

    #[test]
    fn rejects_runt_and_control_frames() {
        assert!(FrameHeader::parse(&[0u8; 10]).is_none());
        // Control frame (type 1, subtype 13 = ACK) has no 24-byte header.
        let ack = [0xD4, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(FrameHeader::parse(&ack).is_none());
    }

    #[test]
    fn deauth_frame_matches_reference_layout() {
        let bssid = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let client = MacAddr::parse("11:22:33:44:55:66").unwrap();
        let frame = deauth_frame(client, bssid, reason::CLASS3_FROM_UNASSOC);
        let bytes = frame.as_slice();
        assert_eq!(bytes.len(), 26);
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x00C0);
        assert_eq!(&bytes[4..10], client.as_bytes());
        assert_eq!(&bytes[10..16], bssid.as_bytes());
        assert_eq!(&bytes[16..22], bssid.as_bytes());
        assert_eq!(&bytes[24..26], &7u16.to_le_bytes());

        let header = FrameHeader::parse(bytes).unwrap();
        assert_eq!(header.fc.subtype, subtype::DEAUTH);
        assert_eq!(header.body.len(), 2);
    }

    #[test]
    fn broadcast_deauth_targets_every_client() {
        let frame = broadcast_deauth(MacAddr::BROADCAST, reason::UNSPECIFIED);
        let header = FrameHeader::parse(frame.as_slice()).unwrap();
        assert!(header.is_broadcast());
    }

    #[test]
    fn generated_beacon_round_trips_through_the_parser() {
        let bssid = MacAddr::parse("02:00:00:00:00:01").unwrap();
        let options = BeaconOptions {
            channel: 11,
            privacy: true,
            wpa2: true,
            hidden: false,
            interval: 100,
            sequence: 7,
        };
        let frame = beacon_frame(b"FreeWiFi", bssid, &options);
        let header = FrameHeader::parse(frame.as_slice()).unwrap();
        assert_eq!(find_ssid(header.ies()), Some(&b"FreeWiFi"[..]));
        assert_eq!(find_channel(header.ies()), Some(11));
        assert_eq!(header.sequence >> 4, 7);
        let caps = capabilities(header.body).unwrap();
        let info = classify_security(header.ies(), caps & 0x0010 != 0);
        assert_eq!(info.security, Security::Wpa2Psk);
        assert_eq!(info.security.label(), "WPA2-PSK");
    }

    #[test]
    fn hidden_beacon_has_empty_ssid() {
        let bssid = MacAddr::parse("02:00:00:00:00:02").unwrap();
        let options = BeaconOptions {
            hidden: true,
            channel: 1,
            ..Default::default()
        };
        let frame = beacon_frame(b"Secret", bssid, &options);
        let header = FrameHeader::parse(frame.as_slice()).unwrap();
        assert_eq!(find_ssid(header.ies()), Some(&[][..]));
    }

    #[test]
    fn probe_request_and_response_shapes() {
        let src = MacAddr::parse("02:00:00:00:00:03").unwrap();
        let req = probe_request(src, None);
        let header = FrameHeader::parse(req.as_slice()).unwrap();
        assert_eq!(header.fc.subtype, subtype::PROBE_REQ);
        assert_eq!(header.addr1, MacAddr::BROADCAST);
        assert_eq!(find_ssid(header.ies()), Some(&[][..]));

        let resp = probe_response(MacAddr::BROADCAST, src, b"Lab", 3, false);
        let header = FrameHeader::parse(resp.as_slice()).unwrap();
        assert_eq!(header.fc.subtype, subtype::PROBE_RESP);
        assert_eq!(find_ssid(header.ies()), Some(&b"Lab"[..]));
        assert_eq!(find_channel(header.ies()), Some(3));
        let info = classify_security(header.ies(), false);
        assert_eq!(info.security, Security::Open);
    }

    #[test]
    fn auth_and_assoc_frames_carry_expected_fields() {
        let dst = MacAddr::BROADCAST;
        let src = MacAddr::parse("02:00:00:00:00:04").unwrap();
        let auth = auth_frame(dst, src, dst, 0, 1, 0);
        let header = FrameHeader::parse(auth.as_slice()).unwrap();
        assert_eq!(header.fc.subtype, subtype::AUTH);
        assert_eq!(&header.body[..6], &[0, 0, 1, 0, 0, 0]);

        let assoc = assoc_request(dst, src, dst, b"LabNet");
        let header = FrameHeader::parse(assoc.as_slice()).unwrap();
        assert_eq!(header.fc.subtype, subtype::ASSOC_REQ);
        assert_eq!(find_ssid(header.ies()), Some(&b"LabNet"[..]));
    }

    #[test]
    fn wps_element_detection() {
        // Beacon with a WPS vendor IE advertising version 1.0, configured, WPA2 PSK.
        let mut frame = FrameBuffer::new();
        frame.begin_mgmt(
            subtype::BEACON,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
        );
        frame.push(&[0u8; 12]);
        frame.push_element(ie::SSID, b"WPSNet");
        frame.push_element(
            ie::VENDOR,
            &[
                0x00, 0x50, 0xF2, 0x04, // OUI + type 4
                0x10, 0x4A, 0x00, 0x01, 0x10, // version 1.0
                0x10, 0x44, 0x00, 0x01, 0x01, // configured
                0x10, 0x3B, 0x00, 0x01, 0x02, // response type AP
            ],
        );
        let bytes = frame.as_slice().to_vec();
        let header = FrameHeader::parse(&bytes).unwrap();
        let info = classify_security(header.ies(), false);
        assert!(info.wps);
        let wps = parse_wps(header.ies()).expect("wps parses");
        assert_eq!(wps.version, 0x10);
        assert!(wps.configured);
        assert_eq!(wps.response_type, 2);
    }

    #[test]
    fn security_classification_covers_wpa3_and_open() {
        let mut frame = FrameBuffer::new();
        frame.begin_mgmt(
            subtype::BEACON,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
        );
        frame.push(&[0u8; 12]);
        // RSN with SAE-only AKM (type 8).
        let mut rsn = RSN_PSK_CCMP;
        rsn[17] = 8;
        frame.push_element(ie::RSN, &rsn);
        let bytes = frame.as_slice().to_vec();
        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(
            classify_security(header.body, true).security,
            Security::Wpa3Sae
        );

        let mut open = FrameBuffer::new();
        open.begin_mgmt(
            subtype::BEACON,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
            MacAddr::BROADCAST,
        );
        open.push(&[0u8; 12]);
        let bytes = open.as_slice().to_vec();
        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(
            classify_security(header.body, false).security,
            Security::Open
        );
        assert_eq!(classify_security(header.body, true).security, Security::Wep);
    }
}

#[cfg(test)]
mod wps_review_regression {
    use super::*;
    #[test]
    fn wps_state_two_means_configured() {
        let ie=[221,9,0,0x50,0xf2,4,0x10,0x44,0,1,2];
        assert!(parse_wps(&ie).unwrap().configured);
    }
}

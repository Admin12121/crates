//! BSS/station tables, the discovery scan engine and the channel hopper.
//!
//! This is the observation side of G01: it turns raw sniffed frames into the AP and
//! client lists shown on device, including security classification, WPS flags,
//! smoothed RSSI and first/last-seen timestamps. Fixed capacities throughout, so a
//! busy RF environment can never exhaust the heap.

use alloc::string::String;
use alloc::vec::Vec;

use crate::net::{Channel, MacAddr};
use crate::util::printable;

use super::frame::{self, FrameHeader, Security, SecurityInfo, subtype};

/// Maximum SSID length in bytes.
pub const MAX_SSID: usize = 32;

/// A bounded SSID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ssid {
    bytes: [u8; MAX_SSID],
    len: u8,
}

impl Ssid {
    pub fn new(bytes: &[u8]) -> Self {
        let len = bytes.len().min(MAX_SSID);
        let mut out = Self::default();
        out.bytes[..len].copy_from_slice(&bytes[..len]);
        out.len = len as u8;
        out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Hidden networks advertise a zero-length SSID.
    pub fn is_hidden(&self) -> bool {
        self.is_empty()
    }

    /// Printable rendering; non-printable bytes become `.` so a malformed SSID
    /// cannot inject control sequences into the display.
    pub fn display(&self) -> String {
        printable(self.as_bytes())
    }
}

/// One observed access point (BSS).
#[derive(Debug, Clone, Copy)]
pub struct BssRecord {
    pub bssid: MacAddr,
    pub ssid: Ssid,
    pub channel: u8,
    /// Latest RSSI in dBm.
    pub rssi: i8,
    /// EWMA of RSSI scaled by 16 (used for stable sorting).
    pub rssi_avg16: i16,
    pub security: SecurityInfo,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub beacons: u16,
    pub probe_responses: u16,
    pub data_frames: u16,
}

impl BssRecord {
    /// Stable signal value in dBm (smoothed).
    pub fn signal_dbm(&self) -> i8 {
        (self.rssi_avg16 / 16) as i8
    }

    /// Two APs with the same SSID but different BSSIDs are distinct records;
    /// this helper lets the UI group them.
    pub fn ssid_key(&self) -> &[u8] {
        self.ssid.as_bytes()
    }
}

/// Fixed-capacity AP table with weakest-signal eviction.
#[derive(Debug)]
pub struct ApTable<const N: usize> {
    records: [Option<BssRecord>; N],
    count: usize,
    evicted: u32,
}

impl<const N: usize> Default for ApTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ApTable<N> {
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
            count: 0,
            evicted: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn evicted(&self) -> u32 {
        self.evicted
    }

    pub fn clear(&mut self) {
        self.records = [const { None }; N];
        self.count = 0;
    }

    pub fn iter(&self) -> impl Iterator<Item = &BssRecord> {
        self.records.iter().filter_map(|slot| slot.as_ref())
    }

    pub fn get(&self, bssid: MacAddr) -> Option<&BssRecord> {
        self.iter().find(|r| r.bssid == bssid)
    }

    /// Records sorted by smoothed signal strength, strongest first (UI rate only).
    pub fn sorted(&self) -> Vec<BssRecord> {
        let mut list: Vec<BssRecord> = self.iter().copied().collect();
        list.sort_by_key(|r| core::cmp::Reverse(r.rssi_avg16));
        list
    }

    /// Insert or update a beacon/probe-response observation.
    pub fn observe(
        &mut self,
        bssid: MacAddr,
        ssid: Ssid,
        channel: u8,
        rssi: i8,
        security: SecurityInfo,
        is_beacon: bool,
        now_ms: u64,
    ) -> usize {
        if let Some(idx) = self.index_of(bssid) {
            let record = self.records[idx].as_mut().expect("index valid");
            // A hidden-SSID beacon must not erase a name learned from a probe response.
            if !ssid.is_hidden() || record.ssid.is_hidden() {
                record.ssid = ssid;
            }
            if channel != 0 {
                record.channel = channel;
            }
            record.rssi = rssi;
            record.rssi_avg16 = ewma16(record.rssi_avg16, rssi);
            if is_beacon {
                record.beacons = record.beacons.saturating_add(1);
            } else {
                record.probe_responses = record.probe_responses.saturating_add(1);
            }
            record.security = security;
            record.last_seen_ms = now_ms;
            return idx;
        }
        let idx = match self.free_slot() {
            Some(idx) => idx,
            None => {
                self.evict_weakest();
                self.free_slot().expect("eviction frees a slot")
            }
        };
        self.records[idx] = Some(BssRecord {
            bssid,
            ssid,
            channel,
            rssi,
            rssi_avg16: i16::from(rssi) * 16,
            security,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            beacons: u16::from(is_beacon),
            probe_responses: u16::from(!is_beacon),
            data_frames: 0,
        });
        self.count += 1;
        idx
    }

    /// Count a data frame attributed to this BSS.
    pub fn note_data(&mut self, bssid: MacAddr) {
        if let Some(record) = self.records.iter_mut().flatten().find(|r| r.bssid == bssid) {
            record.data_frames = record.data_frames.saturating_add(1);
        }
    }

    /// Total APs by security class, for the UI summary line.
    pub fn count_by_security(&self, security: Security) -> usize {
        self.iter()
            .filter(|r| r.security.security == security)
            .count()
    }

    /// Number of APs advertising WPS.
    pub fn wps_count(&self) -> usize {
        self.iter().filter(|r| r.security.wps).count()
    }

    fn index_of(&self, bssid: MacAddr) -> Option<usize> {
        self.records
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|r| r.bssid == bssid))
    }

    fn free_slot(&self) -> Option<usize> {
        self.records.iter().position(|slot| slot.is_none())
    }

    fn evict_weakest(&mut self) {
        let mut weakest: Option<(usize, i16)> = None;
        for (idx, slot) in self.records.iter().enumerate() {
            if let Some(record) = slot {
                if weakest.map(|(_, v)| record.rssi_avg16 < v).unwrap_or(true) {
                    weakest = Some((idx, record.rssi_avg16));
                }
            }
        }
        if let Some((idx, _)) = weakest {
            self.records[idx] = None;
            self.count -= 1;
            self.evicted = self.evicted.saturating_add(1);
        }
    }
}

fn ewma16(previous: i16, sample: i8) -> i16 {
    // weight 1/4 for the new sample: stable enough for the display, still responsive.
    let sample16 = i16::from(sample) * 16;
    previous + (sample16 - previous) / 4
}

/// One observed client station.
#[derive(Debug, Clone, Copy)]
pub struct StationRecord {
    pub mac: MacAddr,
    /// BSSID the station appears to be associated with, when inferable.
    pub bssid: Option<MacAddr>,
    pub channel: u8,
    pub rssi: i8,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub frames: u32,
}

/// Fixed-capacity station table.
#[derive(Debug)]
pub struct StationTable<const N: usize> {
    records: [Option<StationRecord>; N],
    count: usize,
    evicted: u32,
}

impl<const N: usize> Default for StationTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> StationTable<N> {
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
            count: 0,
            evicted: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn evicted(&self) -> u32 {
        self.evicted
    }

    pub fn clear(&mut self) {
        self.records = [const { None }; N];
        self.count = 0;
    }

    pub fn iter(&self) -> impl Iterator<Item = &StationRecord> {
        self.records.iter().filter_map(|slot| slot.as_ref())
    }

    pub fn get(&self, mac: MacAddr) -> Option<&StationRecord> {
        self.iter().find(|r| r.mac == mac)
    }

    /// Stations seen on `bssid`.
    pub fn for_bssid<'a>(&'a self, bssid: MacAddr) -> impl Iterator<Item = &'a StationRecord> + 'a {
        self.iter().filter(move |r| r.bssid == Some(bssid))
    }

    /// Record activity for a station address.
    pub fn observe(
        &mut self,
        mac: MacAddr,
        bssid: Option<MacAddr>,
        channel: u8,
        rssi: i8,
        now_ms: u64,
    ) {
        if mac.is_broadcast() || mac == MacAddr::ZERO {
            return;
        }
        if let Some(record) = self.records.iter_mut().flatten().find(|r| r.mac == mac) {
            record.frames = record.frames.saturating_add(1);
            record.last_seen_ms = now_ms;
            record.rssi = rssi;
            if bssid.is_some() {
                record.bssid = bssid;
            }
            if channel != 0 {
                record.channel = channel;
            }
            return;
        }
        let idx = match self.records.iter().position(|slot| slot.is_none()) {
            Some(idx) => idx,
            None => {
                // Evict the least recently seen station.
                let mut oldest: Option<(usize, u64)> = None;
                for (i, slot) in self.records.iter().enumerate() {
                    if let Some(record) = slot {
                        if oldest.map(|(_, t)| record.last_seen_ms < t).unwrap_or(true) {
                            oldest = Some((i, record.last_seen_ms));
                        }
                    }
                }
                let (i, _) = oldest.expect("table is full");
                self.records[i] = None;
                self.count -= 1;
                self.evicted = self.evicted.saturating_add(1);
                i
            }
        };
        self.records[idx] = Some(StationRecord {
            mac,
            bssid,
            channel,
            rssi,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            frames: 1,
        });
        self.count += 1;
    }
}

/// What the scan engine learned from one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Beacon {
        bssid: MacAddr,
    },
    ProbeResponse {
        bssid: MacAddr,
    },
    ProbeRequest {
        client: MacAddr,
    },
    Deauth {
        source: MacAddr,
        destination: MacAddr,
    },
    Disassoc {
        source: MacAddr,
        destination: MacAddr,
    },
    Data {
        source: MacAddr,
        destination: MacAddr,
    },
    Eapol {
        source: MacAddr,
        destination: MacAddr,
    },
    Other,
    Malformed,
}

/// Discovery engine: frame in, tables updated.
#[derive(Debug)]
pub struct ScanEngine<const A: usize, const S: usize> {
    pub aps: ApTable<A>,
    pub stations: StationTable<S>,
    pub frames: u32,
    pub management: u32,
    pub data: u32,
    pub deauths: u32,
    pub eapol: u32,
    pub malformed: u32,
    pub session_start_ms: u64,
}

impl<const A: usize, const S: usize> Default for ScanEngine<A, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const A: usize, const S: usize> ScanEngine<A, S> {
    pub const fn new() -> Self {
        Self {
            aps: ApTable::new(),
            stations: StationTable::new(),
            frames: 0,
            management: 0,
            data: 0,
            deauths: 0,
            eapol: 0,
            malformed: 0,
            session_start_ms: 0,
        }
    }

    pub fn reset(&mut self) {
        self.aps.clear();
        self.stations.clear();
        self.frames = 0;
        self.management = 0;
        self.data = 0;
        self.deauths = 0;
        self.eapol = 0;
        self.malformed = 0;
    }

    /// Feed one captured 802.11 frame. `rssi` in dBm, `channel` from the radio.
    pub fn on_frame(&mut self, data: &[u8], rssi: i8, channel: u8, now_ms: u64) -> Observation {
        self.frames = self.frames.saturating_add(1);
        let Some(header) = FrameHeader::parse(data) else {
            self.malformed = self.malformed.saturating_add(1);
            return Observation::Malformed;
        };
        if header.fc.is_management() {
            self.management = self.management.saturating_add(1);
        } else if header.fc.is_data() {
            self.data = self.data.saturating_add(1);
        }

        match (header.fc.frame_type, header.fc.subtype) {
            (frame::FRAME_TYPE_MGMT, subtype::BEACON)
            | (frame::FRAME_TYPE_MGMT, subtype::PROBE_RESP) => {
                let is_beacon = header.fc.subtype == subtype::BEACON;
                let ies = header.ies();
                let ssid = frame::find_ssid(ies).unwrap_or(&[]);
                let caps = frame::capabilities(header.body).unwrap_or(0);
                let security = frame::classify_security(ies, caps & 0x0010 != 0);
                let bssid = header.addr3;
                let chan = frame::find_channel(ies).unwrap_or(channel);
                self.aps.observe(
                    bssid,
                    Ssid::new(ssid),
                    chan,
                    rssi,
                    security,
                    is_beacon,
                    now_ms,
                );
                if is_beacon {
                    Observation::Beacon { bssid }
                } else {
                    Observation::ProbeResponse { bssid }
                }
            }
            (frame::FRAME_TYPE_MGMT, subtype::PROBE_REQ) => {
                self.stations
                    .observe(header.addr2, None, channel, rssi, now_ms);
                Observation::ProbeRequest {
                    client: header.addr2,
                }
            }
            (frame::FRAME_TYPE_MGMT, subtype::DEAUTH) => {
                self.deauths = self.deauths.saturating_add(1);
                if header.addr2.is_broadcast() {
                    // Broadcast deauth: attribute to every AP we know on this channel.
                    for ap in self.aps.iter() {
                        if ap.channel == channel {
                            self.stations
                                .observe(ap.bssid, Some(ap.bssid), channel, rssi, now_ms);
                        }
                    }
                }
                Observation::Deauth {
                    source: header.addr2,
                    destination: header.addr1,
                }
            }
            (frame::FRAME_TYPE_MGMT, subtype::DISASSOC) => Observation::Disassoc {
                source: header.addr2,
                destination: header.addr1,
            },
            (frame::FRAME_TYPE_MGMT, subtype::AUTH) => {
                self.stations
                    .observe(header.addr2, Some(header.addr3), channel, rssi, now_ms);
                Observation::Other
            }
            (frame::FRAME_TYPE_DATA, _) => {
                // ToDS frames are client->AP: addr2 is the client, addr1 the BSSID.
                let (client, bssid) = if header.fc.to_ds {
                    (header.addr2, header.addr1)
                } else if header.fc.from_ds {
                    (header.addr1, header.addr2)
                } else {
                    (header.addr2, header.addr3)
                };
                if !header.fc.protected {
                    // EAPOL frames are the interesting ones: they are sent
                    // unprotected with the EAPOL ethertype 0x888E.
                    if is_eapol_frame(header.body) {
                        self.eapol = self.eapol.saturating_add(1);
                        self.stations
                            .observe(client, Some(bssid), channel, rssi, now_ms);
                        self.aps.note_data(bssid);
                        return Observation::Eapol {
                            source: client,
                            destination: bssid,
                        };
                    }
                }
                self.stations
                    .observe(client, Some(bssid), channel, rssi, now_ms);
                self.aps.note_data(bssid);
                Observation::Data {
                    source: client,
                    destination: bssid,
                }
            }
            _ => Observation::Other,
        }
    }

    /// One-line summary for the scan screen.
    pub fn summary(&self) -> String {
        alloc::format!(
            "AP {}  STA {}  PKT {}  DA {}  EAPOL {}",
            self.aps.len(),
            self.stations.len(),
            self.frames,
            self.deauths,
            self.eapol
        )
    }
}

/// Detect an EAPOL payload inside a data frame body (SNAP + 0x888E ethertype).
pub fn is_eapol_frame(body: &[u8]) -> bool {
    // 802.11 data body starts with LLC/SNAP: AA AA 03 00 00 00 <ethertype>
    body.len() >= 8
        && body[..6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]
        && body[6..8] == [0x88, 0x8E]
}

/// Extract the EAPOL payload from a data frame body.
pub fn eapol_payload(body: &[u8]) -> Option<&[u8]> {
    if is_eapol_frame(body) {
        Some(&body[8..])
    } else {
        None
    }
}

/// Channel hop scheduler.
#[derive(Debug)]
pub struct ChannelHopper {
    plan: Vec<Channel>,
    dwell_ms: u32,
    index: usize,
    last_hop_ms: u64,
    hops: u32,
}

impl ChannelHopper {
    pub fn new(plan: Vec<Channel>, dwell_ms: u32) -> Self {
        Self {
            plan,
            dwell_ms: dwell_ms.max(20),
            index: 0,
            last_hop_ms: 0,
            hops: 0,
        }
    }

    pub fn plan(&self) -> &[Channel] {
        &self.plan
    }

    pub fn current(&self) -> Option<Channel> {
        self.plan.get(self.index).copied()
    }

    pub fn dwell_ms(&self) -> u32 {
        self.dwell_ms
    }

    pub fn hops(&self) -> u32 {
        self.hops
    }

    /// Fixed-channel mode: a single-entry plan.
    pub fn fixed(channel: Channel) -> Self {
        Self::new(alloc::vec![channel], u32::MAX)
    }

    /// Advance the plan if the dwell time elapsed. Returns the new channel.
    pub fn poll(&mut self, now_ms: u64) -> Option<Channel> {
        if self.plan.is_empty() {
            return None;
        }
        if now_ms.saturating_sub(self.last_hop_ms) < u64::from(self.dwell_ms) {
            return None;
        }
        self.last_hop_ms = now_ms;
        if self.plan.len() > 1 {
            self.index = (self.index + 1) % self.plan.len();
            self.hops = self.hops.saturating_add(1);
        }
        self.current()
    }

    pub fn set_channel(&mut self, channel: Channel, now_ms: u64) {
        self.plan = alloc::vec![channel];
        self.index = 0;
        self.last_hop_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::frame::tests_support::beacon_frame_bytes;
    use crate::wifi::frame::{BeaconOptions, beacon_frame};

    fn engine() -> ScanEngine<32, 64> {
        ScanEngine::new()
    }

    #[test]
    fn beacon_populates_ap_table_with_metadata() {
        let mut engine = engine();
        let bytes = beacon_frame_bytes();
        let observation = engine.on_frame(&bytes, -48, 6, 1_000);
        let bssid = MacAddr::parse("00:11:22:33:44:55").unwrap();
        assert_eq!(observation, Observation::Beacon { bssid });
        assert_eq!(engine.aps.len(), 1);
        let ap = engine.aps.get(bssid).unwrap();
        assert_eq!(ap.ssid.display(), "CyberLab");
        assert_eq!(ap.channel, 6);
        assert_eq!(ap.security.security, Security::Wpa2Psk);
        assert_eq!(ap.beacons, 1);
        assert_eq!(ap.first_seen_ms, 1_000);
        assert_eq!(engine.summary(), "AP 1  STA 0  PKT 1  DA 0  EAPOL 0");
    }

    #[test]
    fn repeated_beacons_update_instead_of_duplicating() {
        let mut engine = engine();
        let bytes = beacon_frame_bytes();
        for i in 0..5 {
            engine.on_frame(&bytes, -40 - i as i8, 6, 1_000 + i * 100);
        }
        assert_eq!(engine.aps.len(), 1);
        let ap = engine.aps.iter().next().unwrap();
        assert_eq!(ap.beacons, 5);
        assert_eq!(ap.last_seen_ms, 1_400);
        // Smoothed signal moves toward the newest sample without jumping.
        assert!(ap.signal_dbm() > -60 && ap.signal_dbm() < -30);
    }

    #[test]
    fn table_evicts_weakest_ap_when_full() {
        let mut engine: ScanEngine<2, 4> = ScanEngine::new();
        let bssid_a = MacAddr::parse("02:00:00:00:00:0A").unwrap();
        let bssid_b = MacAddr::parse("02:00:00:00:00:0B").unwrap();
        let bssid_c = MacAddr::parse("02:00:00:00:00:0C").unwrap();
        let options = BeaconOptions::default();
        engine.on_frame(beacon_frame(b"A", bssid_a, &options).as_slice(), -30, 1, 0);
        engine.on_frame(beacon_frame(b"B", bssid_b, &options).as_slice(), -80, 1, 0);
        engine.on_frame(beacon_frame(b"C", bssid_c, &options).as_slice(), -50, 1, 0);
        assert_eq!(engine.aps.len(), 2);
        assert_eq!(engine.aps.evicted(), 1);
        assert!(engine.aps.get(bssid_b).is_none(), "weakest AP evicted");
        assert!(engine.aps.get(bssid_a).is_some());
        assert!(engine.aps.get(bssid_c).is_some());
    }

    #[test]
    fn hidden_beacon_does_not_erase_known_ssid() {
        let mut engine = engine();
        let bssid = MacAddr::parse("02:00:00:00:00:0D").unwrap();
        let named = BeaconOptions::default();
        engine.on_frame(beacon_frame(b"Named", bssid, &named).as_slice(), -50, 1, 0);
        let hidden = BeaconOptions {
            hidden: true,
            ..Default::default()
        };
        engine.on_frame(
            beacon_frame(b"Named", bssid, &hidden).as_slice(),
            -50,
            1,
            10,
        );
        assert_eq!(engine.aps.get(bssid).unwrap().ssid.display(), "Named");
    }

    #[test]
    fn probe_request_learns_client_and_deauths_are_counted() {
        let mut engine = engine();
        let client = MacAddr::parse("02:11:22:33:44:55").unwrap();
        let request = frame::probe_request(client, Some(b"CyberLab"));
        let obs = engine.on_frame(request.as_slice(), -60, 1, 5);
        assert_eq!(obs, Observation::ProbeRequest { client });
        assert_eq!(engine.stations.len(), 1);
        assert!(engine.stations.get(client).unwrap().mac.is_randomised());

        let ap = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let deauth = frame::deauth_frame(MacAddr::BROADCAST, ap, frame::reason::UNSPECIFIED);
        let obs = engine.on_frame(deauth.as_slice(), -50, 1, 6);
        assert_eq!(
            obs,
            Observation::Deauth {
                source: ap,
                destination: MacAddr::BROADCAST
            }
        );
        assert_eq!(engine.deauths, 1);
    }

    #[test]
    fn data_frames_attribute_station_to_bssid() {
        let mut engine = engine();
        let ap = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let client = MacAddr::parse("02:AA:BB:CC:DD:EE").unwrap();
        // ToDS data frame: addr1 = BSSID, addr2 = client.
        let mut data = alloc::vec![0x08, 0x01, 0x00, 0x00];
        data.extend_from_slice(ap.as_bytes());
        data.extend_from_slice(client.as_bytes());
        data.extend_from_slice(ap.as_bytes());
        data.extend_from_slice(&[0x10, 0x00]);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let obs = engine.on_frame(&data, -55, 6, 9);
        assert_eq!(
            obs,
            Observation::Data {
                source: client,
                destination: ap
            }
        );
        let station = engine.stations.get(client).unwrap();
        assert_eq!(station.bssid, Some(ap));
        assert_eq!(station.channel, 6);
    }

    #[test]
    fn malformed_frames_are_counted_not_fatal() {
        let mut engine = engine();
        assert_eq!(
            engine.on_frame(&[0x80, 0x00], 0, 1, 0),
            Observation::Malformed
        );
        assert_eq!(engine.malformed, 1);
        assert!(engine.aps.is_empty());
    }

    #[test]
    fn channel_hopper_cycles_with_dwell() {
        let plan = crate::net::hop_plan(1, false);
        let mut hopper = ChannelHopper::new(plan, 200);
        assert_eq!(hopper.current().unwrap().get(), 1);
        assert_eq!(hopper.poll(100), None);
        assert_eq!(hopper.poll(200).unwrap().get(), 2);
        assert_eq!(hopper.poll(200), None);
        assert_eq!(hopper.poll(400).unwrap().get(), 3);
        assert_eq!(hopper.hops(), 2);
        hopper.set_channel(Channel::new(11).unwrap(), 500);
        assert_eq!(hopper.current().unwrap().get(), 11);
        assert_eq!(hopper.plan().len(), 1);
    }

    #[test]
    fn eapol_detection_and_extraction() {
        let mut body = alloc::vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
        body.extend_from_slice(&[0x02, 0x03, 0x00, 0x5F]);
        assert!(is_eapol_frame(&body));
        assert_eq!(eapol_payload(&body).unwrap(), &[0x02, 0x03, 0x00, 0x5F]);
        assert!(eapol_payload(&[0u8; 4]).is_none());
    }

    #[test]
    fn ssid_sanitises_control_bytes() {
        let ssid = Ssid::new(b"evil\x1b[31m");
        assert_eq!(ssid.display(), "evil.[31m");
        assert_eq!(Ssid::new(&[b'x'; 40]).len(), MAX_SSID);
    }
}

#[cfg(test)]
mod review_regression {
    use super::*;
    #[test]
    fn cleartext_eapol_is_observed_as_eapol() {
        let mut frame=alloc::vec![0x08,1,0,0];frame.extend_from_slice(&[1;6]);frame.extend_from_slice(&[2;6]);frame.extend_from_slice(&[3;6]);frame.extend_from_slice(&[0;2]);
        frame.extend_from_slice(&[0xaa,0xaa,3,0,0,0,0x88,0x8e,2,3]);
        let mut engine:ScanEngine<2,2>=ScanEngine::new();
        assert!(matches!(engine.on_frame(&frame,-40,1,1),Observation::Eapol {..}));
        assert_eq!(engine.eapol,1);
    }
}

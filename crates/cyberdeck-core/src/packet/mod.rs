//! G02 — capture session management, filtering, protocol accounting and browsing.
//!
//! The PCAP wire format lives in [`crate::pcap`]; this module owns the session
//! semantics around it: counters that must match the file, filters used while
//! capturing, per-frame summaries for the on-device browser, and export helpers.

pub mod storage;
pub mod passive;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::net::{Channel, MacAddr};
use crate::pcap::{PcapStats, Radiotap};
use crate::time::{Millis, Timestamp};
use crate::util::hex_join;
use crate::wifi::frame::{self, FrameHeader};

/// Longest frame accepted from the radio (802.11 MTU plus radiotap room).
pub const MAX_FRAME_BYTES: usize = 2048;

/// Kind of frame, used for the histogram and the browser label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Authentication,
    Association,
    Deauthentication,
    Disassociation,
    Action,
    Eapol,
    Data,
    Control,
    Other,
    Malformed,
}

impl FrameKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Beacon => "BEACON",
            Self::ProbeRequest => "PROBE REQ",
            Self::ProbeResponse => "PROBE RSP",
            Self::Authentication => "AUTH",
            Self::Association => "ASSOC",
            Self::Deauthentication => "DEAUTH",
            Self::Disassociation => "DISASSOC",
            Self::Action => "ACTION",
            Self::Eapol => "EAPOL",
            Self::Data => "DATA",
            Self::Control => "CTRL",
            Self::Other => "OTHER",
            Self::Malformed => "BAD",
        }
    }
}

/// Classify one captured frame (cheap: fixed offsets only).
pub fn classify(data: &[u8]) -> (FrameKind, Option<FrameHeader<'_>>) {
    let Some(header) = FrameHeader::parse(data) else {
        return (FrameKind::Malformed, None);
    };
    let kind = if header.fc.is_data() {
        if crate::wifi::ap::is_eapol_frame(header.body) {
            FrameKind::Eapol
        } else {
            FrameKind::Data
        }
    } else if header.fc.is_management() {
        match header.fc.subtype {
            frame::subtype::BEACON => FrameKind::Beacon,
            frame::subtype::PROBE_REQ => FrameKind::ProbeRequest,
            frame::subtype::PROBE_RESP => FrameKind::ProbeResponse,
            frame::subtype::AUTH => FrameKind::Authentication,
            frame::subtype::ASSOC_REQ | frame::subtype::ASSOC_RESP => FrameKind::Association,
            frame::subtype::REASSOC_REQ | frame::subtype::REASSOC_RESP => FrameKind::Association,
            frame::subtype::DEAUTH => FrameKind::Deauthentication,
            frame::subtype::DISASSOC => FrameKind::Disassociation,
            frame::subtype::ACTION | frame::subtype::ACTION_NO_ACK => FrameKind::Action,
            _ => FrameKind::Other,
        }
    } else if header.fc.frame_type == frame::FRAME_TYPE_CTRL {
        FrameKind::Control
    } else {
        FrameKind::Other
    };
    (kind, Some(header))
}

/// Per-kind counters shown in the analysis screen and written to the session log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolHistogram {
    pub beacons: u32,
    pub probe_requests: u32,
    pub probe_responses: u32,
    pub authentication: u32,
    pub association: u32,
    pub deauthentication: u32,
    pub disassociation: u32,
    pub action: u32,
    pub eapol: u32,
    pub data: u32,
    pub control: u32,
    pub other: u32,
    pub malformed: u32,
}

impl ProtocolHistogram {
    pub fn count(&mut self, kind: FrameKind) {
        match kind {
            FrameKind::Beacon => self.beacons = self.beacons.saturating_add(1),
            FrameKind::ProbeRequest => self.probe_requests = self.probe_requests.saturating_add(1),
            FrameKind::ProbeResponse => {
                self.probe_responses = self.probe_responses.saturating_add(1)
            }
            FrameKind::Authentication => {
                self.authentication = self.authentication.saturating_add(1)
            }
            FrameKind::Association => self.association = self.association.saturating_add(1),
            FrameKind::Deauthentication => {
                self.deauthentication = self.deauthentication.saturating_add(1)
            }
            FrameKind::Disassociation => {
                self.disassociation = self.disassociation.saturating_add(1)
            }
            FrameKind::Action => self.action = self.action.saturating_add(1),
            FrameKind::Eapol => self.eapol = self.eapol.saturating_add(1),
            FrameKind::Data => self.data = self.data.saturating_add(1),
            FrameKind::Control => self.control = self.control.saturating_add(1),
            FrameKind::Other => self.other = self.other.saturating_add(1),
            FrameKind::Malformed => self.malformed = self.malformed.saturating_add(1),
        }
    }

    pub fn total(&self) -> u32 {
        self.beacons
            + self.probe_requests
            + self.probe_responses
            + self.authentication
            + self.association
            + self.deauthentication
            + self.disassociation
            + self.action
            + self.eapol
            + self.data
            + self.control
            + self.other
            + self.malformed
    }

    /// Multi-line report for the analysis screen and the session text log.
    pub fn report(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Beacons        {:>8}", self.beacons);
        let _ = writeln!(out, "Probe req      {:>8}", self.probe_requests);
        let _ = writeln!(out, "Probe resp     {:>8}", self.probe_responses);
        let _ = writeln!(out, "Auth           {:>8}", self.authentication);
        let _ = writeln!(out, "Assoc          {:>8}", self.association);
        let _ = writeln!(out, "Deauth         {:>8}", self.deauthentication);
        let _ = writeln!(out, "Disassoc       {:>8}", self.disassociation);
        let _ = writeln!(out, "Action         {:>8}", self.action);
        let _ = writeln!(out, "EAPOL          {:>8}", self.eapol);
        let _ = writeln!(out, "Data           {:>8}", self.data);
        let _ = writeln!(out, "Control        {:>8}", self.control);
        let _ = writeln!(out, "Other/bad      {:>8}", self.other + self.malformed);
        out
    }
}

/// Capture-time filter. Filtering happens before the pcap write so a narrow filter
/// also saves card space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureFilter {
    pub management_only: bool,
    pub data_only: bool,
    pub bssid: Option<MacAddr>,
    pub min_length: u16,
    pub max_length: u16,
}

impl Default for CaptureFilter {
    fn default() -> Self {
        Self {
            management_only: false,
            data_only: false,
            bssid: None,
            min_length: 0,
            max_length: MAX_FRAME_BYTES as u16,
        }
    }
}

impl CaptureFilter {
    pub fn management_only() -> Self {
        Self {
            management_only: true,
            ..Default::default()
        }
    }

    pub fn for_bssid(bssid: MacAddr) -> Self {
        Self {
            bssid: Some(bssid),
            ..Default::default()
        }
    }

    /// Whether a frame passes the filter.
    pub fn matches(&self, data: &[u8]) -> bool {
        let len = data.len();
        if len < usize::from(self.min_length) || len > usize::from(self.max_length) {
            return false;
        }
        let Some(header) = FrameHeader::parse(data) else {
            return !self.management_only && !self.data_only;
        };
        if self.management_only && !header.fc.is_management() {
            return false;
        }
        if self.data_only && !header.fc.is_data() {
            return false;
        }
        if let Some(bssid) = self.bssid {
            let addresses = [header.addr1, header.addr2, header.addr3];
            if !addresses.contains(&bssid) {
                return false;
            }
        }
        true
    }

    /// One-line description for the run screen.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.management_only {
            parts.push(String::from("mgmt only"));
        } else if self.data_only {
            parts.push(String::from("data only"));
        } else {
            parts.push(String::from("all frames"));
        }
        if let Some(bssid) = self.bssid {
            parts.push(alloc::format!("BSSID {bssid}"));
        }
        parts.join(", ")
    }
}

/// One row in the on-device packet browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketSummary {
    pub index: u32,
    pub ts: Timestamp,
    pub kind: FrameKind,
    pub source: MacAddr,
    pub destination: MacAddr,
    pub length: u16,
    pub channel: u8,
    pub rssi: i8,
}

impl PacketSummary {
    pub fn build(index: u32, ts: Timestamp, data: &[u8], channel: u8, rssi: i8) -> PacketSummary {
        let (kind, header) = classify(data);
        let (source, destination) = match header {
            Some(header) => (header.addr2, header.addr1),
            None => (MacAddr::ZERO, MacAddr::ZERO),
        };
        Self {
            index,
            ts,
            kind,
            source,
            destination,
            length: data.len().min(u16::MAX as usize) as u16,
            channel,
            rssi,
        }
    }

    /// Compact browser line: `#0012 DEAUTH 00:11.. -> FF:FF.. 26B -42dBm`.
    pub fn render_line(&self, width: usize) -> String {
        let head = alloc::format!(
            "#{:04} {:<9} {}B {}dBm ch{}",
            self.index,
            self.kind.label(),
            self.length,
            self.rssi,
            self.channel
        );
        super::ui::ellipsize(&head, width)
    }
}

/// Bounded ring of recent frame summaries for the browser.
#[derive(Debug)]
pub struct PacketLog<const N: usize> {
    entries: [Option<PacketSummary>; N],
    head: usize,
    len: usize,
    dropped: u32,
}

impl<const N: usize> Default for PacketLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PacketLog<N> {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, summary: PacketSummary) {
        if self.len == N {
            self.entries[self.head] = Some(summary);
            self.head = (self.head + 1) % N;
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let idx = (self.head + self.len) % N;
        self.entries[idx] = Some(summary);
        self.len += 1;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn iter(&self) -> impl Iterator<Item = &PacketSummary> {
        (0..self.len).filter_map(move |i| self.entries[(self.head + i) % N].as_ref())
    }

    pub fn clear(&mut self) {
        self.entries = [const { None }; N];
        self.head = 0;
        self.len = 0;
    }
}

/// Session-level numbers that must agree with the file on card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureSummary {
    pub frames: u32,
    pub bytes: u64,
    pub dropped: u32,
    pub truncated: u32,
    pub queue_overflows: u32,
    pub started_ms: Millis,
    pub ended_ms: Millis,
    pub channels: u8,
}

impl CaptureSummary {
    pub fn duration_ms(&self) -> Millis {
        self.ended_ms.saturating_sub(self.started_ms)
    }

    pub fn frames_per_second(&self) -> u32 {
        let duration = self.duration_ms();
        if duration == 0 {
            return 0;
        }
        (u64::from(self.frames) * 1000 / duration) as u32
    }

    /// Merge writer statistics into the session summary.
    pub fn merge_pcap(&mut self, stats: PcapStats) {
        self.frames = stats.records;
        self.bytes = stats.payload_bytes;
        self.truncated = stats.truncated;
        self.dropped = stats.dropped;
    }

    /// Text report written next to the pcap (`<name>.txt`).
    pub fn report(&self, filename: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "CyberDeck capture report");
        let _ = writeln!(out, "file: {filename}");
        let _ = writeln!(out, "frames: {}", self.frames);
        let _ = writeln!(out, "payload bytes: {}", self.bytes);
        let _ = writeln!(out, "duration ms: {}", self.duration_ms());
        let _ = writeln!(out, "frames/s: {}", self.frames_per_second());
        let _ = writeln!(out, "channels: {}", self.channels);
        let _ = writeln!(out, "dropped (size/shutdown): {}", self.dropped);
        let _ = writeln!(out, "truncated frames: {}", self.truncated);
        let _ = writeln!(out, "queue overflows: {}", self.queue_overflows);
        out
    }
}

/// File name for a capture: `cd-<prefix>-<uptime>.pcap`.
pub fn session_file_name(prefix: &str, started_ms: Millis) -> String {
    alloc::format!("cd-{prefix}-{:06}.pcap", started_ms / 1000)
}

/// Radiotap metadata for a captured frame on `channel`.
pub fn radiotap_for(channel: Channel, rssi: i8, ts: Timestamp) -> Radiotap {
    let mut radiotap = Radiotap::for_mgmt(channel.frequency_mhz(), rssi);
    radiotap.tsft_us = ts.to_micros();
    radiotap
}

/// Printable hex dump for the frame inspector (capped for the display).
pub fn hexdump(data: &[u8], max_rows: usize) -> String {
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        if row >= max_rows {
            let _ = writeln!(out, "... {} bytes total", data.len());
            break;
        }
        let mut line = alloc::format!("{:04X}  ", row * 16);
        let _ = write!(line, "{}", hex_join(chunk));
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// 802.11 protocol names for the analysis view (decoding is metadata only).
pub fn frame_description(kind: FrameKind) -> &'static str {
    match kind {
        FrameKind::Beacon => "Access point beacon advertising an SSID",
        FrameKind::ProbeRequest => "Client searching for a network",
        FrameKind::ProbeResponse => "AP answering a probe request",
        FrameKind::Authentication => "802.11 authentication exchange",
        FrameKind::Association => "Association/reassociation exchange",
        FrameKind::Deauthentication => "Session teardown (possible attack)",
        FrameKind::Disassociation => "Disassociation notice",
        FrameKind::Action => "Action frame (spectrum/measurement/WNM)",
        FrameKind::Eapol => "EAPOL-Key: 4-way handshake material",
        FrameKind::Data => "Protected or plain data frame",
        FrameKind::Control => "Control frame (ACK/RTS/CTS)",
        FrameKind::Other => "Unclassified management frame",
        FrameKind::Malformed => "Frame too short or unparsable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::frame::tests_support::beacon_frame_bytes;

    #[test]
    fn classifies_beacons_and_eapol() {
        let beacon = beacon_frame_bytes();
        assert_eq!(classify(&beacon).0, FrameKind::Beacon);

        let mut data = alloc::vec![0x08, 0x01, 0x00, 0x00];
        data.extend_from_slice(&[0xAA; 6]);
        data.extend_from_slice(&[0xBB; 6]);
        data.extend_from_slice(&[0xCC; 6]);
        data.extend_from_slice(&[0x10, 0x00]);
        data.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x02, 0x03]);
        assert_eq!(classify(&data).0, FrameKind::Eapol);
    }

    #[test]
    fn malformed_frames_are_classified_not_dropped_silently() {
        let (kind, header) = classify(&[0x80, 0x00, 0x00]);
        assert_eq!(kind, FrameKind::Malformed);
        assert!(header.is_none());
        let mut histogram = ProtocolHistogram::default();
        histogram.count(kind);
        assert_eq!(histogram.malformed, 1);
        assert_eq!(histogram.total(), 1);
    }

    #[test]
    fn histogram_counts_and_reports() {
        let mut histogram = ProtocolHistogram::default();
        for kind in [
            FrameKind::Beacon,
            FrameKind::Beacon,
            FrameKind::Eapol,
            FrameKind::Data,
        ] {
            histogram.count(kind);
        }
        assert_eq!(histogram.beacons, 2);
        assert_eq!(histogram.total(), 4);
        let report = histogram.report();
        assert!(
            report
                .lines()
                .any(|line| line.starts_with("Beacons") && line.trim_end().ends_with('2'))
        );
        assert!(report.contains("EAPOL"));
    }

    #[test]
    fn filters_select_frames() {
        let beacon = beacon_frame_bytes();
        let all = CaptureFilter::default();
        assert!(all.matches(&beacon));
        assert!(CaptureFilter::management_only().matches(&beacon));
        assert!(!CaptureFilter::management_only().matches(&[0xFFu8; 40]));

        let bssid = MacAddr::parse("00:11:22:33:44:55").unwrap();
        assert!(CaptureFilter::for_bssid(bssid).matches(&beacon));
        let other = CaptureFilter::for_bssid(MacAddr::parse("02:00:00:00:00:99").unwrap());
        assert!(!other.matches(&beacon));

        let filtered = CaptureFilter {
            min_length: 200,
            ..Default::default()
        };
        assert!(!filtered.matches(&beacon));
        assert_eq!(all.describe(), "all frames");
        assert_eq!(CaptureFilter::management_only().describe(), "mgmt only");
    }

    #[test]
    fn packet_log_keeps_newest_and_counts_drops() {
        let mut log: PacketLog<3> = PacketLog::new();
        let beacon = beacon_frame_bytes();
        for i in 0..5 {
            log.push(PacketSummary::build(
                i,
                Timestamp::new(1, 0),
                &beacon,
                6,
                -40,
            ));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.dropped(), 2);
        let indices: Vec<u32> = log.iter().map(|s| s.index).collect();
        assert_eq!(indices, alloc::vec![2, 3, 4]);
        assert!(log.iter().next().unwrap().render_line(20).chars().count() <= 20);
    }

    #[test]
    fn summary_rates_and_report() {
        let mut summary = CaptureSummary {
            frames: 1000,
            started_ms: 1_000,
            ended_ms: 3_000,
            channels: 13,
            ..Default::default()
        };
        summary.merge_pcap(PcapStats {
            records: 1000,
            payload_bytes: 64_000,
            truncated: 2,
            dropped: 1,
        });
        assert_eq!(summary.duration_ms(), 2_000);
        assert_eq!(summary.frames_per_second(), 500);
        let report = summary.report("cd-capture-000001.pcap");
        assert!(report.contains("frames: 1000"));
        assert!(report.contains("frames/s: 500"));
        assert!(report.contains("truncated frames: 2"));
    }

    #[test]
    fn file_names_are_sortable_and_slugged() {
        assert_eq!(
            session_file_name("capture", 12_000),
            "cd-capture-000012.pcap"
        );
        assert_eq!(session_file_name("ap", 0), "cd-ap-000000.pcap");
    }

    #[test]
    fn hexdump_is_bounded() {
        let dump = hexdump(&[0xAB; 100], 2);
        assert_eq!(dump.lines().count(), 3);
        assert!(dump.contains("100 bytes total"));
        assert!(dump.starts_with("0000  AB:AB"));
    }

    #[test]
    fn radiotap_tracks_channel_and_timestamp() {
        let radiotap = radiotap_for(Channel::new(6).unwrap(), -42, Timestamp::new(10, 5));
        assert_eq!(radiotap.freq_mhz, 2437);
        assert_eq!(radiotap.signal_dbm, -42);
        assert_eq!(radiotap.tsft_us, 10_000_005);
    }

    #[test]
    fn descriptions_cover_every_kind() {
        for kind in [
            FrameKind::Beacon,
            FrameKind::ProbeRequest,
            FrameKind::ProbeResponse,
            FrameKind::Authentication,
            FrameKind::Association,
            FrameKind::Deauthentication,
            FrameKind::Disassociation,
            FrameKind::Action,
            FrameKind::Eapol,
            FrameKind::Data,
            FrameKind::Control,
            FrameKind::Other,
            FrameKind::Malformed,
        ] {
            assert!(!frame_description(kind).is_empty());
            assert!(!kind.label().is_empty());
        }
    }
}

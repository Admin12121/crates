//! nRF24 session baseline: per-channel traffic and payload shape.
//!
//! The nRF24 exposes no signal metric, so a session summarises what the radio
//! actually observed: how long it ran, how many packets arrived, which channels
//! carried them and what the payloads looked like. Payload classes are honest
//! shape labels, not vendor-protocol decoding.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::nrf24::{frequency_mhz, CHANNEL_COUNT};

/// Channels as a slice bound.
const CHANNELS: usize = CHANNEL_COUNT as usize;

/// Coarse payload shape used to summarise a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    /// No payload bytes arrived.
    Empty,
    /// Every byte is identical (a beacon or an idle counter).
    Repeated,
    /// Mostly printable ASCII, i.e. a text payload.
    Text,
    /// Anything else.
    Structured,
}

impl PayloadClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "EMPTY",
            Self::Repeated => "REPEAT",
            Self::Text => "TEXT",
            Self::Structured => "BINARY",
        }
    }
}

/// Classify one payload by shape.
pub fn classify_payload(bytes: &[u8]) -> PayloadClass {
    if bytes.is_empty() {
        return PayloadClass::Empty;
    }
    if bytes.iter().all(|byte| *byte == bytes[0]) {
        return PayloadClass::Repeated;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || **byte == b' ')
        .count();
    if printable * 5 >= bytes.len() * 4 {
        PayloadClass::Text
    } else {
        PayloadClass::Structured
    }
}

/// Running totals for one RF capture session.
#[derive(Debug, Clone)]
pub struct SessionStats {
    started_ms: u64,
    packets: u32,
    bytes: u32,
    text: u32,
    repeated: u32,
    structured: u32,
    busiest_channel: u8,
    busiest_packets: u32,
    per_channel: [u32; CHANNELS],
}

impl SessionStats {
    pub const fn new(started_ms: u64) -> Self {
        Self {
            started_ms,
            packets: 0,
            bytes: 0,
            text: 0,
            repeated: 0,
            structured: 0,
            busiest_channel: 0,
            busiest_packets: 0,
            per_channel: [0; CHANNELS],
        }
    }

    /// Record one received packet.
    pub fn record(&mut self, channel: u8, payload: &[u8]) {
        let index = usize::from(channel) % CHANNELS;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(payload.len() as u32);
        self.per_channel[index] = self.per_channel[index].saturating_add(1);
        if self.per_channel[index] > self.busiest_packets {
            self.busiest_packets = self.per_channel[index];
            self.busiest_channel = channel;
        }
        match classify_payload(payload) {
            PayloadClass::Text => self.text = self.text.saturating_add(1),
            PayloadClass::Repeated => self.repeated = self.repeated.saturating_add(1),
            PayloadClass::Structured => self.structured = self.structured.saturating_add(1),
            PayloadClass::Empty => {}
        }
    }

    pub const fn packets(&self) -> u32 {
        self.packets
    }

    pub const fn duration_seconds(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.started_ms) / 1000
    }

    /// Short result lines for the device screen.
    pub fn lines(&self, now_ms: u64) -> Vec<String> {
        let mut out = Vec::new();
        out.push(format!(
            "{}S  {} PKTS  {} B",
            self.duration_seconds(now_ms),
            self.packets,
            self.bytes
        ));
        out.push(format!(
            "TEXT {}  {}  {}",
            self.text,
            PayloadClass::Repeated.label(),
            self.repeated
        ));
        out.push(format!("BINARY {}", self.structured));
        if self.busiest_packets > 0 {
            out.push(format!(
                "BUSIEST CH{}  {} PKTS",
                self.busiest_channel, self.busiest_packets
            ));
        }
        out
    }

    /// CSV export: one row per channel that carried traffic, then a summary block.
    pub fn csv(&self, now_ms: u64) -> String {
        let mut out = String::from("# Admin12121 nRF24 session\n");
        out.push_str(&format!(
            "# duration_s,{}\n# packets,{}\n# bytes,{}\n# text,{}\n# repeated,{}\n# structured,{}\n",
            self.duration_seconds(now_ms),
            self.packets,
            self.bytes,
            self.text,
            self.repeated,
            self.structured
        ));
        out.push_str("channel,frequency_mhz,packets\n");
        for (channel, count) in self.per_channel.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            out.push_str(&format!(
                "{},{},{}\n",
                channel,
                frequency_mhz(channel as u8),
                count
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape_is_labelled() {
        assert_eq!(classify_payload(&[]), PayloadClass::Empty);
        assert_eq!(classify_payload(&[0xAA; 8]), PayloadClass::Repeated);
        assert_eq!(classify_payload(b"Admin12121"), PayloadClass::Text);
        assert_eq!(classify_payload(&[0x01, 0x02, 0x03, 0x04, 0xFF, 0x00]), PayloadClass::Structured);
    }

    #[test]
    fn recording_counts_channels_and_shape() {
        let mut stats = SessionStats::new(1_000);
        stats.record(6, b"hello");
        stats.record(6, b"world");
        stats.record(76, &[0xAA; 4]);
        stats.record(76, &[0x01, 0x02, 0x03]);
        assert_eq!(stats.packets(), 4);
        assert_eq!(stats.per_channel[6], 2);
        assert_eq!(stats.per_channel[76], 2);
        assert_eq!(stats.busiest_channel, 6, "ties keep the first channel that reached the peak");
        assert_eq!(stats.text, 2);
        assert_eq!(stats.repeated, 1);
        assert_eq!(stats.structured, 1);
        assert_eq!(stats.duration_seconds(4_500), 3);
    }

    #[test]
    fn csv_lists_only_channels_with_traffic() {
        let mut stats = SessionStats::new(0);
        stats.record(6, b"x");
        stats.record(40, b"y");
        let csv = stats.csv(2_000);
        assert!(csv.contains("channel,frequency_mhz,packets"));
        assert!(csv.contains("6,2406,1"));
        assert!(csv.contains("40,2440,1"));
        assert!(!csv.contains("7,"));
        assert!(csv.contains("# duration_s,2"));
    }

    #[test]
    fn empty_session_exports_headers_only() {
        let stats = SessionStats::new(5_000);
        let csv = stats.csv(5_000);
        assert!(csv.contains("# packets,0"));
        assert!(!csv.contains("BUSIEST"));
        assert!(stats.lines(5_000).len() >= 3);
    }
}

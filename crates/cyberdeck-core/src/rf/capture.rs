//! nRF24 packet capture: bounded log, payload formatting and address scan plans.
//!
//! The nRF24 gives a channel, a pipe index and up to 32 payload bytes. It has no
//! RSSI, so captures are labelled with channel and pipe only; the UI never shows a
//! fabricated signal value for RF packets.

use alloc::string::String;
use alloc::vec::Vec;

use crate::util::hex_join;

/// Maximum nRF24 payload size.
pub const PAYLOAD_MAX: usize = 32;

/// One received 2.4 GHz packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrfPacket {
    pub channel: u8,
    pub pipe: u8,
    pub len: u8,
    pub data: [u8; PAYLOAD_MAX],
    pub at_ms: u64,
}

impl NrfPacket {
    pub fn new(channel: u8, pipe: u8, payload: &[u8], at_ms: u64) -> Self {
        let mut data = [0u8; PAYLOAD_MAX];
        let len = payload.len().min(PAYLOAD_MAX);
        data[..len].copy_from_slice(&payload[..len]);
        Self {
            channel,
            pipe,
            len: len as u8,
            data,
            at_ms,
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// Frequency of the channel the packet arrived on.
    pub fn frequency_mhz(&self) -> u16 {
        super::nrf24::frequency_mhz(self.channel)
    }

    /// Hex rendering for the log view.
    pub fn hex(&self) -> String {
        hex_join(self.payload())
    }

    /// Browser line: `ch76 2476MHz p0 32B 001122...`.
    pub fn render_line(&self, width: usize) -> String {
        let head = alloc::format!(
            "ch{:03} {}MHz p{} {}B {}",
            self.channel,
            self.frequency_mhz(),
            self.pipe,
            self.len,
            super::super::util::hex_join(&self.payload()[..self.len.min(6) as usize])
        );
        crate::ui::ellipsize(&head, width)
    }

    /// Printable ASCII view (non-printable bytes become `.`).
    pub fn ascii(&self) -> String {
        crate::util::printable(self.payload())
    }
}

/// Bounded packet log.
#[derive(Debug)]
pub struct NrfLog<const N: usize> {
    entries: [Option<NrfPacket>; N],
    head: usize,
    len: usize,
    dropped: u32,
}

impl<const N: usize> Default for NrfLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NrfLog<N> {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, packet: NrfPacket) {
        if self.len == N {
            self.entries[self.head] = Some(packet);
            self.head = (self.head + 1) % N;
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let idx = (self.head + self.len) % N;
        self.entries[idx] = Some(packet);
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

    pub fn iter(&self) -> impl Iterator<Item = &NrfPacket> {
        (0..self.len).filter_map(move |i| self.entries[(self.head + i) % N].as_ref())
    }

    pub fn clear(&mut self) {
        self.entries = [const { None }; N];
        self.head = 0;
        self.len = 0;
        self.dropped = 0;
    }

    /// CSV export of the log.
    pub fn to_csv(&self) -> String {
        let mut out = String::from("channel,frequency_mhz,pipe,length,payload_hex,uptime_ms\n");
        for packet in self.iter() {
            out.push_str(&alloc::format!(
                "{},{},{},{},{},{}\n",
                packet.channel,
                packet.frequency_mhz(),
                packet.pipe,
                packet.len,
                packet.hex(),
                packet.at_ms
            ));
        }
        out
    }
}

/// Primary sniff addresses for 2.4 GHz input-device research (MouseJack).
///
/// These are the two addresses Bastille's research tooling sweeps first; an empty
/// capture is a normal result and is reported as such.
pub const MOUSEJACK_ADDRESSES: &[[u8; 5]] = &[[0xAA, 0xAA, 0xAA, 0xAA, 0xAA], [0x55; 5]];

/// Address width register value for the 5-byte research addresses.
pub const MOUSEJACK_ADDRESS_WIDTH: u8 = 0x03;

/// Channels scanned by the input-device sweep (nRF24 channel numbers).
pub fn sniff_channels() -> Vec<u8> {
    // 2403..=2481 MHz covers every non-overlapping Wi-Fi channel plus the gaps
    // where input devices commonly transmit.
    (3..=81).collect()
}

/// Whether a received length is plausible for a captured packet.
pub fn plausible_length(len: u8) -> bool {
    len > 0 && len <= PAYLOAD_MAX as u8
}

/// Summary of a capture session for the status line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NrfStats {
    pub packets: u32,
    pub bytes: u32,
    pub channels_hit: u8,
    pub dropped: u32,
    pub started_ms: u64,
}

impl NrfStats {
    pub fn record(&mut self, packet: &NrfPacket) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(u32::from(packet.len));
    }

    pub fn rate_per_second(&self, now_ms: u64) -> u32 {
        let elapsed = now_ms.saturating_sub(self.started_ms);
        if elapsed == 0 {
            return 0;
        }
        (u64::from(self.packets) * 1000 / elapsed) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_truncates_and_formats_payloads() {
        let payload = [0xABu8; 40];
        let packet = NrfPacket::new(76, 2, &payload, 100);
        assert_eq!(packet.len, 32);
        assert_eq!(packet.payload().len(), 32);
        assert_eq!(packet.frequency_mhz(), 2476);
        assert_eq!(packet.hex().split(':').count(), 32);
        assert!(packet.render_line(30).chars().count() <= 30);
        assert!(packet.render_line(200).contains("ch076 2476MHz p2 32B"));
    }

    #[test]
    fn empty_and_ascii_payloads() {
        let packet = NrfPacket::new(10, 0, b"HELLO\x00\x01", 5);
        assert_eq!(packet.ascii(), "HELLO..");
        let empty = NrfPacket::new(10, 0, &[], 5);
        assert_eq!(empty.len, 0);
        assert!(empty.payload().is_empty());
        assert_eq!(empty.hex(), "");
    }

    #[test]
    fn log_is_bounded_and_exports_csv() {
        let mut log: NrfLog<2> = NrfLog::new();
        for i in 0..4u8 {
            log.push(NrfPacket::new(i, 0, &[i, i], u64::from(i)));
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 2);
        let channels: Vec<u8> = log.iter().map(|p| p.channel).collect();
        assert_eq!(channels, alloc::vec![2, 3]);
        let csv = log.to_csv();
        assert!(csv.starts_with("channel,frequency_mhz,pipe,length,payload_hex,uptime_ms\n"));
        assert!(csv.contains("2,2402,0,2,02:02,2"));
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn stats_track_rate() {
        let mut stats = NrfStats {
            started_ms: 1_000,
            ..Default::default()
        };
        for _ in 0..10 {
            stats.record(&NrfPacket::new(1, 0, &[0u8; 8], 0));
        }
        assert_eq!(stats.packets, 10);
        assert_eq!(stats.bytes, 80);
        assert_eq!(stats.rate_per_second(2_000), 10);
        assert_eq!(stats.rate_per_second(1_000), 0);
    }

    #[test]
    fn scan_plans_are_sane() {
        let channels = sniff_channels();
        assert_eq!(channels.first(), Some(&3));
        assert_eq!(channels.last(), Some(&81));
        for channel in &channels {
            assert!(super::super::nrf24::channel_for_mhz(super::super::nrf24::frequency_mhz(*channel)).is_some());
        }
        assert_eq!(MOUSEJACK_ADDRESSES.len(), 2);
        assert_eq!(MOUSEJACK_ADDRESS_WIDTH, 0x03);
        assert!(plausible_length(1));
        assert!(plausible_length(32));
        assert!(!plausible_length(0));
        assert!(!plausible_length(33));
    }
}

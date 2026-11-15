//! PCAP (libpcap) writer with radiotap metadata — G02 capture format.
//!
//! Layout is the classic little-endian `0xa1b2c3d4` libpcap file with link type
//! `LINKTYPE_IEEE802_11_RADIOTAP` (127). Each record is preceded by a radiotap
//! header carrying TSFT, rate, channel and dBm signal, so captures open directly
//! in Wireshark/tshark and in the reference projects' tooling.
//!
//! Deliberate scope: classic PCAP only. PCAPNG (multi-interface blocks) is not
//! produced; the tracker lists it as not implemented rather than pretending.

use alloc::vec::Vec;

use crate::error::DeckError;
use crate::time::Timestamp;

/// `LINKTYPE_IEEE802_11_RADIOTAP`.
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
/// Default snapshot length (fits any 802.11 frame with padding).
pub const SNAPLEN_DEFAULT: u32 = 2048;
/// Hard per-file cap so a runaway capture cannot fill the card silently.
pub const MAX_CAPTURE_BYTES: u64 = 512 * 1024 * 1024;

/// Marker for a little-endian pcap file.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// 802.11 FCS present in the captured frame (radiotap flags bit 4).
pub const RADIOTAP_FLAG_FCS: u8 = 0x10;
/// 802.11 frame protected by WEP/WPA (radiotap flags bit 5).
pub const RADIOTAP_FLAG_WEP: u8 = 0x20;

/// Destination for pcap bytes (SD file, USB CDC stream or a test vector).
pub trait PcapSink {
    fn write_all(&mut self, data: &[u8]) -> Result<(), DeckError>;
    fn flush(&mut self) -> Result<(), DeckError> {
        Ok(())
    }
}

/// In-memory sink used by tests and by the "preview capture" path.
#[derive(Debug, Default)]
pub struct VecSink(pub Vec<u8>);

impl PcapSink for VecSink {
    fn write_all(&mut self, data: &[u8]) -> Result<(), DeckError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

/// Radiotap metadata for one 2.4 GHz frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Radiotap {
    /// Microseconds since the radio started (TSFT).
    pub tsft_us: u64,
    pub flags: u8,
    /// 500 kbps units (2 => 1 Mbps, 12 => 6 Mbps).
    pub rate_500kbps: u8,
    pub freq_mhz: u16,
    pub signal_dbm: i8,
}

impl Radiotap {
    /// Serialized size of the header produced by [`Self::encode`].
    pub const LEN: usize = 23;

    /// Present bitmap: TSFT, Flags, Rate, Channel, dBm antenna signal.
    const PRESENT: u32 = 0x0000_002F;

    /// Header for a typical 2.4 GHz management frame.
    pub fn for_mgmt(freq_mhz: u16, signal_dbm: i8) -> Self {
        Self {
            tsft_us: 0,
            flags: 0,
            rate_500kbps: 2,
            freq_mhz,
            signal_dbm,
        }
    }

    /// Serialize into a fixed buffer (no allocation on the capture path).
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = 0; // radiotap version
        out[1] = 0; // pad
        out[2..4].copy_from_slice(&(Self::LEN as u16).to_le_bytes());
        out[4..8].copy_from_slice(&Self::PRESENT.to_le_bytes());
        // TSFT at offset 8 (8-byte aligned).
        out[8..16].copy_from_slice(&self.tsft_us.to_le_bytes());
        out[16] = self.flags;
        out[17] = self.rate_500kbps;
        // Channel at offset 18 (2-byte aligned): frequency + 2 GHz CCK flags.
        out[18..20].copy_from_slice(&self.freq_mhz.to_le_bytes());
        out[20..22].copy_from_slice(&0x00A0u16.to_le_bytes());
        out[22] = self.signal_dbm as u8;
        out
    }
}

/// Counters reported in the session summary and the UI status line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PcapStats {
    pub records: u32,
    /// Bytes for records only (global header excluded).
    pub payload_bytes: u64,
    /// Frames captured with FCS stripped in whole.
    pub truncated: u32,
    /// Frames refused because the file size cap was reached.
    pub dropped: u32,
}

/// Streaming pcap writer.
#[derive(Debug)]
pub struct PcapWriter<S: PcapSink> {
    sink: S,
    snaplen: u32,
    fcs_included: bool,
    max_bytes: u64,
    written: u64,
    stats: PcapStats,
    finished: bool,
}

impl<S: PcapSink> PcapWriter<S> {
    /// Start a capture file: writes the 24-byte global header immediately so a
    /// truncated capture is still a parseable pcap.
    pub fn new(
        mut sink: S,
        snaplen: u32,
        fcs_included: bool,
        max_bytes: u64,
    ) -> Result<Self, DeckError> {
        let snaplen = snaplen.clamp(64, SNAPLEN_DEFAULT);
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
        header[6..8].copy_from_slice(&4u16.to_le_bytes()); // minor
        header[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
        header[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
        header[16..20].copy_from_slice(&snaplen.to_le_bytes());
        header[20..24].copy_from_slice(&LINKTYPE_IEEE802_11_RADIOTAP.to_le_bytes());
        sink.write_all(&header)?;
        Ok(Self {
            sink,
            snaplen,
            fcs_included,
            max_bytes,
            written: 24,
            stats: PcapStats::default(),
            finished: false,
        })
    }

    pub fn stats(&self) -> PcapStats {
        self.stats
    }

    pub fn written_bytes(&self) -> u64 {
        self.written
    }

    /// Append one captured frame.
    ///
    /// * `frame` is exactly what the radio delivered (FCS included when the driver
    ///   appends it; `fcs_included` mirrors that in the radiotap flags).
    /// * Over-long frames are truncated to the snapshot length and counted, which
    ///   is valid pcap behaviour and keeps the file readable.
    pub fn write_frame(
        &mut self,
        ts: Timestamp,
        frame: &[u8],
        radiotap: &Radiotap,
    ) -> Result<(), DeckError> {
        if self.finished {
            return Err(DeckError::Internal {
                reason: "pcap writer already closed",
            });
        }
        let rt = {
            let mut rt = *radiotap;
            if self.fcs_included {
                rt.flags |= RADIOTAP_FLAG_FCS;
            }
            rt
        };
        let encoded = rt.encode();
        let orig_len = encoded.len() + frame.len();
        let incl_frame = &frame[..frame.len().min(self.snaplen as usize)];
        let incl_len = encoded.len() + incl_frame.len();
        if orig_len > incl_len {
            self.stats.truncated = self.stats.truncated.saturating_add(1);
        }
        let record_bytes = 16 + incl_len as u64;
        if self.written + record_bytes > self.max_bytes {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Err(DeckError::Storage {
                reason: "capture size limit reached",
            });
        }

        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&(ts.secs as u32).to_le_bytes());
        header[4..8].copy_from_slice(&ts.micros.to_le_bytes());
        header[8..12].copy_from_slice(&(incl_len as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(orig_len as u32).to_le_bytes());

        self.sink.write_all(&header)?;
        self.sink.write_all(&encoded)?;
        self.sink.write_all(incl_frame)?;

        self.written += record_bytes;
        self.stats.records = self.stats.records.saturating_add(1);
        self.stats.payload_bytes += incl_len as u64;
        Ok(())
    }

    /// Append a frame whose radiotap metadata should be derived from the channel
    /// and RSSI reported by the sniffer.
    pub fn write_frame_on_channel(
        &mut self,
        ts: Timestamp,
        frame: &[u8],
        channel_mhz: u16,
        signal_dbm: i8,
    ) -> Result<(), DeckError> {
        let mut radiotap = Radiotap::for_mgmt(channel_mhz, signal_dbm);
        radiotap.tsft_us = ts.to_micros();
        self.write_frame(ts, frame, &radiotap)
    }

    /// Flush and return the sink so the caller can close the file.
    pub fn finish(mut self) -> Result<(S, PcapStats), DeckError> {
        self.finished = true;
        self.sink.flush()?;
        Ok((self.sink, self.stats))
    }
}

/// Strip a trailing 4-byte FCS when the radio reports one.
pub fn strip_fcs(frame: &[u8]) -> &[u8] {
    if frame.len() >= 4 {
        &frame[..frame.len() - 4]
    } else {
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser_global_header(data: &[u8]) -> (u32, u16, u16, u32, u32) {
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let major = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let minor = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let snaplen = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let linktype = u32::from_le_bytes(data[20..24].try_into().unwrap());
        (magic, major, minor, snaplen, linktype)
    }

    #[test]
    fn global_header_is_valid_libpcap() {
        let writer = PcapWriter::new(VecSink::default(), SNAPLEN_DEFAULT, false, 1 << 20).unwrap();
        let (sink, stats) = writer.finish().unwrap();
        let (magic, major, minor, snaplen, linktype) = parser_global_header(&sink.0);
        assert_eq!(magic, PCAP_MAGIC);
        assert_eq!((major, minor), (2, 4));
        assert_eq!(snaplen, SNAPLEN_DEFAULT);
        assert_eq!(linktype, LINKTYPE_IEEE802_11_RADIOTAP);
        assert_eq!(stats.records, 0);
        assert_eq!(sink.0.len(), 24);
    }

    #[test]
    fn radiotap_header_fields_are_aligned_and_correct() {
        let mut rt = Radiotap::for_mgmt(2437, -42);
        rt.tsft_us = 0x1122_3344_5566_7788;
        rt.flags = RADIOTAP_FLAG_FCS;
        let bytes = rt.encode();
        assert_eq!(bytes[0], 0);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 23);
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            Radiotap::PRESENT
        );
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        // Flags, rate, channel, signal
        assert_eq!(bytes[16], RADIOTAP_FLAG_FCS);
        assert_eq!(bytes[17], 2);
        assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 2437);
        assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), 0x00A0);
        assert_eq!(bytes[22] as i8, -42);
    }

    #[test]
    fn records_carry_timestamps_lengths_and_radiotap() {
        let mut writer = PcapWriter::new(VecSink::default(), SNAPLEN_DEFAULT, true, 1 << 20).unwrap();
        // Minimal 26-byte deauthentication frame.
        let frame = [
            0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x10, 0x00, 0x07, 0x00,
        ];
        writer
            .write_frame_on_channel(Timestamp::new(1_700_000_000, 123_456), &frame, 2412, -55)
            .unwrap();
        let (sink, stats) = writer.finish().unwrap();
        assert_eq!(stats.records, 1);
        let record = &sink.0[24..];
        assert_eq!(u32::from_le_bytes(record[0..4].try_into().unwrap()), 1_700_000_000);
        assert_eq!(u32::from_le_bytes(record[4..8].try_into().unwrap()), 123_456);
        let incl = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
        let orig = u32::from_le_bytes(record[12..16].try_into().unwrap()) as usize;
        assert_eq!(incl, Radiotap::LEN + frame.len());
        assert_eq!(orig, incl);
        // Radiotap flags advertise the FCS that the caller said is included.
        assert_eq!(record[16 + 16], RADIOTAP_FLAG_FCS);
        // Frame follows the 23-byte radiotap header verbatim.
        assert_eq!(&record[16 + Radiotap::LEN..16 + incl], &frame[..]);
        assert_eq!(u32::from_le_bytes(record[16 + 2..16 + 4].try_into().unwrap()), 23);
    }

    #[test]
    fn oversize_frames_truncate_without_corrupting_the_file() {
        let mut writer = PcapWriter::new(VecSink::default(), 100, false, 1 << 20).unwrap();
        let frame = [0xABu8; 400];
        writer
            .write_frame_on_channel(Timestamp::new(1, 0), &frame, 2412, -30)
            .unwrap();
        let (sink, stats) = writer.finish().unwrap();
        assert_eq!(stats.truncated, 1);
        let record = &sink.0[24..];
        let incl = u32::from_le_bytes(record[8..12].try_into().unwrap());
        let orig = u32::from_le_bytes(record[12..16].try_into().unwrap());
        assert_eq!(incl as usize, 100 + Radiotap::LEN);
        assert_eq!(orig as usize, 400 + Radiotap::LEN);
        assert_eq!(record.len(), 16 + incl as usize);
    }

    #[test]
    fn size_limit_stops_the_capture_with_a_storage_error() {
        let mut writer = PcapWriter::new(VecSink::default(), SNAPLEN_DEFAULT, false, 128).unwrap();
        let frame = [0u8; 60];
        writer
            .write_frame_on_channel(Timestamp::new(1, 0), &frame, 2412, -30)
            .unwrap();
        let err = writer
            .write_frame_on_channel(Timestamp::new(1, 1), &frame, 2412, -30)
            .unwrap_err();
        assert!(matches!(err, DeckError::Storage { .. }));
        assert_eq!(writer.stats().dropped, 1);
    }

    #[test]
    fn fcs_stripping_is_safe_for_short_frames() {
        assert_eq!(strip_fcs(&[1, 2, 3, 4, 5]), &[1]);
        assert_eq!(strip_fcs(&[1, 2]), &[1, 2]);
    }
}

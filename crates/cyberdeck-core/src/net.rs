//! Link-layer primitives shared by the Wi-Fi, packet, BLE and RF groups:
//! MAC addresses and the 2.4 GHz channel plan.

use core::fmt;

use crate::error::DeckError;
use crate::util::hex_val_checked;

/// IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Parse `AA:BB:CC:DD:EE:FF` (also accepts `-` separators and bare hex).
    pub fn parse(text: &str) -> Result<Self, DeckError> {
        let mut nibbles = [0u8; 12];
        let mut count = 0;
        for byte in text.bytes() {
            if byte == b':' || byte == b'-' || byte == b'.' {
                continue;
            }
            let value = hex_val_checked(byte).ok_or(DeckError::InvalidInput {
                reason: "MAC address contains a non-hex character",
            })?;
            if count >= 12 {
                return Err(DeckError::InvalidInput {
                    reason: "MAC address is longer than 6 octets",
                });
            }
            nibbles[count] = value;
            count += 1;
        }
        if count != 12 {
            return Err(DeckError::InvalidInput {
                reason: "MAC address must contain 12 hex digits",
            });
        }
        let mut out = [0u8; 6];
        for i in 0..6 {
            out[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
        }
        Ok(Self(out))
    }

    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// Group bit: multicast/broadcast destination.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Locally administered bit (randomised MACs set this).
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Vendor OUI (first three octets).
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// True when this looks like a randomised client address.
    pub fn is_randomised(&self) -> bool {
        self.is_locally_administered() && !self.is_multicast()
    }

    /// ASCII rendering without a heap allocation (for tiny embedded buffers).
    pub fn write_into(&self, out: &mut [u8; 17]) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (i, byte) in self.0.iter().enumerate() {
            out[i * 3] = HEX[(byte >> 4) as usize];
            out[i * 3 + 1] = HEX[(byte & 0x0F) as usize];
            if i < 5 {
                out[i * 3 + 2] = b':';
            }
        }
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// 2.4 GHz Wi-Fi channel (1..=14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Channel(u8);

impl Channel {
    /// Construct from a channel number.
    pub fn new(number: u8) -> Result<Self, DeckError> {
        if (1..=14).contains(&number) {
            Ok(Self(number))
        } else {
            Err(DeckError::InvalidInput {
                reason: "Wi-Fi channel must be 1..14",
            })
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    /// Centre frequency in MHz.
    pub const fn frequency_mhz(self) -> u16 {
        if self.0 == 14 {
            2484
        } else {
            2407 + 5 * self.0 as u16
        }
    }

    /// Inverse mapping used when correlating radiotap metadata.
    pub fn from_frequency_mhz(freq: u16) -> Option<Self> {
        if freq == 2484 {
            return Some(Self(14));
        }
        if !(2412..=2472).contains(&freq) {
            return None;
        }
        let ch = (freq - 2407) / 5;
        if (1..=13).contains(&ch) {
            Some(Self(ch as u8))
        } else {
            None
        }
    }

    /// Channel reported by the ESP32 promiscuous metadata.
    pub fn from_primary(value: u8) -> Option<Self> {
        if (1..=14).contains(&value) {
            Some(Self(value))
        } else {
            None
        }
    }
}

/// The channels captured by a full 2.4 GHz hop sweep.
pub const PLAN_2GHZ: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Build a hop plan starting at `first`, optionally including channel 14.
pub fn hop_plan(first: u8, include_14: bool) -> alloc::vec::Vec<Channel> {
    let start = if (1..=13).contains(&first) { first } else { 1 };
    let mut plan = alloc::vec::Vec::with_capacity(14);
    for ch in start..=13 {
        plan.push(Channel(ch));
    }
    for ch in 1..start {
        plan.push(Channel(ch));
    }
    if include_14 {
        plan.push(Channel(14));
    }
    plan
}

/// Neighbour overlap penalty used to rank channels for captures.
pub fn overlapping_channels(channel: Channel) -> &'static [u8] {
    match channel.get() {
        1 => &[1, 2, 3, 4, 5],
        2 => &[1, 2, 3, 4, 5, 6],
        3 => &[1, 2, 3, 4, 5, 6, 7],
        4 => &[2, 3, 4, 5, 6, 7, 8],
        5 => &[3, 4, 5, 6, 7, 8, 9],
        6 => &[4, 5, 6, 7, 8, 9, 10],
        7 => &[5, 6, 7, 8, 9, 10, 11],
        8 => &[6, 7, 8, 9, 10, 11, 12],
        9 => &[7, 8, 9, 10, 11, 12, 13],
        10 => &[8, 9, 10, 11, 12, 13],
        11 => &[9, 10, 11, 12, 13],
        12 => &[10, 11, 12, 13],
        13 => &[11, 12, 13],
        _ => &[14],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_display_and_parse() {
        let mac = MacAddr::parse("aa:bb:cc:00:11:22").unwrap();
        assert_eq!(mac.to_string(), "AA:BB:CC:00:11:22");
        assert_eq!(MacAddr::parse("AABBCC001122").unwrap(), mac);
        assert_eq!(MacAddr::parse("aa-bb-cc-00-11-22").unwrap(), mac);
        assert!(MacAddr::parse("aa:bb").is_err());
        assert!(MacAddr::parse("zz:bb:cc:00:11:22").is_err());
    }

    #[test]
    fn mac_classification() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::ZERO.is_multicast());
        // 0x02 in the first octet = locally administered (randomised client).
        assert!(MacAddr::new([0x02, 0, 0, 0, 0, 1]).is_randomised());
        assert!(!MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_randomised());
    }

    #[test]
    fn write_into_matches_display() {
        let mac = MacAddr::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let mut buf = [0u8; 17];
        mac.write_into(&mut buf);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), mac.to_string());
    }

    #[test]
    fn channel_frequencies_round_trip() {
        for ch in 1..=13u8 {
            let channel = Channel::new(ch).unwrap();
            assert_eq!(channel.frequency_mhz(), 2407 + 5 * ch as u16);
            assert_eq!(Channel::from_frequency_mhz(channel.frequency_mhz()), Some(channel));
        }
        assert_eq!(Channel::new(14).unwrap().frequency_mhz(), 2484);
        assert_eq!(Channel::from_frequency_mhz(2484).unwrap().get(), 14);
        assert!(Channel::new(0).is_err());
        assert!(Channel::new(15).is_err());
    }

    #[test]
    fn hop_plan_starts_at_requested_channel() {
        let plan = hop_plan(6, false);
        assert_eq!(plan.first().unwrap().get(), 6);
        assert_eq!(plan.len(), 13);
        assert_eq!(plan.last().unwrap().get(), 5);
        assert_eq!(hop_plan(1, true).len(), 14);
    }
}

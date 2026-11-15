//! BLE advertisement test payload generator (G03 "advertisement experiments").
//!
//! The payload tables are ported from the reference firmware's advertisement test
//! tools: Bruce `src/modules/ble/ble_spam.cpp` (Samsung Galaxy Buds/Watch byte
//! layouts are copied verbatim, including the truncated trailing record the real
//! Buds advertise) and the Apple Continuity "nearby action" frames used by
//! Bruce/GhostESP. Continuity/Fast Pair/Swift Pair are *advertisement formats*;
//! whether a given phone shows a popup is a property of the phone and is recorded
//! on the G03 hardware-acceptance checklist, not claimed here.
//!
//! These tools transmit advertisements only; they never pair, connect or read data.

use super::ad::AdvBuilder;

/// Advertisement campaign selector shown in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamCampaign {
    /// Apple Continuity nearby-action / AirPods frames.
    Apple,
    /// Samsung Galaxy Buds frames (31-byte payload).
    SamsungBuds,
    /// Samsung Galaxy Watch frames.
    SamsungWatch,
    /// Google Fast Pair service data.
    FastPair,
    /// Microsoft Swift Pair manufacturer data.
    SwiftPair,
    /// Plain iBeacon frames for beacon-scanner testing.
    IBeacon,
}

impl SpamCampaign {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Apple => "Apple Continuity",
            Self::SamsungBuds => "Galaxy Buds",
            Self::SamsungWatch => "Galaxy Watch",
            Self::FastPair => "Fast Pair",
            Self::SwiftPair => "Swift Pair",
            Self::IBeacon => "iBeacon",
        }
    }

    pub const fn all() -> &'static [SpamCampaign] {
        &[
            Self::Apple,
            Self::SamsungBuds,
            Self::SamsungWatch,
            Self::FastPair,
            Self::SwiftPair,
            Self::IBeacon,
        ]
    }

    pub fn from_index(index: usize) -> Option<Self> {
        Self::all().get(index).copied()
    }

    /// Advertisement data can be sent without a connection.
    pub const fn requires_connection(self) -> bool {
        false
    }
}

/// Apple Continuity manufacturer payloads (company id prepended by the builder).
const APPLE_PAYLOADS: &[&[u8]] = &[
    // Nearby action: "set up new iPhone" style prompt.
    &[0x0F, 0x05, 0xC1, 0x01, 0x60, 0x4C, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00],
    // Nearby action: accessory setup prompt.
    &[0x0F, 0x05, 0xC1, 0x07, 0x60, 0x4C, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00],
    // AirPods proximity frame.
    &[
        0x07, 0x19, 0x07, 0x0E, 0x20, 0x75, 0xAA, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12,
    ],
    // Nearby info frame.
    &[0x10, 0x05, 0x41, 0x00, 0x60, 0x4C, 0x95, 0x00],
];

/// Galaxy Buds model identifiers used by the reference table.
const SAMSUNG_BUDS_MODELS: &[u32] = &[0xEE12_1A4B, 0xEE12_1A4C, 0xEE12_1A4D, 0xEE12_1A4E];
/// Galaxy Watch model bytes.
const SAMSUNG_WATCH_MODELS: &[u8] = &[0x1A, 0x1B, 0x1C, 0x1D];
/// Example Fast Pair model identifiers (configurable for lab use).
const FASTPAIR_MODELS: &[[u8; 3]] = &[
    [0x00, 0x00, 0xB7],
    [0x00, 0x00, 0x47],
    [0x00, 0x0A, 0x0E],
    [0x00, 0x00, 0x5E],
];
/// Swift Pair display names.
const SWIFT_PAIR_NAMES: &[&[u8]] = &[
    b"CyberDeck Mouse",
    b"BT Keyboard",
    b"Wireless Headset",
    b"Surface Pen",
];

/// Build the Samsung Galaxy Buds advertisement exactly as the reference firmware
/// emits it (including the truncated second record real Buds send).
fn samsung_buds_payload(model: u32) -> [u8; 31] {
    let mut data = [0u8; 31];
    let mut i = 0;
    let mut push = |value: u8| {
        if i < data.len() {
            data[i] = value;
            i += 1;
        }
    };
    push(27);
    push(0xFF);
    push(0x75);
    push(0x00);
    push(0x42);
    push(0x09);
    push(0x81);
    push(0x02);
    push(0x14);
    push(0x15);
    push(0x03);
    push(0x21);
    push(0x01);
    push(0x09);
    push(((model >> 16) & 0xFF) as u8);
    push(((model >> 8) & 0xFF) as u8);
    push(0x01);
    push((model & 0xFF) as u8);
    push(0x06);
    push(0x3C);
    push(0x94);
    push(0x8E);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0xC7);
    push(0x00);
    // Trailing truncated record (claims 16 bytes, carries 2).
    push(0x10);
    push(0xFF);
    push(0x75);
    data
}

/// Galaxy Watch advertisement (preceded by a Flags element).
fn samsung_watch_payload(model: u8) -> [u8; 15] {
    [
        0x0E, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43,
        model,
    ]
}

/// Deterministic rotator producing fresh advertising payloads for one campaign.
#[derive(Debug)]
pub struct SpamRotator {
    campaign: SpamCampaign,
    rng: super::super::wifi::attack::Rng,
    frames: u32,
    cursor: usize,
}

impl SpamRotator {
    pub fn new(campaign: SpamCampaign, seed: u64) -> Self {
        Self {
            campaign,
            rng: super::super::wifi::attack::Rng::new(seed),
            frames: 0,
            cursor: 0,
        }
    }

    pub fn campaign(&self) -> SpamCampaign {
        self.campaign
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// Fill `out` with the next advertising payload.
    ///
    /// Returns `false` only if the payload does not fit the 31-byte legacy limit,
    /// which cannot happen for the built-in tables (asserted by tests).
    pub fn next_payload(&mut self, out: &mut AdvBuilder) -> bool {
        let ok = match self.campaign {
            SpamCampaign::Apple => {
                let payload = APPLE_PAYLOADS[self.cursor % APPLE_PAYLOADS.len()];
                self.cursor = self.cursor.wrapping_add(1);
                out.flags(0x06) && out.manufacturer(super::vendor::COMPANY_APPLE, payload)
            }
            SpamCampaign::SamsungBuds => {
                let model = SAMSUNG_BUDS_MODELS[self.rng.below(SAMSUNG_BUDS_MODELS.len())];
                out.push_raw(&samsung_buds_payload(model))
            }
            SpamCampaign::SamsungWatch => {
                let model = SAMSUNG_WATCH_MODELS[self.rng.below(SAMSUNG_WATCH_MODELS.len())];
                out.push_raw(&samsung_watch_payload(model)) && out.flags(0x06)
            }
            SpamCampaign::FastPair => {
                let model = FASTPAIR_MODELS[self.rng.below(FASTPAIR_MODELS.len())];
                out.flags(0x06)
                    && out.service_data16(
                        super::ad::ServiceUuid::FAST_PAIR.0,
                        &[0x00, model[0], model[1], model[2]],
                    )
            }
            SpamCampaign::SwiftPair => {
                let name = SWIFT_PAIR_NAMES[self.rng.below(SWIFT_PAIR_NAMES.len())];
                let mut payload = alloc::vec![0x03u8, 0x00, 0x80];
                payload.extend_from_slice(name);
                out.flags(0x06)
                    && out.manufacturer(super::vendor::COMPANY_MICROSOFT, &payload)
            }
            SpamCampaign::IBeacon => {
                let mut payload = alloc::vec![0x02u8, 0x15];
                payload.extend_from_slice(&[0xE2, 0xC5, 0x6D, 0xB5, 0xDF, 0xFB, 0x48, 0xD2]);
                payload.extend_from_slice(&[0xB0, 0x60, 0xD0, 0xF5, 0xA7, 0x10, 0x96, 0xE0]);
                payload.extend_from_slice(&[0x00, 0x01]); // major
                payload.extend_from_slice(&[0x00, 0x02]); // minor
                payload.push(0xC5); // measured power
                out.flags(0x06) && out.manufacturer(super::vendor::COMPANY_APPLE, &payload)
            }
        };
        if ok {
            self.frames = self.frames.saturating_add(1);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::ad::{AdvReport, BleAddress};

    fn generate(campaign: SpamCampaign, count: usize) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut rotator = SpamRotator::new(campaign, 0xDEAD_BEEF);
        let mut out = alloc::vec::Vec::new();
        for _ in 0..count {
            let mut builder = AdvBuilder::new();
            assert!(rotator.next_payload(&mut builder), "{campaign:?} payload fits");
            out.push(builder.as_slice().to_vec());
        }
        out
    }

    #[test]
    fn every_campaign_produces_parseable_advertising_data() {
        for campaign in SpamCampaign::all() {
            let payloads = generate(*campaign, 6);
            for payload in payloads {
                assert!(!payload.is_empty());
                assert!(payload.len() <= 31);
                let report = AdvReport::parse(
                    BleAddress::new([0x41; 6]),
                    -40,
                    &payload,
                    false,
                    0,
                );
                let matched = crate::ble::vendor::classify(&report);
                assert_ne!(
                    matched.kind,
                    crate::ble::vendor::TrackerKind::Unknown,
                    "{campaign:?} should be classifiable"
                );
            }
        }
    }

    #[test]
    fn samsung_buds_payload_matches_reference_bytes() {
        let payload = samsung_buds_payload(0xEE12_1A4B);
        assert_eq!(payload.len(), 31);
        assert_eq!(payload[0], 27);
        assert_eq!(payload[1], 0xFF);
        assert_eq!(payload[2], 0x75);
        assert_eq!(payload[3], 0x00);
        assert_eq!(payload[13], 0x09);
        // Model bytes are big-to-small, matching the reference implementation.
        assert_eq!(payload[14], 0x12);
        assert_eq!(payload[15], 0x1A);
        assert_eq!(payload[16], 0x01);
        assert_eq!(payload[17], 0x4B);
        // Trailing truncated record preserved for scanner recognition.
        assert_eq!(&payload[28..], &[0x10, 0xFF, 0x75]);
    }

    #[test]
    fn samsung_watch_payload_has_flags_and_manufacturer_data() {
        let payload = samsung_watch_payload(0x1A);
        assert_eq!(payload.len(), 15);
        assert_eq!(payload[0], 0x0E);
        assert_eq!(&payload[1..4], &[0xFF, 0x75, 0x00]);
        assert_eq!(payload[14], 0x1A);
    }

    #[test]
    fn apple_campaign_rotates_payloads() {
        let payloads = generate(SpamCampaign::Apple, 6);
        let unique: alloc::collections::BTreeSet<&alloc::vec::Vec<u8>> = payloads.iter().collect();
        assert!(unique.len() >= 3, "Apple campaign rotates through the table");
        for payload in &payloads {
            // Flags AD (3 bytes), then manufacturer AD: length, 0xFF, company 0x004C.
            assert_eq!(&payload[0..3], &[0x02, 0x01, 0x06]);
            assert_eq!(payload[4], 0xFF);
            assert_eq!(&payload[5..7], &[0x4C, 0x00]);
        }
    }

    #[test]
    fn swift_pair_uses_microsoft_company_id_and_a_name() {
        let payloads = generate(SpamCampaign::SwiftPair, 8);
        for payload in payloads {
            assert!(payload.len() <= 31);
            let report = AdvReport::parse(BleAddress::new([1; 6]), -30, &payload, false, 0);
            assert_eq!(report.company_id(), Some(0x0006));
            assert!(report.company_payload()[..3] == [0x03, 0x00, 0x80]);
        }
    }

    #[test]
    fn ibeacon_frame_has_apple_proximity_prefix() {
        let payloads = generate(SpamCampaign::IBeacon, 1);
        let report = AdvReport::parse(BleAddress::new([1; 6]), -30, &payloads[0], false, 0);
        assert_eq!(report.company_id(), Some(0x004C));
        assert_eq!(report.company_payload()[..2], [0x02, 0x15]);
        assert_eq!(report.company_payload().len(), 23);
    }

    #[test]
    fn rotator_counters_and_campaign_accessors() {
        let mut rotator = SpamRotator::new(SpamCampaign::FastPair, 1);
        assert_eq!(rotator.campaign(), SpamCampaign::FastPair);
        assert_eq!(rotator.frames(), 0);
        let mut builder = AdvBuilder::new();
        assert!(rotator.next_payload(&mut builder));
        assert_eq!(rotator.frames(), 1);
        assert!(!SpamCampaign::FastPair.requires_connection());
        assert_eq!(SpamCampaign::from_index(0), Some(SpamCampaign::Apple));
        assert_eq!(SpamCampaign::from_index(99), None);
    }
}

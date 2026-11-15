//! Vendor, tracker and Remote-ID classification.
//!
//! Everything here is derived from the advertisement payload itself — no guessing
//! from RSSI or address alone. Where the payload is ambiguous the result says
//! `Unknown` instead of inventing a model, per the plan's honest-confidence rule.

use alloc::string::String;
use alloc::vec::Vec;

use super::ad::{AdvReport, ServiceUuid};

/// Bluetooth SIG company identifiers used by the classification rules.
pub const COMPANY_APPLE: u16 = 0x004C;
pub const COMPANY_SAMSUNG: u16 = 0x0075;
pub const COMPANY_MICROSOFT: u16 = 0x0006;
pub const COMPANY_GOOGLE: u16 = 0x00E0;

/// Tracker categories the detection screen can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerKind {
    /// Apple Find My network accessory (AirTag and compatible).
    AppleFindMy,
    /// Apple device advertising Continuity (iPhone/Mac/iPad).
    AppleDevice,
    /// Samsung SmartTag / Galaxy family.
    SamsungSmartTag,
    /// Tile-style tracker (service-data based).
    Tile,
    /// Google Fast Pair accessory.
    FastPair,
    /// Microsoft Swift Pair peripheral.
    SwiftPair,
    /// Remote ID broadcast (drone/unmanned aircraft).
    RemoteIdBroadcast,
    /// Recognised vendor, unclassified product family.
    Other,
    /// No vendor signature recognised.
    Unknown,
}

impl TrackerKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AppleFindMy => "Find My",
            Self::AppleDevice => "Apple device",
            Self::SamsungSmartTag => "SmartTag",
            Self::Tile => "Tile",
            Self::FastPair => "Fast Pair",
            Self::SwiftPair => "Swift Pair",
            Self::RemoteIdBroadcast => "Remote ID",
            Self::Other => "Vendor",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this category should raise a "tracker nearby" alert.
    pub const fn is_tracker(self) -> bool {
        matches!(self, Self::AppleFindMy | Self::SamsungSmartTag | Self::Tile)
    }
}

/// Classification result for one advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorMatch {
    pub kind: TrackerKind,
    pub vendor: &'static str,
    /// Product/type detail decoded from the payload when available.
    pub detail: String,
}

impl VendorMatch {
    fn unknown() -> Self {
        Self {
            kind: TrackerKind::Unknown,
            vendor: "Unknown",
            detail: String::new(),
        }
    }
}

/// Apple Continuity message types carried in manufacturer data byte 0.
fn apple_continuity(type_byte: u8) -> (&'static str, TrackerKind) {
    match type_byte {
        0x01 => ("iBeacon", TrackerKind::Other),
        0x02 => ("iBeacon", TrackerKind::Other),
        0x05 => ("AirDrop", TrackerKind::AppleDevice),
        0x07 => ("AirPods", TrackerKind::Other),
        0x09 => ("AirPlay target", TrackerKind::AppleDevice),
        0x0A => ("AirPlay source", TrackerKind::AppleDevice),
        0x0C => ("Handoff", TrackerKind::AppleDevice),
        0x0D => ("Tethering target", TrackerKind::AppleDevice),
        0x0E => ("Tethering source", TrackerKind::AppleDevice),
        0x0F => ("Nearby action", TrackerKind::AppleDevice),
        0x10 => ("Nearby info", TrackerKind::AppleDevice),
        0x12 => ("Find My accessory", TrackerKind::AppleFindMy),
        _ => ("Continuity", TrackerKind::AppleDevice),
    }
}

/// Classify an advertisement by its vendor signatures.
pub fn classify(report: &AdvReport) -> VendorMatch {
    if let Some(company) = report.company_id() {
        let payload = report.company_payload();
        match company {
            COMPANY_APPLE => {
                let (detail, kind) = apple_continuity(payload.first().copied().unwrap_or(0xFF));
                return VendorMatch {
                    kind,
                    vendor: "Apple",
                    detail: String::from(detail),
                };
            }
            COMPANY_SAMSUNG => {
                let (detail, kind) = match payload.first().copied() {
                    Some(0x42) => ("Galaxy Buds", TrackerKind::Other),
                    Some(0x01) => ("SmartTag / Galaxy Watch", TrackerKind::SamsungSmartTag),
                    _ => ("Samsung accessory", TrackerKind::Other),
                };
                return VendorMatch {
                    kind,
                    vendor: "Samsung",
                    detail: String::from(detail),
                };
            }
            COMPANY_MICROSOFT => {
                return VendorMatch {
                    kind: TrackerKind::SwiftPair,
                    vendor: "Microsoft",
                    detail: String::from("Swift Pair peripheral"),
                };
            }
            COMPANY_GOOGLE => {
                return VendorMatch {
                    kind: TrackerKind::FastPair,
                    vendor: "Google",
                    detail: String::from("Fast Pair advertiser"),
                };
            }
            _ => {
                return VendorMatch {
                    kind: TrackerKind::Other,
                    vendor: company_name(company),
                    detail: alloc::format!("Company 0x{company:04X}"),
                };
            }
        }
    }

    if let Some(uuid) = report.service_data_uuid() {
        // Match on the raw UUID value: associated-constant field access is not a
        // valid pattern, and duplicating the numbers in `match` keeps this readable.
        match uuid {
            0xFE2C => {
                return VendorMatch {
                    kind: TrackerKind::FastPair,
                    vendor: "Google",
                    detail: String::from("Fast Pair service data"),
                };
            }
            0xFFFA => {
                return VendorMatch {
                    kind: TrackerKind::RemoteIdBroadcast,
                    vendor: "ASTM",
                    detail: String::from("Remote ID service data"),
                };
            }
            0xFEAA => {
                return VendorMatch {
                    kind: TrackerKind::Other,
                    vendor: "Google",
                    detail: String::from("Eddystone beacon"),
                };
            }
            0xFE9F => {
                return VendorMatch {
                    kind: TrackerKind::FastPair,
                    vendor: "Google",
                    detail: String::from("Nearby service"),
                };
            }
            0xFEF5 => {
                return VendorMatch {
                    kind: TrackerKind::Tile,
                    vendor: "Tile",
                    detail: String::from("Tile tracker"),
                };
            }
            _ => {}
        }
    }

    VendorMatch::unknown()
}

/// Names for the company identifiers the UI is likely to meet.
pub fn company_name(company: u16) -> &'static str {
    match company {
        0x0006 => "Microsoft",
        0x004C => "Apple",
        0x0075 => "Samsung",
        0x00E0 => "Google",
        0x0059 => "Nordic",
        0x000F => "Broadcom",
        0x0087 => "Garmin",
        0x0157 => "Anhui Huami",
        0x027D => "Huawei",
        0x038F => "Xiaomi",
        0x0499 => "Ruuvi",
        _ => "Vendor",
    }
}

/// Remote ID data parsed from the ASTM BLE service-data transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteId {
    pub protocol_version: u8,
    /// ASTM UA type label (`Helicopter/multirotor`, `Aeroplane`, ...).
    pub ua_type: &'static str,
    /// ID type label (`Serial (CTA-2063)`, `CAA registration`, ...).
    pub id_type: &'static str,
    /// The 20-byte UAS ID as printable text.
    pub uas_id: String,
}

/// ASTM F3411 UA type names.
fn ua_type_label(value: u8) -> &'static str {
    match value {
        0 => "Undeclared",
        1 => "Aeroplane",
        2 => "Helicopter/multirotor",
        3 => "Gyroplane",
        4 => "Hybrid lift",
        5 => "Ornithopter",
        6 => "Glider",
        7 => "Kite",
        8 => "Free balloon",
        9 => "Captive balloon",
        10 => "Airship",
        11 => "Free-fall parachute",
        12 => "Rocket",
        13 => "Tethered balloon",
        14 => "Ground obstacle",
        _ => "Other",
    }
}

fn id_type_label(value: u8) -> &'static str {
    match value {
        0 => "None",
        1 => "Serial (CTA-2063)",
        2 => "CAA registration",
        3 => "UTM UUID",
        4 => "Specific session ID",
        _ => "Reserved",
    }
}

/// Parse a Basic ID message from the Remote ID BLE service data.
///
/// Transport layout (ASTM F3411 over Bluetooth 4 legacy advertising):
/// UUID(2) | application code 0x0D | message counter(1) | 25-byte message.
/// The message itself is `(type << 4) | protocol_version` followed by the body.
pub fn parse_remote_id(service_data: &[u8]) -> Option<RemoteId> {
    if service_data.len() < 4 + 25 {
        return None;
    }
    if u16::from_le_bytes([service_data[0], service_data[1]]) != ServiceUuid::REMOTE_ID.0 {
        return None;
    }
    if service_data[2] != 0x0D {
        return None;
    }
    let message = &service_data[4..4 + 25];
    let message_type = message[0] >> 4;
    let protocol_version = message[0] & 0x0F;
    if message_type != 0 {
        // Only Basic ID is decoded; other message types are surfaced as detected
        // but not interpreted, never filled with invented values.
        return None;
    }
    // Byte 1 packs ID type in the high nibble and UA type in the low nibble.
    let id_type = message[1] >> 4;
    let ua_type = message[1] & 0x0F;
    let id_bytes: Vec<u8> = message[2..22]
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .collect();
    Some(RemoteId {
        protocol_version,
        ua_type: ua_type_label(ua_type),
        id_type: id_type_label(id_type),
        uas_id: crate::util::printable(&id_bytes),
    })
}

/// Remote ID message type of a service-data payload (0 = Basic ID, 1 = Location...).
pub fn remote_id_message_type(service_data: &[u8]) -> Option<u8> {
    if service_data.len() < 4 + 25
        || u16::from_le_bytes([service_data[0], service_data[1]]) != ServiceUuid::REMOTE_ID.0
        || service_data[2] != 0x0D
    {
        return None;
    }
    Some(service_data[4] >> 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::ad::{AdvBuilder, AdvReport, BleAddress};

    fn report_from(build: impl FnOnce(&mut AdvBuilder)) -> AdvReport {
        let mut builder = AdvBuilder::new();
        builder.flags(0x06);
        build(&mut builder);
        AdvReport::parse(
            BleAddress::new([0x11; 6]),
            -55,
            builder.as_slice(),
            false,
            0,
        )
    }

    #[test]
    fn detects_apple_find_my() {
        let report = report_from(|b| {
            b.manufacturer(COMPANY_APPLE, &[0x12, 0x19, 0x10, 0x00, 0x5A]);
        });
        let matched = classify(&report);
        assert_eq!(matched.vendor, "Apple");
        assert_eq!(matched.kind, TrackerKind::AppleFindMy);
        assert!(matched.kind.is_tracker());
    }

    #[test]
    fn detects_apple_nearby_and_airpods() {
        let nearby = report_from(|b| {
            b.manufacturer(COMPANY_APPLE, &[0x0F, 0x05, 0xC1, 0x01]);
        });
        assert_eq!(classify(&nearby).kind, TrackerKind::AppleDevice);
        assert_eq!(classify(&nearby).detail, "Nearby action");

        let airpods = report_from(|b| {
            b.manufacturer(COMPANY_APPLE, &[0x07, 0x19, 0x07, 0x0E]);
        });
        assert_eq!(classify(&airpods).detail, "AirPods");
    }

    #[test]
    fn detects_samsung_families() {
        let buds = report_from(|b| {
            b.manufacturer(COMPANY_SAMSUNG, &[0x42, 0x09, 0x81]);
        });
        assert_eq!(classify(&buds).detail, "Galaxy Buds");
        let tag = report_from(|b| {
            b.manufacturer(COMPANY_SAMSUNG, &[0x01, 0x00, 0x02]);
        });
        assert_eq!(classify(&tag).kind, TrackerKind::SamsungSmartTag);
    }

    #[test]
    fn detects_fast_pair_and_swift_pair_from_services() {
        let fast = report_from(|b| {
            b.service_data16(ServiceUuid::FAST_PAIR.0, &[0x03, 0x01, 0x02, 0x03]);
        });
        assert_eq!(classify(&fast).kind, TrackerKind::FastPair);
        assert_eq!(fast.company_id(), None);

        let swift = report_from(|b| {
            b.manufacturer(COMPANY_MICROSOFT, &[0x03, 0x00, 0x80, b'M', b'S']);
        });
        assert_eq!(classify(&swift).kind, TrackerKind::SwiftPair);
    }

    #[test]
    fn unknown_vendor_is_reported_honestly() {
        let report = report_from(|b| {
            b.manufacturer(0x1234, &[0x01]);
        });
        let matched = classify(&report);
        assert_eq!(matched.kind, TrackerKind::Other);
        assert_eq!(matched.vendor, "Vendor");
        assert!(matched.detail.contains("0x1234"));

        let plain = report_from(|b| {
            b.name(b"NoVendorData");
        });
        assert_eq!(classify(&plain).kind, TrackerKind::Unknown);
    }

    #[test]
    fn parses_remote_id_basic_id() {
        let mut service = alloc::vec![0xFA, 0xFF, 0x0D, 0x01];
        let mut message = alloc::vec![0x02, 0x12]; // Basic ID, proto 2, id type 1, UA type 2
        message.extend_from_slice(b"1596F3A2C4D5E6F7");
        message.resize(25, 0);
        service.extend_from_slice(&message);
        let parsed = parse_remote_id(&service).expect("basic id parses");
        assert_eq!(parsed.protocol_version, 2);
        assert_eq!(parsed.ua_type, "Helicopter/multirotor");
        assert_eq!(parsed.id_type, "Serial (CTA-2063)");
        assert_eq!(parsed.uas_id, "1596F3A2C4D5E6F7");
        assert_eq!(remote_id_message_type(&service), Some(0));
    }

    #[test]
    fn remote_id_rejects_wrong_transport_and_other_message_types() {
        assert!(parse_remote_id(&[0xFA, 0xFF, 0x0D]).is_none());
        let mut service = alloc::vec![0xFA, 0xFF, 0x0D, 0x01];
        service.extend_from_slice(&[0x12; 25]); // Location message type 1
        assert!(parse_remote_id(&service).is_none());
        assert_eq!(remote_id_message_type(&service), Some(1));
        // Wrong application code.
        let mut wrong = service.clone();
        wrong[2] = 0x00;
        assert!(remote_id_message_type(&wrong).is_none());
    }

    #[test]
    fn remote_id_is_classified_from_advertisement() {
        // Remote ID needs 29 bytes of service data, so it is advertised without a
        // Flags element (as real transmitters do in the 31-byte legacy payload).
        let mut service = alloc::vec![0xFA, 0xFF, 0x0D, 0x00];
        service.extend_from_slice(&[0x02, 0x12]);
        service.resize(4 + 25, 0);
        let mut builder = AdvBuilder::new();
        assert!(builder.service_data16(ServiceUuid::REMOTE_ID.0, &service[2..]));
        let report = AdvReport::parse(
            BleAddress::new([0x33; 6]),
            -50,
            builder.as_slice(),
            false,
            0,
        );
        let matched = classify(&report);
        assert_eq!(matched.kind, TrackerKind::RemoteIdBroadcast);
        let parsed = parse_remote_id(&service).expect("basic id");
        assert_eq!(parsed.ua_type, "Helicopter/multirotor");
        assert_eq!(remote_id_message_type(&service), Some(0));
    }
}

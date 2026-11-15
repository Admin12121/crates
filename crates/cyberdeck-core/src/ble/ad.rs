//! BLE advertising-data parsing, advertisement reports and the bounded device table.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::net::MacAddr;
use crate::util::printable;

/// AD type: flags.
pub const AD_FLAGS: u8 = 0x01;
/// AD type: 16-bit service UUID list (complete).
pub const AD_UUID16_COMPLETE: u8 = 0x03;
/// AD type: 16-bit service UUID list (incomplete).
pub const AD_UUID16_INCOMPLETE: u8 = 0x02;
/// AD type: complete local name.
pub const AD_NAME_COMPLETE: u8 = 0x09;
/// AD type: shortened local name.
pub const AD_NAME_SHORT: u8 = 0x08;
/// AD type: TX power level.
pub const AD_TX_POWER: u8 = 0x0A;
/// AD type: 16-bit service data.
pub const AD_SERVICE_DATA16: u8 = 0x16;
/// AD type: 16-bit manufacturer data.
pub const AD_MANUFACTURER: u8 = 0xFF;

/// BLE device address (public or random).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BleAddress(pub [u8; 6]);

impl BleAddress {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Random addresses have the two most significant bits of the MSB set.
    pub fn is_random(&self) -> bool {
        self.0[5] & 0xC0 != 0
    }

    /// Resolvable private address shape (used by tracker detection heuristics).
    pub fn is_resolvable_private(&self) -> bool {
        self.0[5] & 0xC0 == 0x40
    }

    pub fn display(&self) -> String {
        MacAddr::new(self.0).to_string()
    }
}

/// Identity of a BLE device across address rotation: name plus manufacturer/service
/// fingerprint. Two advertisements with different random addresses but the same
/// identity are the same physical device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId {
    pub fingerprint: u32,
    pub has_name: bool,
}

impl DeviceId {
    /// Build a fingerprint from the advertisement's stable fields.
    pub fn from_advertisement(name: Option<&[u8]>, manufacturer: Option<&[u8]>, services: u32) -> Self {
        let mut hash: u32 = 0x811C_9DC5;
        let mut mix = |byte: u8| {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        };
        if let Some(name) = name {
            for byte in name {
                mix(*byte);
            }
        }
        if let Some(data) = manufacturer {
            // Manufacturer data's trailing bytes usually carry randomised
            // per-session values; hash the company id and first 6 payload bytes.
            for byte in data.iter().take(8) {
                mix(*byte);
            }
        }
        for byte in services.to_le_bytes() {
            mix(byte);
        }
        Self {
            fingerprint: hash,
            has_name: name.is_some(),
        }
    }
}

/// One AD structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdStructure<'a> {
    pub kind: u8,
    pub data: &'a [u8],
}

/// Parse an advertising payload into AD structures. Malformed tails end the walk.
pub fn parse_ad_structures(data: &[u8]) -> impl Iterator<Item = AdStructure<'_>> {
    AdStructures { rest: data }
}

struct AdStructures<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for AdStructures<'a> {
    type Item = AdStructure<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.rest.len() >= 2 {
            let len = self.rest[0] as usize;
            if len == 0 {
                self.rest = &[];
                return None;
            }
            if self.rest.len() < 1 + len {
                self.rest = &[];
                return None;
            }
            let kind = self.rest[1];
            let body = &self.rest[2..1 + len];
            self.rest = &self.rest[1 + len..];
            return Some(AdStructure { kind, data: body });
        }
        self.rest = &[];
        None
    }
}

/// Builder for an advertising payload (max 31 bytes for legacy advertising).
#[derive(Debug, Clone)]
pub struct AdvBuilder {
    data: [u8; 31],
    len: usize,
}

impl Default for AdvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvBuilder {
    pub const MAX_LEN: usize = 31;

    pub const fn new() -> Self {
        Self {
            data: [0; Self::MAX_LEN],
            len: 0,
        }
    }

    /// Append an AD structure. Returns `false` when it does not fit.
    pub fn push(&mut self, kind: u8, body: &[u8]) -> bool {
        let need = 2 + body.len();
        if body.len() > 29 || self.len + need > Self::MAX_LEN {
            return false;
        }
        self.data[self.len] = (1 + body.len()) as u8;
        self.data[self.len + 1] = kind;
        self.data[self.len + 2..self.len + 2 + body.len()].copy_from_slice(body);
        self.len += need;
        true
    }

    pub fn flags(&mut self, flags: u8) -> bool {
        self.push(AD_FLAGS, &[flags])
    }

    pub fn name(&mut self, name: &[u8]) -> bool {
        self.push(AD_NAME_COMPLETE, name)
    }

    pub fn manufacturer(&mut self, company: u16, data: &[u8]) -> bool {
        let mut buf = [0u8; 29];
        if data.len() > 27 {
            return false;
        }
        buf[..2].copy_from_slice(&company.to_le_bytes());
        buf[2..2 + data.len()].copy_from_slice(data);
        self.push(AD_MANUFACTURER, &buf[..2 + data.len()])
    }

    pub fn service_data16(&mut self, uuid: u16, data: &[u8]) -> bool {
        let mut buf = [0u8; 29];
        if data.len() > 27 {
            return false;
        }
        buf[..2].copy_from_slice(&uuid.to_le_bytes());
        buf[2..2 + data.len()].copy_from_slice(data);
        self.push(AD_SERVICE_DATA16, &buf[..2 + data.len()])
    }

    /// Append an already-encoded AD structure verbatim (used for ported vendor
    /// payload tables that include their own length/type bytes).
    pub fn push_raw(&mut self, raw: &[u8]) -> bool {
        if self.len + raw.len() > Self::MAX_LEN {
            return false;
        }
        self.data[self.len..self.len + raw.len()].copy_from_slice(raw);
        self.len += raw.len();
        true
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
}

/// 16-bit Bluetooth SIG service UUID, for display and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceUuid(pub u16);

impl ServiceUuid {
    pub const GENERIC_ACCESS: Self = Self(0x1800);
    pub const DEVICE_INFORMATION: Self = Self(0x180A);
    pub const BATTERY_SERVICE: Self = Self(0x180F);
    pub const HEART_RATE: Self = Self(0x180D);
    pub const HID: Self = Self(0x1812);
    pub const FAST_PAIR: Self = Self(0xFE2C);
    pub const REMOTE_ID: Self = Self(0xFFFA);
    pub const EDDYSTONE: Self = Self(0xFEAA);

    /// Human label for the services the UI cares about.
    pub const fn label(self) -> &'static str {
        match self.0 {
            0x1800 => "Generic Access",
            0x1801 => "Generic Attribute",
            0x180A => "Device Information",
            0x180F => "Battery",
            0x180D => "Heart Rate",
            0x1809 => "Health Thermometer",
            0x1812 => "HID",
            0x181A => "Environmental",
            0xFE2C => "Fast Pair",
            0xFFFA => "Remote ID",
            0xFEAA => "Eddystone",
            0xFE9F => "Google",
            0xFEF5 => "Tile",
            _ => "Vendor service",
        }
    }
}

/// Parsed advertisement fields used by every BLE tool.
#[derive(Debug, Clone)]
pub struct AdvReport {
    pub address: BleAddress,
    pub rssi: i8,
    pub rssi_avg16: i16,
    pub name: Option<String>,
    pub manufacturer: Option<Vec<u8>>,
    pub service_uuids: Vec<ServiceUuid>,
    pub service_data: Option<Vec<u8>>,
    pub tx_power: Option<i8>,
    pub connectable: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub count: u16,
    pub identity: DeviceId,
}

impl AdvReport {
    /// Extract the interesting fields from a raw advertising payload.
    pub fn parse(
        address: BleAddress,
        rssi: i8,
        data: &[u8],
        connectable: bool,
        now_ms: u64,
    ) -> Self {
        let mut name: Option<Vec<u8>> = None;
        let mut manufacturer: Option<Vec<u8>> = None;
        let mut service_data: Option<Vec<u8>> = None;
        let mut uuids: Vec<ServiceUuid> = Vec::new();
        let mut tx_power = None;

        for structure in parse_ad_structures(data) {
            match structure.kind {
                AD_NAME_COMPLETE | AD_NAME_SHORT if name.is_none() && !structure.data.is_empty() => {
                    name = Some(structure.data.to_vec());
                }
                AD_MANUFACTURER if manufacturer.is_none() && structure.data.len() >= 2 => {
                    manufacturer = Some(structure.data.to_vec());
                }
                AD_SERVICE_DATA16 if service_data.is_none() && structure.data.len() >= 2 => {
                    service_data = Some(structure.data.to_vec());
                }
                AD_UUID16_COMPLETE | AD_UUID16_INCOMPLETE => {
                    let mut chunks = structure.data.chunks_exact(2);
                    for chunk in &mut chunks {
                        if uuids.len() < 8 {
                            uuids.push(ServiceUuid(u16::from_le_bytes([chunk[0], chunk[1]])));
                        }
                    }
                }
                AD_TX_POWER if !structure.data.is_empty() => {
                    tx_power = Some(structure.data[0] as i8);
                }
                _ => {}
            }
        }

        let services_mask = uuids.iter().fold(0u32, |acc, u| acc | (1 << (u.0 % 32)));
        let identity = DeviceId::from_advertisement(
            name.as_deref(),
            manufacturer.as_deref(),
            services_mask,
        );
        let display_name = name.as_ref().map(|n| printable(n));

        Self {
            address,
            rssi,
            rssi_avg16: i16::from(rssi) * 16,
            name: display_name,
            manufacturer,
            service_uuids: uuids,
            service_data,
            tx_power,
            connectable,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            count: 1,
            identity,
        }
    }

    pub fn signal_dbm(&self) -> i8 {
        (self.rssi_avg16 / 16) as i8
    }

    /// Manufacturer company identifier (little-endian first two bytes).
    pub fn company_id(&self) -> Option<u16> {
        self.manufacturer
            .as_ref()
            .filter(|m| m.len() >= 2)
            .map(|m| u16::from_le_bytes([m[0], m[1]]))
    }

    /// Vendor payload after the company identifier.
    pub fn company_payload(&self) -> &[u8] {
        match &self.manufacturer {
            Some(m) if m.len() > 2 => &m[2..],
            _ => &[],
        }
    }

    /// 16-bit UUID of the service-data field.
    pub fn service_data_uuid(&self) -> Option<u16> {
        self.service_data
            .as_ref()
            .filter(|d| d.len() >= 2)
            .map(|d| u16::from_le_bytes([d[0], d[1]]))
    }

    /// Display name or a placeholder derived from the address.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => String::from("(no name)"),
        }
    }
}

/// Bounded table of observed BLE devices, keyed by physical identity so address
/// rotation does not create duplicates.
#[derive(Debug)]
pub struct AdvTable<const N: usize> {
    entries: Vec<AdvReport>,
    dropped: u32,
}

impl<const N: usize> Default for AdvTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AdvTable<N> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &AdvReport> {
        self.entries.iter()
    }

    pub fn get(&self, identity: DeviceId) -> Option<&AdvReport> {
        self.entries.iter().find(|e| e.identity == identity)
    }

    /// Insert or refresh a device. Returns `true` when it is a new identity.
    pub fn observe(&mut self, report: AdvReport) -> bool {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.identity == report.identity || e.address == report.address)
        {
            existing.address = report.address;
            existing.rssi = report.rssi;
            existing.rssi_avg16 = existing.rssi_avg16 + (report.rssi_avg16 - existing.rssi_avg16) / 4;
            existing.last_seen_ms = report.last_seen_ms;
            existing.count = existing.count.saturating_add(1);
            if existing.name.is_none() {
                existing.name = report.name;
            }
            if existing.manufacturer.is_none() {
                existing.manufacturer = report.manufacturer;
            }
            if existing.service_data.is_none() {
                existing.service_data = report.service_data;
            }
            return false;
        }
        if self.entries.len() >= N {
            // Evict the weakest signal: the device the operator is least likely
            // to be looking at, never "drop the new one" (which would hide a
            // device that just appeared).
            if let Some((idx, _)) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.rssi_avg16)
            {
                self.entries.swap_remove(idx);
                self.dropped = self.dropped.saturating_add(1);
            }
        }
        self.entries.push(report);
        true
    }

    /// Strongest-first snapshot for the UI.
    pub fn sorted(&self) -> Vec<&AdvReport> {
        let mut list: Vec<&AdvReport> = self.entries.iter().collect();
        list.sort_by_key(|e| core::cmp::Reverse(e.rssi_avg16));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_to_vec;

    #[test]
    fn parses_apple_continuity_advertisement() {
        // Flags + a complete 25-byte Apple iBeacon manufacturer body.
        let payload = hex_to_vec(
            "0201061AFF4C000215000102030405060708090A0B0C0D0E0F01000102C5",
        )
        .unwrap();
        let report = AdvReport::parse(BleAddress::new([1, 2, 3, 4, 5, 6]), -62, &payload, false, 10);
        assert_eq!(report.company_id(), Some(0x004C));
        assert_eq!(report.company_payload().len(), 23);
        assert_eq!(report.signal_dbm(), -62);
        assert_eq!(report.label(), "(no name)");
    }

    #[test]
    fn parses_name_and_service_uuid() {
        let mut builder = AdvBuilder::new();
        assert!(builder.flags(0x06));
        assert!(builder.name(b"CyberTag"));
        assert!(builder.push(AD_UUID16_COMPLETE, &[0x0F, 0x18]));
        let report = AdvReport::parse(
            BleAddress::new([0xAA; 6]),
            -50,
            builder.as_slice(),
            true,
            1,
        );
        assert_eq!(report.label(), "CyberTag");
        assert_eq!(report.service_uuids[0].0, 0x180F);
        assert_eq!(report.service_uuids[0].label(), "Battery");
        assert!(report.connectable);
    }

    #[test]
    fn truncated_ad_data_never_panics() {
        let payload = [0x05, 0x09, b'A', b'B']; // claims 5 bytes, only 2 present
        let report = AdvReport::parse(BleAddress::new([0; 6]), 0, &payload, false, 0);
        assert!(report.name.is_none());
        // Zero-length AD terminates the walk.
        let report = AdvReport::parse(BleAddress::new([0; 6]), 0, &[0x00, 0x09], false, 0);
        assert!(report.name.is_none());
    }

    #[test]
    fn builder_respects_31_byte_limit() {
        let mut builder = AdvBuilder::new();
        assert!(builder.flags(0x06));
        assert!(builder.name(&[b'X'; 28]) == false);
        assert!(builder.name(&[b'X'; 26]));
        assert_eq!(builder.len(), 31);
        assert!(!builder.flags(0x06));
    }

    #[test]
    fn table_deduplicates_address_rotation_by_identity() {
        let mut builder = AdvBuilder::new();
        builder.name(b"Rotating");
        builder.flags(0x06);
        let payload = builder.as_slice().to_vec();

        let mut table: AdvTable<8> = AdvTable::new();
        let first = AdvReport::parse(BleAddress::new([0x41; 6]), -70, &payload, false, 0);
        assert!(table.observe(first));
        let rotated = AdvReport::parse(BleAddress::new([0x42; 6]), -40, &payload, false, 100);
        assert!(!table.observe(rotated), "same identity, not a new device");
        assert_eq!(table.len(), 1);
        let entry = table.iter().next().unwrap();
        assert_eq!(entry.count, 2);
        assert_eq!(entry.address, BleAddress::new([0x42; 6]));
        assert!(entry.signal_dbm() > -70);
    }

    #[test]
    fn table_evicts_weakest_not_newest() {
        let mut table: AdvTable<2> = AdvTable::new();
        for (i, rssi) in [(1u8, -90i8), (2, -40), (3, -30)] {
            let mut builder = AdvBuilder::new();
            builder.name(&[b'D', b'0' + i]);
            let payload = builder.as_slice().to_vec();
            table.observe(AdvReport::parse(
                BleAddress::new([i; 6]),
                rssi,
                &payload,
                false,
                u64::from(i),
            ));
        }
        assert_eq!(table.len(), 2);
        assert_eq!(table.dropped(), 1);
        let names: Vec<String> = table.iter().map(|e| e.label()).collect();
        assert!(!names.contains(&String::from("D1")));
    }

    #[test]
    fn address_kind_detection() {
        assert!(BleAddress::new([1, 2, 3, 4, 5, 0xC1]).is_random());
        assert!(BleAddress::new([1, 2, 3, 4, 5, 0x41]).is_resolvable_private());
        assert!(!BleAddress::new([1, 2, 3, 4, 5, 0x01]).is_random());
        assert_eq!(BleAddress::new([0xAA; 6]).display(), "AA:AA:AA:AA:AA:AA");
    }
}

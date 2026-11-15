//! G03 — Bluetooth Low Energy (hardware independent part).
//!
//! * [`ad`] — advertising-data (AD structure) parsing/building and device table.
//! * [`vendor`] — vendor/tracker/Remote-ID classification from real payloads.
//! * [`spam`] — advertisement test payloads ported from the reference firmware.
//!
//! Classic Bluetooth (BR/EDR) is **not** available on the ESP32-S3 radio; tools that
//! require it are reported as `Requires Different Hardware` with the specific
//! profile, never as "unsupported because unimplemented".

pub mod ad;
pub mod spam;
pub mod vendor;

pub use ad::{AdStructure, AdvReport, AdvTable, BleAddress, DeviceId, ServiceUuid};
pub use vendor::{RemoteId, TrackerKind, VendorMatch};

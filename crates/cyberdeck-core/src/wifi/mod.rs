//! G01 — Wi-Fi offensive/security engine (hardware independent part).
//!
//! Modules:
//! * [`frame`] — 802.11 parsing/building (beacons, probe, auth, assoc, deauth).
//! * [`ap`] — BSS/station tables, discovery scan engine, channel hopper.
//! * [`eapol`] — EAPOL-Key parsing, handshake assembly, PMKID capture, MIC
//!   verification and hashcat-compatible export.
//! * [`crypto`] — PBKDF2/PMK/PTK/PMKID/MIC primitives.
//! * [`attack`] — bounded, cancellable frame-injection state machines.
//! * [`portal`] — captive-portal HTTP/DNS protocol handling and credential capture.
//!
//! The radio driver itself (scan/AP/sniffer/raw TX) lives in the firmware package
//! under `features/wifi/adapters`; everything decision-making is here so it is
//! covered by the host test suite.

pub mod ap;
pub mod attack;
pub mod crypto;
pub mod eapol;
pub mod frame;
pub mod portal;

pub use ap::{ApTable, BssRecord, ChannelHopper, ScanEngine, Ssid, StationTable};
pub use frame::{FrameBuffer, FrameControl, FrameHeader, Security, SecurityInfo};

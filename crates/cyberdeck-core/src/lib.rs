//! Hardware-independent CyberDeck logic.
//!
//! Every protocol engine, format writer, state machine and UI projection in this
//! crate is plain Rust with no hardware access, so the exact code that runs on the
//! ESP32-S3 is also executed by the host test suite (`cargo test` from this
//! directory). Firmware-only code lives in the `cyberdeck-firmware` package and is
//! limited to platform adapters (ESP-IDF/esp-hal drivers) and composition.
//!
//! Layout follows the project's feature-first MVC split: `model`/`service` style
//! logic lives under `wifi`, `packet`, `ble`, `usb_hid` and `rf`; shared
//! primitives (errors, hardware registry, jobs, queues, PCAP, UI canvas) live at
//! the crate root.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]

extern crate alloc;

pub mod ble;
pub mod board;
pub mod error;
pub mod event;
pub mod hardware;
pub mod hid;
pub mod job;
pub mod net;
pub mod packet;
pub mod pcap;
pub mod rf;
pub mod time;
pub mod ui;
pub mod util;
pub mod wifi;

pub use error::{DeckError, ErrorCategory};
pub use hardware::{DeviceClass, DeviceState, HardwareManifest, PeripheralRegistry};

/// Firmware version reported in logs, session files and the about screen.
pub const FIRMWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name shown in the device UI header.
pub const DEVICE_NAME: &str = "CyberDeck";

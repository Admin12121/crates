//! CyberDeck firmware composition layer.
//!
//! Everything protocol-related lives in `cyberdeck-core` (host-tested); this crate
//! owns the ESP32-S3 platform adapters (`platform/`) and the screen/navigation
//! composition (`app/`). `main.rs` only initialises hardware and injects it.

#![no_std]

extern crate alloc;

pub mod app;
pub mod platform;

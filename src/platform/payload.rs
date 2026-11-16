//! Payload catalogue shared by the USB and BLE HID actors.
//!
//! Built-in demo scripts live in `cyberdeck_core`; user scripts come from
//! `PAYLOADS/HID/*.TXT` on the SD card and are moved here exactly once, so a script
//! body exists in RAM once rather than once per reader.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use critical_section::Mutex;
use cyberdeck_core::hid::engine;

use super::sd;

static EXTERNAL: Mutex<RefCell<Vec<(String, String)>>> = Mutex::new(RefCell::new(Vec::new()));

/// Adopt a freshly scanned SD payload list. Returns true when the catalogue changed.
pub fn sync_from_storage() -> bool {
    let Some(list) = sd::take_payloads() else {
        return false;
    };
    critical_section::with(|cs| *EXTERNAL.borrow_ref_mut(cs) = list);
    true
}

/// Picker names: built-ins first, then SD scripts, in the order indices resolve.
pub fn names() -> Vec<String> {
    critical_section::with(|cs| engine::payload_names(&EXTERNAL.borrow_ref(cs)))
}

/// Resolve a picker index to `(name, script body)`.
pub fn resolve(index: u8) -> Option<(String, String)> {
    critical_section::with(|cs| engine::resolve_payload(usize::from(index), &EXTERNAL.borrow_ref(cs)))
}

/// Setup-screen preview text for the selected payload.
pub fn preview(index: u8) -> Option<String> {
    resolve(index).map(|(name, body)| alloc::format!("{name}\n{body}"))
}

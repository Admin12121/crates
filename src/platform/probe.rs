//! Boot-time hardware probing for the peripheral registry.
//!
//! Each adapter reports its own outcome; the registry keeps the whole picture so
//! menus can show `NO HW` for one tool while the rest stay usable.

use alloc::string::String;
use alloc::vec::Vec;
use cyberdeck_core::hardware::{DeviceClass, DeviceState, PeripheralRegistry};
use cyberdeck_core::board::BoardProfile;

/// Result of the boot probe, including one human-readable line per device.
pub struct ProbeReport {
    pub registry: PeripheralRegistry,
    pub lines: Vec<String>,
}

impl ProbeReport {
    pub fn new() -> Self {
        Self {
            registry: PeripheralRegistry::new(),
            lines: Vec::new(),
        }
    }

    pub fn record(
        &mut self,
        class: DeviceClass,
        result: Result<Option<String>, &'static str>,
    ) {
        match result {
            Ok(detail) => {
                self.registry
                    .upsert(class, DeviceState::Ready, detail.as_deref());
                self.lines.push(match detail {
                    Some(detail) => alloc::format!("{}: ready ({detail})", class.label()),
                    None => alloc::format!("{}: ready", class.label()),
                });
            }
            Err(reason) => {
                self.registry
                    .upsert(class, DeviceState::InitFailed { reason }, None);
                self.lines
                    .push(alloc::format!("{}: {reason}", class.label()));
            }
        }
    }

    pub fn summary(&self, profile: &BoardProfile) -> Vec<String> {
        let mut out = alloc::vec![profile.wiring_summary()];
        out.extend(self.lines.iter().cloned());
        out
    }
}

impl Default for ProbeReport {
    fn default() -> Self {
        Self::new()
    }
}

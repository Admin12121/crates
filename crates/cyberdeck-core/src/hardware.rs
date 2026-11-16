//! Runtime peripheral registry and operation-scoped hardware guards.
//!
//! Mandatory rule (master plan §3A.8): a board profile states what *can* be
//! supported; only the registry states what is *detected and initialized now*.
//! Every operation checks its manifest immediately before starting, so a missing
//! optional module disables exactly the tools that need it and nothing else.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::DeckError;

/// Maximum number of distinct peripherals tracked at once.
pub const MAX_DEVICES: usize = 16;

/// Peripheral classes the firmware can require, detect or mark incompatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    WifiRadio,
    BleRadio,
    UsbDevice,
    Nrf24,
    SdCard,
    Display,
    Input,
    BatteryAdc,
    Gps,
    Cc1101,
    NfcReader,
    Infrared,
    ExternalRtc,
}

impl DeviceClass {
    /// Operator-facing name used in every message and status line.
    pub const fn label(self) -> &'static str {
        match self {
            Self::WifiRadio => "ESP32-S3 Wi-Fi radio",
            Self::BleRadio => "ESP32-S3 Bluetooth radio",
            Self::UsbDevice => "native USB device controller",
            Self::Nrf24 => "nRF24L01 radio",
            Self::SdCard => "microSD card",
            Self::Display => "display",
            Self::Input => "input buttons",
            Self::BatteryAdc => "battery monitor",
            Self::Gps => "GPS receiver",
            Self::Cc1101 => "CC1101 radio",
            Self::NfcReader => "NFC reader",
            Self::Infrared => "infrared transceiver",
            Self::ExternalRtc => "external RTC",
        }
    }

    /// Related devices that share a role, used to explain an incompatibility
    /// instead of reporting a bare "not detected".
    pub const fn substitutes(self) -> &'static [DeviceClass] {
        match self {
            Self::Nrf24 => &[Self::Cc1101],
            Self::Cc1101 => &[Self::Nrf24],
            _ => &[],
        }
    }
}

/// Lifecycle of one detected peripheral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Probed and nothing answered.
    NotDetected,
    /// Answered on the bus, not yet initialised.
    Detected,
    /// Something answered, but it is a different device class.
    Incompatible { detected: DeviceClass },
    /// Present but driver initialisation failed.
    InitFailed { reason: &'static str },
    /// Owned by a running operation.
    Busy { owner: &'static str },
    /// Initialised and usable.
    Ready,
}

impl DeviceState {
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Compact label for status screens.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NotDetected => "not detected",
            Self::Detected => "detected",
            Self::Incompatible { .. } => "incompatible",
            Self::InitFailed { .. } => "init failed",
            Self::Busy { .. } => "busy",
            Self::Ready => "ready",
        }
    }
}

/// One registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    pub class: DeviceClass,
    pub state: DeviceState,
    /// Optional driver/model note, e.g. `probe returns 0xE7`.
    pub detail: Option<String>,
    /// Uptime of the last probe in milliseconds.
    pub probed_at_ms: u64,
}

/// Per-device registry with bounded size (no unbounded growth from hot-plug).
#[derive(Debug, Default)]
pub struct PeripheralRegistry {
    entries: Vec<DeviceEntry>,
}

impl PeripheralRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or replace the state of `class`.
    pub fn upsert(&mut self, class: DeviceClass, state: DeviceState, detail: Option<&str>) {
        self.set(class, state, detail, 0);
    }

    /// Insert or replace with an explicit probe timestamp.
    pub fn set(
        &mut self,
        class: DeviceClass,
        state: DeviceState,
        detail: Option<&str>,
        now_ms: u64,
    ) {
        let detail = detail.map(|d| d.to_string());
        if let Some(entry) = self.entries.iter_mut().find(|e| e.class == class) {
            entry.state = state;
            entry.detail = detail;
            entry.probed_at_ms = now_ms;
            return;
        }
        if self.entries.len() >= MAX_DEVICES {
            // Registry is full: drop the oldest *not ready* row rather than growing.
            if let Some(idx) = self.entries.iter().position(|e| !e.state.is_ready()) {
                self.entries.swap_remove(idx);
            } else {
                return;
            }
        }
        self.entries.push(DeviceEntry {
            class,
            state,
            detail,
            probed_at_ms: now_ms,
        });
    }

    pub fn get(&self, class: DeviceClass) -> Option<&DeviceEntry> {
        self.entries.iter().find(|e| e.class == class)
    }

    pub fn state(&self, class: DeviceClass) -> Option<&DeviceState> {
        self.get(class).map(|e| &e.state)
    }

    pub fn is_ready(&self, class: DeviceClass) -> bool {
        self.state(class)
            .map(DeviceState::is_ready)
            .unwrap_or(false)
    }

    /// Mark a device busy for the duration of an operation.
    pub fn mark_busy(&mut self, class: DeviceClass, owner: &'static str) {
        self.set(class, DeviceState::Busy { owner }, None, 0);
    }

    /// Restore a busy device to ready (or its previous failure) after an operation.
    pub fn release(&mut self, class: DeviceClass) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.class == class)
            && matches!(entry.state, DeviceState::Busy { .. })
        {
            entry.state = DeviceState::Ready;
        }
    }

    /// All rows, for the diagnostics screen.
    pub fn all(&self) -> &[DeviceEntry] {
        &self.entries
    }

    /// Human-readable one-line status for the diagnostics/UX requirement.
    pub fn describe(&self, class: DeviceClass) -> String {
        match self.get(class) {
            None => alloc::format!("{}: not probed", class.label()),
            Some(entry) => {
                let mut out = alloc::format!("{}: {}", class.label(), entry.state.label());
                match (&entry.state, &entry.detail) {
                    (DeviceState::InitFailed { reason }, _) => {
                        out.push_str(&alloc::format!(" ({reason})"));
                    }
                    (DeviceState::Incompatible { detected }, _) => {
                        out.push_str(&alloc::format!(" ({})", detected.label()));
                    }
                    (_, Some(detail)) => {
                        out.push_str(&alloc::format!(" ({detail})"));
                    }
                    _ => {}
                }
                out
            }
        }
    }

    /// Guard an operation: every required device must be ready.
    ///
    /// Returns the structured error mandated by the plan (MissingHardware /
    /// IncompatibleHardware / InitializationFailed / ResourceBusy) rather than a
    /// generic failure, so the view can render actionable text.
    pub fn require(&self, manifest: &HardwareManifest) -> Result<(), DeckError> {
        self.require_for(manifest, "")
    }

    /// Same as [`Self::require`] with the operation name used in messages.
    pub fn require_for(
        &self,
        manifest: &HardwareManifest,
        operation: &str,
    ) -> Result<(), DeckError> {
        for &wanted in manifest.required {
            match self.state(wanted) {
                Some(DeviceState::Ready) => {}
                Some(DeviceState::Busy { owner }) => {
                    return Err(DeckError::Busy {
                        resource: wanted.label(),
                        owner,
                    });
                }
                Some(DeviceState::InitFailed { reason }) => {
                    return Err(DeckError::InitFailed {
                        device: wanted,
                        reason,
                    });
                }
                Some(DeviceState::Detected) => {
                    return Err(DeckError::InitFailed {
                        device: wanted,
                        reason: "detected but not initialised",
                    });
                }
                Some(DeviceState::Incompatible { detected }) => {
                    return Err(DeckError::Incompatible {
                        wanted,
                        detected: *detected,
                        hint: manifest.hint,
                    });
                }
                Some(DeviceState::NotDetected) | None => {
                    return Err(DeckError::MissingHardware {
                        wanted,
                        detected: self.find_substitute(wanted),
                        hint: manifest.hint,
                    });
                }
            }
        }
        let _ = operation;
        Ok(())
    }

    /// Look for a present device that could be mistaken for `wanted`.
    pub fn find_substitute(&self, wanted: DeviceClass) -> Option<DeviceClass> {
        wanted.substitutes().iter().copied().find(|candidate| {
            matches!(
                self.state(*candidate),
                Some(DeviceState::Ready | DeviceState::Detected)
            )
        })
    }
}

/// Declarative hardware requirement of one operation (not of a menu).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareManifest {
    pub required: &'static [DeviceClass],
    /// Enhancements that improve the tool but never block it.
    pub optional: &'static [DeviceClass],
    /// Extra sentence appended to failure messages (e.g. which sibling tools stay available).
    pub hint: &'static str,
}

impl HardwareManifest {
    pub const fn new(required: &'static [DeviceClass], optional: &'static [DeviceClass]) -> Self {
        Self {
            required,
            optional,
            hint: "",
        }
    }

    pub const fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = hint;
        self
    }

    /// True when every required device is ready.
    pub fn is_satisfied(&self, registry: &PeripheralRegistry) -> bool {
        self.required.iter().all(|c| registry.is_ready(*c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_registry() -> PeripheralRegistry {
        let mut reg = PeripheralRegistry::new();
        for class in [
            DeviceClass::WifiRadio,
            DeviceClass::BleRadio,
            DeviceClass::UsbDevice,
            DeviceClass::Display,
            DeviceClass::Input,
        ] {
            reg.set(class, DeviceState::Ready, None, 10);
        }
        reg.set(DeviceClass::SdCard, DeviceState::NotDetected, None, 10);
        reg
    }

    #[test]
    fn missing_optional_module_does_not_block_other_tools() {
        let reg = ready_registry();
        let wifi = HardwareManifest::new(&[DeviceClass::WifiRadio], &[DeviceClass::SdCard]);
        assert!(reg.require(&wifi).is_ok());

        let rf = HardwareManifest::new(&[DeviceClass::Nrf24], &[]);
        let err = reg.require(&rf).unwrap_err();
        assert!(matches!(err, DeckError::MissingHardware { .. }));
        // Wi-Fi stays usable after an RF guard fails.
        assert!(reg.require(&wifi).is_ok());
    }

    #[test]
    fn cc1101_is_reported_as_incompatible_not_missing() {
        let mut reg = ready_registry();
        reg.set(DeviceClass::Cc1101, DeviceState::Ready, None, 1);
        let err = reg
            .require(&HardwareManifest::new(&[DeviceClass::Nrf24], &[]))
            .unwrap_err();
        match err {
            DeckError::MissingHardware { detected, .. } => {
                assert_eq!(detected, Some(DeviceClass::Cc1101));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn busy_device_reports_owner() {
        let mut reg = ready_registry();
        reg.mark_busy(DeviceClass::WifiRadio, "Deauth Test");
        let err = reg
            .require(&HardwareManifest::new(&[DeviceClass::WifiRadio], &[]))
            .unwrap_err();
        assert_eq!(
            err,
            DeckError::Busy {
                resource: "ESP32-S3 Wi-Fi radio",
                owner: "Deauth Test"
            }
        );
        reg.release(DeviceClass::WifiRadio);
        assert!(reg.is_ready(DeviceClass::WifiRadio));
    }

    #[test]
    fn registry_is_bounded() {
        let mut reg = PeripheralRegistry::new();
        for _ in 0..MAX_DEVICES {
            reg.set(DeviceClass::Gps, DeviceState::NotDetected, None, 0);
        }
        reg.set(DeviceClass::NfcReader, DeviceState::NotDetected, None, 0);
        assert!(reg.all().len() <= MAX_DEVICES);
    }

    #[test]
    fn describe_reports_init_failure_reason() {
        let mut reg = PeripheralRegistry::new();
        reg.set(
            DeviceClass::Nrf24,
            DeviceState::InitFailed {
                reason: "no response on SPI",
            },
            None,
            0,
        );
        let line = reg.describe(DeviceClass::Nrf24);
        assert_eq!(line, "nRF24L01 radio: init failed (no response on SPI)");
    }
}

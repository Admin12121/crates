//! Typed error model shared by every capability group.
//!
//! The on-device UX contract requires *actionable* failures: name the missing or
//! incompatible module, say which operation needs it, and keep unrelated features
//! usable. [`DeckError::describe`] is the single place that produces those strings,
//! so every feature reports hardware faults consistently.

use alloc::format;
use alloc::string::String;
use core::fmt;

use crate::hardware::DeviceClass;

/// Coarse error class used by the UI to pick an icon/colour and by tests to assert
/// the fault-isolation contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// A required peripheral is not present at all.
    MissingHardware,
    /// A peripheral answered but is the wrong kind for this operation.
    IncompatibleHardware,
    /// A present peripheral failed to initialise.
    InitializationFailed,
    /// The peripheral or shared bus is owned by another running operation.
    ResourceBusy,
    /// A peripheral disappeared while an operation was running.
    Disconnected,
    /// Storage is absent, full or failed.
    Storage,
    /// Caller supplied invalid input (target, channel, script, field).
    InvalidInput,
    /// An operation did not complete in time.
    Timeout,
    /// The operator cancelled the operation.
    Cancelled,
    /// The chip/SDK cannot perform this on the current board profile.
    Unsupported,
    /// An invariant that should not fail at runtime.
    Internal,
}

/// A user-presentable CyberDeck failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeckError {
    MissingHardware {
        wanted: DeviceClass,
        /// A related device that *is* present, when one can be identified.
        detected: Option<DeviceClass>,
        hint: &'static str,
    },
    Incompatible {
        wanted: DeviceClass,
        detected: DeviceClass,
        hint: &'static str,
    },
    InitFailed {
        device: DeviceClass,
        reason: &'static str,
    },
    Busy {
        resource: &'static str,
        owner: &'static str,
    },
    Disconnected {
        device: DeviceClass,
        hint: &'static str,
    },
    Storage {
        reason: &'static str,
    },
    InvalidInput {
        reason: &'static str,
    },
    Timeout {
        what: &'static str,
    },
    Cancelled,
    Unsupported {
        what: &'static str,
    },
    Internal {
        reason: &'static str,
    },
}

impl DeckError {
    /// Category used for UI treatment and machine assertions.
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::MissingHardware { .. } => ErrorCategory::MissingHardware,
            Self::Incompatible { .. } => ErrorCategory::IncompatibleHardware,
            Self::InitFailed { .. } => ErrorCategory::InitializationFailed,
            Self::Busy { .. } => ErrorCategory::ResourceBusy,
            Self::Disconnected { .. } => ErrorCategory::Disconnected,
            Self::Storage { .. } => ErrorCategory::Storage,
            Self::InvalidInput { .. } => ErrorCategory::InvalidInput,
            Self::Timeout { .. } => ErrorCategory::Timeout,
            Self::Cancelled => ErrorCategory::Cancelled,
            Self::Unsupported { .. } => ErrorCategory::Unsupported,
            Self::Internal { .. } => ErrorCategory::Internal,
        }
    }

    /// Whether the operator can fix this by attaching/replacing hardware.
    pub const fn is_hardware_fault(&self) -> bool {
        matches!(
            self.category(),
            ErrorCategory::MissingHardware
                | ErrorCategory::IncompatibleHardware
                | ErrorCategory::InitializationFailed
                | ErrorCategory::Disconnected
        )
    }

    /// Short operation-scoped description, for example
    /// `No hardware detected: nRF24L01 radio. Connect a compatible nRF24L01 module
    /// to use RF Channel Monitor.`
    pub fn describe(&self, operation: &str) -> String {
        match self {
            Self::MissingHardware {
                wanted,
                detected,
                hint,
            } => {
                let mut out = format!("No hardware detected: {}.", wanted.label());
                if let Some(found) = detected {
                    out.push_str(&format!(" Detected {} instead.", found.label()));
                }
                out.push_str(&format!(
                    " Connect a compatible {} to use {operation}.",
                    wanted.label()
                ));
                if !hint.is_empty() {
                    out.push(' ');
                    out.push_str(hint);
                }
                out
            }
            Self::Incompatible {
                wanted,
                detected,
                hint,
            } => {
                let mut out = format!(
                    "Incompatible hardware: detected {}; {operation} requires {}.",
                    detected.label(),
                    wanted.label()
                );
                if !hint.is_empty() {
                    out.push(' ');
                    out.push_str(hint);
                }
                out
            }
            Self::InitFailed { device, reason } => {
                format!(
                    "{} failed to initialise ({reason}). {operation} is unavailable; \
                     check wiring and retry detection.",
                    device.label()
                )
            }
            Self::Busy { resource, owner } => format!(
                "{resource} is busy: {owner} is running. Stop it before starting {operation}."
            ),
            Self::Disconnected { device, hint } => {
                let mut out = format!("{} disconnected. {operation} stopped.", device.label());
                if !hint.is_empty() {
                    out.push(' ');
                    out.push_str(hint);
                }
                out
            }
            Self::Storage { reason } => {
                format!("Storage unavailable ({reason}). {operation} cannot persist results.")
            }
            Self::InvalidInput { reason } => format!("{operation}: {reason}."),
            Self::Timeout { what } => format!("{operation} timed out waiting for {what}."),
            Self::Cancelled => format!("{operation} cancelled."),
            Self::Unsupported { what } => format!("{operation} is not supported here: {what}."),
            Self::Internal { reason } => format!("{operation} failed internally: {reason}."),
        }
    }
}

impl fmt::Display for DeckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe("this operation"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_hardware_message_names_module_and_operation() {
        let err = DeckError::MissingHardware {
            wanted: DeviceClass::Nrf24,
            detected: None,
            hint: "",
        };
        let text = err.describe("RF Channel Monitor");
        assert!(text.starts_with("No hardware detected: nRF24L01 radio."));
        assert!(text.contains("Connect a compatible nRF24L01 radio to use RF Channel Monitor."));
        assert_eq!(err.category(), ErrorCategory::MissingHardware);
        assert!(err.is_hardware_fault());
    }

    #[test]
    fn incompatible_message_keeps_other_tools_available() {
        let err = DeckError::Incompatible {
            wanted: DeviceClass::Nrf24,
            detected: DeviceClass::Cc1101,
            hint: "CC1101 tools remain available.",
        };
        let text = err.describe("RF Packet Mode");
        assert_eq!(
            text,
            "Incompatible hardware: detected CC1101 radio; RF Packet Mode requires \
             nRF24L01 radio. CC1101 tools remain available."
        );
        assert_eq!(err.category(), ErrorCategory::IncompatibleHardware);
    }

    #[test]
    fn busy_message_names_owner() {
        let err = DeckError::Busy {
            resource: "Wi-Fi radio",
            owner: "Deauth Test",
        };
        assert!(
            err.describe("Packet Capture")
                .contains("Deauth Test is running")
        );
    }

    #[test]
    fn cancellation_is_not_a_hardware_fault() {
        assert!(!DeckError::Cancelled.is_hardware_fault());
        assert_eq!(DeckError::Cancelled.category(), ErrorCategory::Cancelled);
    }
}

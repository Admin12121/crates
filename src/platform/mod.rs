//! Platform adapters: the only modules allowed to touch esp-hal / esp-radio.
//!
//! Every adapter is fallible and independent. A missing display, SD card, radio or
//! nRF24 module must never prevent the others from initialising (master plan
//! §3A.8), so constructors return `Result` and callers record the outcome in the
//! peripheral registry instead of unwrapping.

pub mod display;
pub mod input;
pub mod nrf24;
pub mod probe;
pub mod wifi;

pub use display::Display;
pub use input::{Button, Buttons};
pub use probe::ProbeReport;

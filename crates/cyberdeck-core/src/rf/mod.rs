//! G05 — nRF24L01 / 2.4 GHz RF (hardware independent part).
//!
//! * [`nrf24`] — register map, command encoding and mode configuration plans.
//! * [`spectrum`] — RPD sweep integration, peak hold and envelope rendering.
//! * [`capture`] — received packet log, payload formatting and address scan plans.
//! * [`session`] — per-channel session baseline and payload-shape summary.
//!
//! Honesty boundary: the nRF24L01 exposes a **1-bit** received-power detector
//! (`RPD`). The "spectrum" view is a relative activity display built from those
//! bits, not an SDR power measurement, and the UI labels it accordingly.

pub mod capture;
pub mod nrf24;
pub mod session;
pub mod spectrum;

pub use capture::{NrfLog, NrfPacket};
pub use nrf24::{DataRate, Nrf24Mode, RegisterWrite};
pub use session::{PayloadClass, SessionStats};
pub use spectrum::Spectrum;

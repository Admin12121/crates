//! Battery monitor state: raw ADC samples in, pack voltage and percent out.
//!
//! The ADC itself is owned by the composition root (it is a blocking, cheap
//! peripheral like the nRF24); this module only converts and publishes so the
//! diagnostics screen can read a recent value without touching the ADC.

use alloc::string::String;
use core::cell::RefCell;

use critical_section::Mutex;

/// Full-scale reading for 12-bit conversions at 11 dB attenuation.
const ADC_FULL_SCALE_MV: u32 = 3100;
/// Single-cell Li-ion window used for the percentage estimate.
const PACK_EMPTY_MV: u32 = 3300;
const PACK_FULL_MV: u32 = 4200;

struct BatteryState {
    millivolts: u16,
    percent: u8,
    samples: u32,
}

static STATE: Mutex<RefCell<BatteryState>> = Mutex::new(RefCell::new(BatteryState {
    millivolts: 0,
    percent: 0,
    samples: 0,
}));

/// Convert one raw ADC sample and publish it.
///
/// The conversion is uncalibrated: it assumes a 3.1 V full scale at 11 dB, and
/// the divider ratio comes from the board profile. Treat the absolute value as
/// indicative until it is measured against a meter.
pub fn publish(raw: u16, divider: u16) {
    let pin_mv = u32::from(raw) * ADC_FULL_SCALE_MV / 4095;
    let pack_mv = (pin_mv * u32::from(divider.max(1))).min(u16::MAX as u32) as u16;
    let percent = if pack_mv <= PACK_EMPTY_MV as u16 {
        0
    } else if pack_mv >= PACK_FULL_MV as u16 {
        100
    } else {
        ((u32::from(pack_mv) - PACK_EMPTY_MV) * 100 / (PACK_FULL_MV - PACK_EMPTY_MV)) as u8
    };
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.millivolts = pack_mv;
        state.percent = percent;
        state.samples = state.samples.saturating_add(1);
    });
}

/// Latest pack reading, or `None` before the first sample.
pub fn snapshot() -> Option<(u16, u8)> {
    critical_section::with(|cs| {
        let state = STATE.borrow_ref(cs);
        (state.samples > 0).then_some((state.millivolts, state.percent))
    })
}

/// One diagnostics line, e.g. `BAT 3.92 V 62%`.
pub fn status_line() -> String {
    match snapshot() {
        Some((millivolts, percent)) => alloc::format!(
            "BAT {}.{:02} V {}%",
            millivolts / 1000,
            (millivolts % 1000) / 10,
            percent
        ),
        None => String::from("BAT: no reading"),
    }
}

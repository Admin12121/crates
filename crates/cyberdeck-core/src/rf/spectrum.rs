//! RPD-based activity sweep, peak hold, envelope and waterfall rows.
//!
//! Ported from Bruce `src/modules/NRF24/nrf_spectrum.cpp`: 1 MHz channel steps,
//! ~128 us dwell, exponential smoothing `(old * 3 + sample) / 4` and linearly
//! interpolated envelopes for the plot. Levels are relative activity from a 1-bit
//! detector — the UI must not present them as calibrated power.

use super::nrf24::{CHANNEL_COUNT, MAX_CHANNEL};

/// Full-scale level for one channel: the accumulator converges to 125 when RPD is
/// asserted on every sweep (same scale as the reference implementation).
pub const FULL_SCALE: u8 = 125;

/// Microseconds to listen per channel before sampling RPD.
pub const DWELL_US: u16 = 128;

/// Per-channel activity state for the spectrum and waterfall views.
#[derive(Debug)]
pub struct Spectrum {
    levels: [u8; CHANNEL_COUNT as usize],
    peak: [u8; CHANNEL_COUNT as usize],
    sweeps: u32,
    waterfall: [[u8; 64]; 4],
    waterfall_row: usize,
}

impl Default for Spectrum {
    fn default() -> Self {
        Self::new()
    }
}

impl Spectrum {
    pub const fn new() -> Self {
        Self {
            levels: [0; CHANNEL_COUNT as usize],
            peak: [0; CHANNEL_COUNT as usize],
            sweeps: 0,
            waterfall: [[0; 64]; 4],
            waterfall_row: 0,
        }
    }

    /// Record one RPD sample for `channel` (0..=125).
    pub fn apply(&mut self, channel: u8, rpd_asserted: bool) {
        if channel > MAX_CHANNEL {
            return;
        }
        let idx = channel as usize;
        let sample = if rpd_asserted { FULL_SCALE } else { 0 };
        let current = u16::from(self.levels[idx]);
        self.levels[idx] = ((current * 3 + u16::from(sample)) / 4) as u8;
        if self.levels[idx] > self.peak[idx] {
            self.peak[idx] = self.levels[idx];
        } else {
            // Slow decay keeps the hold line readable.
            self.peak[idx] = self.peak[idx].saturating_sub(1);
        }
    }

    /// Mark a full sweep complete (used for the sweep counter and waterfall).
    pub fn finish_sweep(&mut self) {
        self.sweeps = self.sweeps.saturating_add(1);
        self.push_waterfall_row();
    }

    pub fn sweeps(&self) -> u32 {
        self.sweeps
    }

    pub fn level(&self, channel: u8) -> u8 {
        self.levels
            .get(channel as usize)
            .copied()
            .unwrap_or(0)
    }

    pub fn peak_level(&self, channel: u8) -> u8 {
        self.peak.get(channel as usize).copied().unwrap_or(0)
    }

    /// Activity as 0..=100 % of full scale.
    pub fn percent(&self, channel: u8) -> u8 {
        let level = u16::from(self.level(channel)).min(u16::from(FULL_SCALE));
        (level * 100 / u16::from(FULL_SCALE)) as u8
    }

    /// Busiest channel, or `None` when the band is quiet.
    pub fn peak_channel(&self) -> Option<u8> {
        let mut best: Option<(u8, u8)> = None;
        for (channel, level) in self.levels.iter().enumerate() {
            if *level == 0 {
                continue;
            }
            if best.map(|(_, v)| *level > v).unwrap_or(true) {
                best = Some((channel as u8, *level));
            }
        }
        best.map(|(channel, _)| channel)
    }

    /// Interpolate the 126 carriers into `out.len()` columns, scaled to 0..=100.
    pub fn envelope(&self, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        let last = (CHANNEL_COUNT - 1) as i32;
        for (i, slot) in out.iter_mut().enumerate() {
            let position = if out.len() == 1 {
                0
            } else {
                (i as i32 * last * 256) / (out.len() as i32 - 1)
            };
            let mut carrier = (position >> 8).clamp(0, last - 1);
            let fraction = position & 0xFF;
            if carrier >= last {
                carrier = last - 1;
            }
            let a = i32::from(self.levels[carrier as usize]);
            let b = i32::from(self.levels[(carrier + 1) as usize]);
            let value = a + (b - a) * fraction / 256;
            *slot = ((value * 100) / i32::from(FULL_SCALE)).clamp(0, 100) as u8;
        }
    }

    /// Interpolate the peak-hold trace.
    pub fn peak_envelope(&self, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        let last = (CHANNEL_COUNT - 1) as i32;
        for (i, slot) in out.iter_mut().enumerate() {
            let position = if out.len() == 1 {
                0
            } else {
                (i as i32 * last * 256) / (out.len() as i32 - 1)
            };
            let carrier = (position >> 8).clamp(0, last - 1);
            let a = i32::from(self.peak[carrier as usize]);
            let b = i32::from(self.peak[(carrier + 1) as usize]);
            let value = a + (b - a) * (position & 0xFF) / 256;
            *slot = ((value * 100) / i32::from(FULL_SCALE)).clamp(0, 100) as u8;
        }
    }

    /// Waterfall history rows (oldest first), 64 columns each.
    pub fn waterfall(&self) -> [[u8; 64]; 4] {
        let mut rows = [[0u8; 64]; 4];
        for i in 0..4 {
            rows[i] = self.waterfall[(self.waterfall_row + 1 + i) % 4];
        }
        rows
    }

    /// Activity percentage at a channel, for the status readout.
    pub fn readout(&self) -> (u8, u16, u8) {
        let channel = self.peak_channel().unwrap_or(0);
        (channel, super::nrf24::frequency_mhz(channel), self.percent(channel))
    }

    pub fn clear(&mut self) {
        self.levels = [0; CHANNEL_COUNT as usize];
        self.peak = [0; CHANNEL_COUNT as usize];
        self.sweeps = 0;
    }

    fn push_waterfall_row(&mut self) {
        let mut row = [0u8; 64];
        self.envelope(&mut row);
        let next = (self.waterfall_row + 1) % 4;
        self.waterfall[next] = row;
        self.waterfall_row = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoothing_converges_toward_full_scale() {
        let mut spectrum = Spectrum::new();
        for _ in 0..10 {
            spectrum.apply(40, true);
        }
        assert!(spectrum.level(40) > 100, "converges near 125");
        for _ in 0..10 {
            spectrum.apply(40, false);
        }
        assert!(spectrum.level(40) < 10);
    }

    #[test]
    fn single_sample_sets_a_quarter_scale() {
        let mut spectrum = Spectrum::new();
        spectrum.apply(10, true);
        assert_eq!(spectrum.level(10), 31); // 125 / 4
        assert_eq!(spectrum.percent(10), 24);
    }

    #[test]
    fn out_of_range_channels_are_ignored() {
        let mut spectrum = Spectrum::new();
        spectrum.apply(200, true);
        assert_eq!(spectrum.peak_channel(), None);
    }

    #[test]
    fn peak_holds_then_decays() {
        let mut spectrum = Spectrum::new();
        for _ in 0..8 {
            spectrum.apply(6, true);
        }
        let peak = spectrum.peak_level(6);
        assert!(peak > spectrum.level(6) || peak == spectrum.level(6));
        for _ in 0..8 {
            spectrum.apply(6, false);
        }
        assert!(spectrum.peak_level(6) < peak);
        assert!(spectrum.peak_level(6) > spectrum.level(6));
    }

    #[test]
    fn peak_channel_finds_the_busiest_carrier() {
        let mut spectrum = Spectrum::new();
        for _ in 0..6 {
            spectrum.apply(20, false);
            spectrum.apply(75, true);
        }
        assert_eq!(spectrum.peak_channel(), Some(75));
        let (channel, freq, percent) = spectrum.readout();
        assert_eq!(channel, 75);
        assert_eq!(freq, 2475);
        assert!(percent > 50);
    }

    #[test]
    fn envelope_scales_and_interpolates() {
        let mut spectrum = Spectrum::new();
        for _ in 0..8 {
            spectrum.apply(0, true);
        }
        let mut out = [0u8; 32];
        spectrum.envelope(&mut out);
        assert!(out[0] > 80, "start of the envelope is hot");
        assert!(out[31] < 10, "end of the envelope is quiet");
        // Monotonic decreasing across the interpolated band.
        assert!(out.windows(2).all(|w| w[0] >= w[1]));

        let single = &mut [0u8; 1];
        spectrum.envelope(single);
        assert_eq!(single[0], out[0]);
    }

    #[test]
    fn waterfall_rows_are_filled_on_sweep_completion() {
        let mut spectrum = Spectrum::new();
        for _ in 0..8 {
            spectrum.apply(30, true);
        }
        assert_eq!(spectrum.sweeps(), 0);
        spectrum.finish_sweep();
        assert_eq!(spectrum.sweeps(), 1);
        let rows = spectrum.waterfall();
        assert!(rows[3].iter().any(|v| *v > 0));
        spectrum.finish_sweep();
        assert_eq!(spectrum.sweeps(), 2);
    }

    #[test]
    fn clear_resets_state() {
        let mut spectrum = Spectrum::new();
        spectrum.apply(1, true);
        spectrum.finish_sweep();
        spectrum.clear();
        assert_eq!(spectrum.level(1), 0);
        assert_eq!(spectrum.peak_level(1), 0);
        assert_eq!(spectrum.sweeps(), 0);
    }
}

//! Time, timestamps and rate accounting.
//!
//! Firmware supplies a monotonic millisecond clock; everything here is pure so
//! PCAP timestamps, job durations and drop-rate math are testable on the host.

use alloc::string::String;

/// Milliseconds since boot (monotonic).
pub type Millis = u64;

/// Absolute capture timestamp. ESP32 has no RTC battery backup by default, so
/// `secs` is derived from uptime plus a boot wall-clock epoch when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp {
    pub secs: u64,
    pub micros: u32,
}

impl Timestamp {
    pub const ZERO: Self = Self {
        secs: 0,
        micros: 0,
    };

    pub const fn new(secs: u64, micros: u32) -> Self {
        Self { secs, micros }
    }

    /// Build from microseconds since the epoch.
    pub const fn from_micros(total: u64) -> Self {
        Self {
            secs: total / 1_000_000,
            micros: (total % 1_000_000) as u32,
        }
    }

    /// Build from uptime in milliseconds plus a boot epoch in seconds.
    pub const fn from_uptime(boot_secs: u64, uptime_ms: Millis) -> Self {
        Self {
            secs: boot_secs + uptime_ms / 1000,
            micros: ((uptime_ms % 1000) * 1000) as u32,
        }
    }

    pub const fn to_micros(self) -> u64 {
        self.secs * 1_000_000 + self.micros as u64
    }

    /// `HH:MM:SS` for the status bar.
    pub fn clock_string(self) -> String {
        let day_secs = self.secs % 86_400;
        alloc::format!(
            "{:02}:{:02}:{:02}",
            day_secs / 3600,
            (day_secs % 3600) / 60,
            day_secs % 60
        )
    }
}

/// Elapsed-time formatter (`1h02m`, `9m30s`, `42s`).
pub fn format_duration(ms: Millis) -> String {
    let secs = ms / 1000;
    if secs >= 3600 {
        alloc::format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        alloc::format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        alloc::format!("{secs}s")
    }
}

/// Rolling event-rate meter with a one-second window.
#[derive(Debug, Clone, Copy, Default)]
pub struct RateMeter {
    window_start: Millis,
    events: u32,
    last_rate: u32,
    total: u32,
}

impl RateMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `count` events at `now_ms`. Returns the current rate once the
    /// window closes, otherwise `None`.
    pub fn add(&mut self, count: u32, now_ms: Millis) -> Option<u32> {
        self.events = self.events.saturating_add(count);
        self.total = self.total.saturating_add(count);
        let elapsed = now_ms.saturating_sub(self.window_start);
        if elapsed >= 1000 {
            self.last_rate = (u64::from(self.events) * 1000 / elapsed.max(1)) as u32;
            self.events = 0;
            self.window_start = now_ms;
            Some(self.last_rate)
        } else {
            None
        }
    }

    pub fn rate(&self) -> u32 {
        self.last_rate
    }

    pub fn total(&self) -> u32 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_split_correctly() {
        let ts = Timestamp::from_micros(1_234_567);
        assert_eq!(ts.secs, 1);
        assert_eq!(ts.micros, 234_567);
        assert_eq!(ts.to_micros(), 1_234_567);
        assert_eq!(Timestamp::from_uptime(1000, 1500), Timestamp::new(1001, 500_000));
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(42_000), "42s");
        assert_eq!(format_duration(570_000), "9m30s");
        assert_eq!(format_duration(3_780_000), "1h03m");
    }

    #[test]
    fn rate_meter_uses_one_second_window() {
        let mut meter = RateMeter::new();
        for _ in 0..50 {
            assert_eq!(meter.add(1, 0), None);
        }
        // 50 events over 1000 ms = 50/s
        assert_eq!(meter.add(0, 1000), Some(50));
        assert_eq!(meter.rate(), 50);
        assert_eq!(meter.total(), 50);
    }

    #[test]
    fn clock_string_is_stable() {
        assert_eq!(Timestamp::new(3_661, 0).clock_string(), "01:01:01");
    }
}

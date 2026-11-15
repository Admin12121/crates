//! Typed cross-feature events.
//!
//! Features never import each other's views or controllers. They publish small
//! typed events; the app runtime decides what to render. Payloads stay compact so
//! publishing from a radio callback never allocates.

use crate::hardware::DeviceClass;
use crate::job::OpId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Debug => "DBG",
            Self::Info => "INF",
            Self::Warn => "WRN",
            Self::Error => "ERR",
        }
    }
}

/// One event on the shared bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeckEvent {
    Log {
        level: LogLevel,
        message: &'static str,
    },
    JobStarted {
        id: OpId,
        owner: &'static str,
    },
    JobProgress {
        id: OpId,
        done: u32,
        total: u32,
        dropped: u32,
    },
    JobFinished {
        id: OpId,
        state: crate::job::JobState,
    },
    /// Registry row changed (probe finished, device removed, error cleared).
    DeviceChanged {
        class: DeviceClass,
        ready: bool,
    },
    /// A capture or scan queue overflowed; counters are honest, never hidden.
    QueueSaturated {
        dropped: u32,
    },
    /// Persistent storage became unavailable mid-operation.
    StorageUnavailable {
        operation: &'static str,
    },
}

impl DeckEvent {
    /// One-line log rendering for the on-device log ring and UART mirror.
    pub fn log_line(&self) -> alloc::string::String {
        use alloc::format;
        match self {
            Self::Log { level, message } => format!("[{}] {message}", level.tag()),
            Self::JobStarted { id, owner } => format!("[INF] op {id} start: {owner}"),
            Self::JobProgress {
                id,
                done,
                total,
                dropped,
            } => format!("[DBG] op {id} {done}/{total} dropped {dropped}"),
            Self::JobFinished { id, state } => format!("[INF] op {id} {}", state.label()),
            Self::DeviceChanged { class, ready } => format!(
                "[INF] {} {}",
                class.label(),
                if *ready { "ready" } else { "unavailable" }
            ),
            Self::QueueSaturated { dropped } => format!("[WRN] queue saturated, {dropped} dropped"),
            Self::StorageUnavailable { operation } => {
                format!("[ERR] storage unavailable during {operation}")
            }
        }
    }
}

/// Bounded in-memory log ring used by the diagnostics screen and the UART mirror.
#[derive(Debug)]
pub struct LogRing<const N: usize> {
    lines: [Option<alloc::string::String>; N],
    head: usize,
    len: usize,
    dropped: u32,
}

impl<const N: usize> Default for LogRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LogRing<N> {
    pub const fn new() -> Self {
        Self {
            lines: [const { None }; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, line: alloc::string::String) {
        if self.len == N {
            // Overwrite the oldest line: a log ring must keep the newest evidence.
            self.lines[self.head] = Some(line);
            self.head = (self.head + 1) % N;
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let idx = (self.head + self.len) % N;
        self.lines[idx] = Some(line);
        self.len += 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = &alloc::string::String> {
        (0..self.len).filter_map(move |i| self.lines[(self.head + i) % N].as_ref())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn dropped(&self) -> u32 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn event_lines_are_greppable() {
        let event = DeckEvent::DeviceChanged {
            class: DeviceClass::Nrf24,
            ready: false,
        };
        assert_eq!(event.log_line(), "[INF] nRF24L01 radio unavailable");
    }

    #[test]
    fn log_ring_keeps_newest_lines() {
        let mut ring: LogRing<3> = LogRing::new();
        for i in 0..5 {
            ring.push(alloc::format!("line {i}"));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.dropped(), 2);
        let lines: alloc::vec::Vec<&String> = ring.iter().collect();
        assert_eq!(lines[0], "line 2");
        assert_eq!(lines[2], "line 4");
    }
}

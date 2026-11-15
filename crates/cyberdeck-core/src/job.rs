//! Operation management: identifiers, cancellation, resource leases, bounded
//! queues and honest progress accounting.
//!
//! Controllers own lifecycle boundaries; this module owns *state*. It is shared by
//! every capability group so that "start", "stop", "busy" and "cancelled" mean the
//! same thing everywhere and cannot drift per feature.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::error::DeckError;
use crate::hardware::DeviceClass;

/// Maximum concurrently tracked jobs.
pub const MAX_JOBS: usize = 6;

/// Monotonic operation identifier.
pub type OpId = u32;

/// Cooperative cancellation flag, cloned into workers.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// `Err(Cancelled)` when the operator asked to stop.
    pub fn check(&self) -> Result<(), DeckError> {
        if self.is_cancelled() {
            Err(DeckError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Lifecycle of an operation. Payload-carrying variants keep failure detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Idle,
    Running,
    Paused,
    Succeeded,
    Failed(DeckError),
    Cancelled,
}

impl JobState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed(_) | Self::Cancelled)
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Succeeded => "complete",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Progress counters rendered by views. `total == 0` means indeterminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    pub done: u32,
    pub total: u32,
    pub failures: u32,
}

impl Progress {
    pub const fn new(done: u32, total: u32) -> Self {
        Self {
            done,
            total,
            failures: 0,
        }
    }

    /// Completion in percent, `None` when indeterminate.
    pub fn percent(&self) -> Option<u8> {
        if self.total == 0 {
            return None;
        }
        let pct = (u64::from(self.done) * 100 / u64::from(self.total)).min(100);
        Some(pct as u8)
    }
}

/// Exclusive hardware resources leased to one operation at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resource {
    Wifi,
    Ble,
    Nrf24,
    Usb,
    Sd,
}

impl Resource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wifi => "Wi-Fi radio",
            Self::Ble => "Bluetooth radio",
            Self::Nrf24 => "nRF24L01 radio",
            Self::Usb => "USB device",
            Self::Sd => "microSD card",
        }
    }

    /// Device class to mark busy in the peripheral registry.
    pub const fn device(self) -> DeviceClass {
        match self {
            Self::Wifi => DeviceClass::WifiRadio,
            Self::Ble => DeviceClass::BleRadio,
            Self::Nrf24 => DeviceClass::Nrf24,
            Self::Usb => DeviceClass::UsbDevice,
            Self::Sd => DeviceClass::SdCard,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Wifi => 1 << 0,
            Self::Ble => 1 << 1,
            Self::Nrf24 => 1 << 2,
            Self::Usb => 1 << 3,
            Self::Sd => 1 << 4,
        }
    }
}

/// One running operation.
#[derive(Debug)]
pub struct Job {
    pub id: OpId,
    pub owner: &'static str,
    pub state: JobState,
    pub token: CancelToken,
    pub progress: Progress,
    pub started_ms: u64,
    leases: u8,
    /// Secondary label for the status line (target, channel, script name...).
    pub detail: Option<alloc::string::String>,
}

impl Job {
    pub fn leases_resource(&self, resource: Resource) -> bool {
        self.leases & resource.bit() != 0
    }
}

/// Bounded job table with exclusive resource leases.
#[derive(Debug, Default)]
pub struct JobManager {
    jobs: Vec<Job>,
    next_id: OpId,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next_id: 1,
        }
    }

    /// Start an operation owning `resources`.
    ///
    /// Fails with `Busy` when another operation already holds one of them, naming
    /// the owner so the UI can tell the operator what to stop.
    pub fn begin(
        &mut self,
        owner: &'static str,
        resources: &[Resource],
        now_ms: u64,
    ) -> Result<(OpId, CancelToken), DeckError> {
        for resource in resources {
            if let Some(job) = self.jobs.iter().find(|j| {
                j.leases_resource(*resource) && matches!(j.state, JobState::Running | JobState::Paused)
            }) {
                return Err(DeckError::Busy {
                    resource: resource.label(),
                    owner: job.owner,
                });
            }
        }
        // Reap finished jobs before allocating a slot.
        self.jobs.retain(|j| !j.state.is_terminal());
        if self.jobs.len() >= MAX_JOBS {
            return Err(DeckError::Busy {
                resource: "job slots",
                owner: "other operations",
            });
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let token = CancelToken::new();
        let leases = resources.iter().fold(0u8, |acc, r| acc | r.bit());
        self.jobs.push(Job {
            id,
            owner,
            state: JobState::Running,
            token: token.clone(),
            progress: Progress::default(),
            started_ms: now_ms,
            leases,
            detail: None,
        });
        Ok((id, token))
    }

    pub fn set_detail(&mut self, id: OpId, detail: &str) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            job.detail = Some(alloc::string::String::from(detail));
        }
    }

    pub fn set_progress(&mut self, id: OpId, progress: Progress) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            job.progress = progress;
        }
    }

    pub fn pause(&mut self, id: OpId) -> Result<(), DeckError> {
        let job = self
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(DeckError::Internal {
                reason: "unknown job",
            })?;
        if job.state == JobState::Running {
            job.state = JobState::Paused;
        }
        Ok(())
    }

    pub fn resume(&mut self, id: OpId) -> Result<(), DeckError> {
        let job = self
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(DeckError::Internal {
                reason: "unknown job",
            })?;
        if job.state == JobState::Paused {
            job.state = JobState::Running;
        }
        Ok(())
    }

    /// Request cancellation; the worker observes the token and finishes.
    pub fn cancel(&mut self, id: OpId) {
        if let Some(job) = self.jobs.iter().find(|j| j.id == id) {
            job.token.cancel();
        }
    }

    /// Cancel every running job (used by the global "stop all" control).
    pub fn cancel_all(&mut self) {
        for job in &self.jobs {
            job.token.cancel();
        }
    }

    /// Record the terminal state, releasing the leases.
    pub fn finish(&mut self, id: OpId, state: JobState) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            job.state = state;
            job.leases = 0;
        }
    }

    pub fn get(&self, id: OpId) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// The first running/paused job, used to route input to the active tool.
    pub fn active(&self) -> Option<&Job> {
        self.jobs
            .iter()
            .find(|j| matches!(j.state, JobState::Running | JobState::Paused))
    }

    pub fn active_id(&self) -> Option<OpId> {
        self.active().map(|j| j.id)
    }

    pub fn is_busy(&self, resource: Resource) -> bool {
        self.jobs.iter().any(|j| {
            j.leases_resource(resource) && matches!(j.state, JobState::Running | JobState::Paused)
        })
    }
}

/// Fixed-capacity FIFO used on hot paths (sniffer callbacks, BLE reports, RF rows).
///
/// Never allocates and never blocks; a full queue drops the *newest* item and
/// counts it, so the UI can report saturation honestly instead of stalling the
/// radio callback.
#[derive(Debug)]
pub struct BoundedQueue<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    len: usize,
    dropped: u32,
    pushed: u32,
}

impl<T, const N: usize> Default for BoundedQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> BoundedQueue<T, N> {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; N],
            head: 0,
            len: 0,
            dropped: 0,
            pushed: 0,
        }
    }

    pub fn push(&mut self, item: T) -> bool {
        self.pushed = self.pushed.saturating_add(1);
        if self.len == N {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let idx = (self.head + self.len) % N;
        self.slots[idx] = Some(item);
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        item
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

    pub fn pushed(&self) -> u32 {
        self.pushed
    }

    pub fn reset_counters(&mut self) {
        self.dropped = 0;
        self.pushed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_are_exclusive_and_name_the_owner() {
        let mut mgr = JobManager::new();
        let (id, _) = mgr.begin("Deauth Test", &[Resource::Wifi], 0).unwrap();
        let err = mgr
            .begin("Packet Capture", &[Resource::Wifi], 1)
            .unwrap_err();
        assert_eq!(
            err,
            DeckError::Busy {
                resource: "Wi-Fi radio",
                owner: "Deauth Test"
            }
        );
        mgr.finish(id, JobState::Succeeded);
        // Leases are released on finish, so the next operation can start.
        assert!(mgr.begin("Packet Capture", &[Resource::Wifi], 2).is_ok());
    }

    #[test]
    fn cancel_token_is_observed_by_worker() {
        let mut mgr = JobManager::new();
        let (id, token) = mgr.begin("Beacon Spam", &[Resource::Wifi], 0).unwrap();
        assert!(token.check().is_ok());
        mgr.cancel(id);
        assert_eq!(token.check(), Err(DeckError::Cancelled));
    }

    #[test]
    fn progress_percent_is_bounded() {
        assert_eq!(Progress::new(0, 0).percent(), None);
        assert_eq!(Progress::new(5, 10).percent(), Some(50));
        assert_eq!(Progress::new(20, 10).percent(), Some(100));
    }

    #[test]
    fn bounded_queue_drops_and_counts_instead_of_blocking() {
        let mut q: BoundedQueue<u8, 4> = BoundedQueue::new();
        for i in 0..6 {
            q.push(i);
        }
        assert_eq!(q.len(), 4);
        assert_eq!(q.dropped(), 2);
        assert_eq!(q.pushed(), 6);
        assert_eq!(q.pop(), Some(0));
        assert_eq!(q.pop(), Some(1));
    }

    #[test]
    fn bounded_queue_wraps_without_loss_below_capacity() {
        let mut q: BoundedQueue<u8, 3> = BoundedQueue::new();
        q.push(1);
        q.push(2);
        assert_eq!(q.pop(), Some(1));
        q.push(3);
        q.push(4);
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), Some(4));
    }
}

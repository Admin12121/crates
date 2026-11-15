//! Wi-Fi radio actor: scanning, monitor capture and management-frame injection.
//!
//! The ESP32-S3 has one 2.4 GHz front end, so the radio is owned by a single actor
//! task. The UI submits a command through [`WIFI_COMMAND`] and reads bounded state
//! from [`WIFI_STATE`]; no packet processing ever runs on the UI path.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use critical_section::Mutex;
use cyberdeck_core::net::MacAddr;
use cyberdeck_core::wifi::ap::Ssid;
use cyberdeck_core::wifi::attack::{AttackMode, AttackPlan, AttackRunner};
use cyberdeck_core::wifi::frame::{self, FrameBuffer};
use esp_radio::wifi::ap::AccessPointInfo;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::{Config, WifiController};
use esp_radio::wifi::sta::StationConfig;

/// Largest frame retained from the promiscuous callback.
pub const SNAP_LEN: usize = 512;
const RX_SLOTS: usize = 8;
/// Access points kept in the scan table.
pub const MAX_APS: usize = 24;

/// One captured frame, copied out of the radio callback.
#[derive(Clone, Copy)]
pub struct CapturedFrame {
    pub len: u16,
    pub channel: u8,
    pub rssi: i8,
    pub data: [u8; SNAP_LEN],
}

impl CapturedFrame {
    const EMPTY: Self = Self {
        len: 0,
        channel: 0,
        rssi: 0,
        data: [0; SNAP_LEN],
    };

    pub fn bytes(&self) -> &[u8] {
        &self.data[..usize::from(self.len).min(SNAP_LEN)]
    }
}

struct RxRing {
    slots: [CapturedFrame; RX_SLOTS],
    head: usize,
    tail: usize,
    dropped: u32,
}

impl RxRing {
    const fn new() -> Self {
        Self {
            slots: [CapturedFrame::EMPTY; RX_SLOTS],
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, frame: CapturedFrame) {
        let next = (self.head + 1) % RX_SLOTS;
        if next == self.tail {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.slots[self.head] = frame;
        self.head = next;
    }

    fn pop(&mut self) -> Option<CapturedFrame> {
        if self.head == self.tail {
            return None;
        }
        let frame = self.slots[self.tail];
        self.tail = (self.tail + 1) % RX_SLOTS;
        Some(frame)
    }
}

static RX: Mutex<RefCell<RxRing>> = Mutex::new(RefCell::new(RxRing::new()));

/// Promiscuous callback: copy the frame and return immediately.
fn receive(packet: esp_radio::wifi::sniffer::PromiscuousPkt) {
    let data = packet.data;
    let len = usize::from(packet.len).min(data.len()).min(SNAP_LEN);
    let mut frame = CapturedFrame::EMPTY;
    frame.len = len as u16;
    frame.data[..len].copy_from_slice(&data[..len]);
    frame.channel = packet.rx_cntl.channel as u8;
    frame.rssi = packet.rx_cntl.rssi as i8;
    critical_section::with(|cs| RX.borrow_ref_mut(cs).push(frame));
}

/// One access-point row for the UI.
#[derive(Clone)]
pub struct ApRow {
    pub ssid: String,
    pub bssid: MacAddr,
    pub channel: u8,
    pub rssi: i8,
    pub security: &'static str,
}

/// Radio state shared with the UI.
pub struct WifiState {
    pub busy: bool,
    pub status: String,
    pub aps: Vec<ApRow>,
    pub frames: u32,
    pub bytes: u64,
    pub dropped: u32,
    pub channel: u8,
    pub last_frame: Option<CapturedFrame>,
}

impl WifiState {
    const fn new() -> Self {
        Self {
            busy: false,
            status: String::new(),
            aps: Vec::new(),
            frames: 0,
            bytes: 0,
            dropped: 0,
            channel: 1,
            last_frame: None,
        }
    }
}

static WIFI_STATE: Mutex<RefCell<WifiState>> = Mutex::new(RefCell::new(WifiState::new()));
static WIFI_COMMAND: Mutex<RefCell<Option<WifiCommand>>> = Mutex::new(RefCell::new(None));

/// Work requested by the UI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WifiCommand {
    Scan,
    Capture { channel: u8 },
    Attack { mode: AttackMode, channel: u8 },
    Stop,
}

/// Submit a command; returns false when the actor is still busy.
pub fn submit(command: WifiCommand) -> bool {
    critical_section::with(|cs| {
        let mut slot = WIFI_COMMAND.borrow_ref_mut(cs);
        if slot.is_some() {
            return false;
        }
        *slot = Some(command);
        true
    })
}

fn take_command() -> Option<WifiCommand> {
    critical_section::with(|cs| WIFI_COMMAND.borrow_ref_mut(cs).take())
}

fn set_status(status: &str) {
    critical_section::with(|cs| {
        let mut state = WIFI_STATE.borrow_ref_mut(cs);
        state.status.clear();
        state.status.push_str(status);
    });
}

fn set_busy(busy: bool) {
    critical_section::with(|cs| WIFI_STATE.borrow_ref_mut(cs).busy = busy);
}

/// Snapshot of the shared state for rendering.
pub fn snapshot() -> (String, Vec<ApRow>, u32, u32, u8, Option<CapturedFrame>) {
    critical_section::with(|cs| {
        let state = WIFI_STATE.borrow_ref(cs);
        (
            state.status.clone(),
            state.aps.clone(),
            state.frames,
            state.dropped,
            state.channel,
            state.last_frame,
        )
    })
}

/// Convert an esp-radio scan result into the UI row.
fn to_row(info: &AccessPointInfo) -> ApRow {
    ApRow {
        ssid: info.ssid.as_str().into(),
        bssid: MacAddr::new(info.bssid),
        channel: info.channel,
        rssi: info.signal_strength,
        security: info.auth_method.map(security_label).unwrap_or("?"),
    }
}

fn security_label(method: esp_radio::wifi::AuthenticationMethod) -> &'static str {
    use esp_radio::wifi::AuthenticationMethod as A;
    match method {
        A::None => "OPEN",
        A::Wep => "WEP",
        A::Wpa => "WPA",
        A::Wpa2Personal => "WPA2",
        A::Wpa2Wpa3Personal => "WPA2/3",
        A::Wpa3Personal => "WPA3",
        A::Wpa2Enterprise => "WPA2-ENT",
        A::Wpa3Enterprise => "WPA3-ENT",
        _ => "?",
    }
}

/// The radio actor body. Owns the controller for the whole program lifetime.
pub async fn run(controller: WifiController<'static>) -> ! {
    let mut controller = controller;
    if let Err(error) = controller.set_config(&Config::Station(StationConfig::default())) {
        set_status(&alloc::format!("station config failed: {error:?}"));
    }
    loop {
        match take_command() {
            Some(WifiCommand::Scan) => {
                set_busy(true);
                set_status("scanning");
                match controller.scan_async(&ScanConfig::default()).await {
                    Ok(results) => {
                        let mut rows: Vec<ApRow> = results.iter().map(to_row).collect();
                        rows.sort_by_key(|row| -i16::from(row.rssi));
                        rows.truncate(MAX_APS);
                        let count = rows.len();
                        critical_section::with(|cs| {
                            let mut state = WIFI_STATE.borrow_ref_mut(cs);
                            state.aps = rows;
                            state.status = alloc::format!("{count} access points");
                        });
                    }
                    Err(error) => set_status(&alloc::format!("scan failed: {error:?}")),
                }
                set_busy(false);
            }
            Some(WifiCommand::Capture { channel }) => {
                capture_session(&mut controller, channel).await;
            }
            Some(WifiCommand::Attack { mode, channel }) => {
                attack_session(&mut controller, mode, channel).await;
            }
            Some(WifiCommand::Stop) => {}
            None => {}
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
    }
}

fn stop_requested() -> bool {
    critical_section::with(|cs| {
        let state = WIFI_STATE.borrow_ref(cs);
        state.status == "stopping"
    })
}

fn reset_counters(channel: u8) {
    critical_section::with(|cs| {
        let mut state = WIFI_STATE.borrow_ref_mut(cs);
        state.frames = 0;
        state.bytes = 0;
        state.dropped = 0;
        state.channel = channel;
        state.last_frame = None;
        state.busy = true;
    });
    critical_section::with(|cs| {
        let mut ring = RX.borrow_ref_mut(cs);
        ring.head = 0;
        ring.tail = 0;
        ring.dropped = 0;
    });
}

fn finish_session(status: &str) {
    critical_section::with(|cs| {
        let mut state = WIFI_STATE.borrow_ref_mut(cs);
        state.busy = false;
        state.status.clear();
        state.status.push_str(status);
    });
}

async fn capture_session(controller: &mut WifiController<'static>, channel: u8) {
    reset_counters(channel);
    set_status("monitor capture");
    let mut sniffer = controller.sniffer();
    if let Err(error) = sniffer.set_promiscuous_mode(true) {
        finish_session(&alloc::format!("sniffer unavailable: {error:?}"));
        return;
    }
    sniffer.set_receive_cb(receive);
    let mut last_total = 0u32;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(20)).await;
        let mut latest = None;
        let mut drained = 0u32;
        critical_section::with(|cs| {
            let mut ring = RX.borrow_ref_mut(cs);
            while let Some(frame) = ring.pop() {
                drained += 1;
                latest = Some(frame);
            }
            let mut state = WIFI_STATE.borrow_ref_mut(cs);
            state.frames = state.frames.saturating_add(drained);
            state.dropped = ring.dropped;
            if let Some(frame) = latest {
                state.bytes = state.bytes.saturating_add(u64::from(frame.len));
                state.last_frame = Some(frame);
            }
        });
        if drained > 0 {
            last_total = last_total.saturating_add(drained);
        }
        if stop_requested() {
            break;
        }
    }
    let _ = sniffer.set_promiscuous_mode(false);
    finish_session(&alloc::format!("capture stopped: {last_total} frames"));
}

async fn attack_session(controller: &mut WifiController<'static>, mode: AttackMode, channel: u8) {
    reset_counters(channel);
    let plan = AttackPlan::new(mode, channel);
    let mut runner = AttackRunner::new(plan, 0xC1BE_2DEC, 0);
    set_status(mode.label());
    let mut sniffer = controller.sniffer();
    let mut frame = FrameBuffer::new();
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
        let now_us = embassy_time::Instant::now().as_micros();
        while let Some(_kind) = runner.next_frame(now_us, &mut frame) {
            if sniffer.send_raw_frame(false, frame.as_slice(), true).is_err() {
                finish_session("transmit rejected by driver");
                return;
            }
            critical_section::with(|cs| {
                let mut state = WIFI_STATE.borrow_ref_mut(cs);
                state.frames = runner.frames();
                state.last_frame = None;
            });
        }
        if runner.should_stop(embassy_time::Instant::now().as_millis()) || stop_requested() {
            break;
        }
    }
    finish_session(&alloc::format!("{} frames sent", runner.frames()));
}

/// Frame kind label for the packet inspector.
pub fn describe(frame: &[u8]) -> String {
    cyberdeck_core::packet::classify(frame).0.label().into()
}

/// Convenience for the diagnostics screen.
pub fn ssid_display(ssid: &Ssid) -> String {
    ssid.display()
}

/// Channel list used by the hopping capture.
pub const CHANNELS: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Build a deauth frame for the lab acceptance test.
pub fn lab_deauth(bssid: MacAddr) -> FrameBuffer {
    frame::broadcast_deauth(bssid, frame::reason::CLASS3_FROM_UNASSOC)
}

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams, LeSetScanEnable, LeSetScanParams};
use bt_hci::controller::{Controller, ControllerCmdSync, ExternalController};
use bt_hci::FromHciBytes;
use bt_hci::event::le::LeAdvertisingReport;
use bt_hci::param::{
    AdvChannelMap, AdvKind, AddrKind, BdAddr, Duration, LeScanKind, ScanningFilterPolicy,
};
use critical_section::Mutex;
use cyberdeck_core::ble::ad::{AdvReport, BleAddress};
use cyberdeck_core::ble::spam::{SpamCampaign, SpamRotator};
use cyberdeck_core::ble::vendor::classify;
use esp_radio::ble::controller::BleConnector;

const MAX_DEVICES: usize = 24;
const SCAN_INTERVAL_MS: u32 = 100;
const SCAN_WINDOW_MS: u32 = 50;
const ADV_INTERVAL_MS: u32 = 100;

#[derive(Clone)]
pub struct BleDevice {
    pub address: String,
    pub name: String,
    pub rssi: i8,
    pub kind: &'static str,
    pub detail: String,
}

pub struct BleState {
    pub online: bool,
    busy: bool,
    pub status: String,
    pub devices: Vec<BleDevice>,
    pub frames: u32,
    pub dropped: u32,
}

impl BleState {
    const fn new() -> Self {
        Self {
            online: false,
            busy: false,
            status: String::new(),
            devices: Vec::new(),
            frames: 0,
            dropped: 0,
        }
    }
}

static STATE: Mutex<RefCell<BleState>> = Mutex::new(RefCell::new(BleState::new()));
static COMMAND: Mutex<RefCell<Option<BleCommand>>> = Mutex::new(RefCell::new(None));

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BleCommand {
    Scan,
    Advertise(SpamCampaign),
    Stop,
}

pub fn submit(command: BleCommand) -> bool {
    critical_section::with(|cs| {
        let mut slot = COMMAND.borrow_ref_mut(cs);
        if slot.is_some() {
            return false;
        }
        *slot = Some(command);
        true
    })
}

pub fn online() {
    critical_section::with(|cs| STATE.borrow_ref_mut(cs).online = true);
}

fn take_command() -> Option<BleCommand> {
    critical_section::with(|cs| COMMAND.borrow_ref_mut(cs).take())
}

fn set_status(text: &str) {
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.status.clear();
        state.status.push_str(text);
    });
}

pub fn snapshot() -> (String, Vec<BleDevice>, u32, u32) {
    critical_section::with(|cs| {
        let state = STATE.borrow_ref(cs);
        (
            state.status.clone(),
            state.devices.clone(),
            state.frames,
            state.dropped,
        )
    })
}

fn stop_requested() -> bool {
    critical_section::with(|cs| STATE.borrow_ref(cs).status == "stopping")
}

fn record(report: &AdvReport) {
    let matched = classify(report);
    let address = report.address.display();
    let name = report.name.clone().unwrap_or_default();
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.frames = state.frames.saturating_add(1);
        if let Some(slot) = state
            .devices
            .iter_mut()
            .find(|device| device.address == address)
        {
            slot.rssi = report.rssi;
            if !name.is_empty() {
                slot.name = name;
            }
            slot.kind = matched.kind.label();
            return;
        }
        if state.devices.len() >= MAX_DEVICES {
            state.devices.remove(0);
            state.dropped = state.dropped.saturating_add(1);
        }
        state.devices.push(BleDevice {
            address,
            name,
            rssi: report.rssi,
            kind: matched.kind.label(),
            detail: matched.vendor.into(),
        });
    });
}

fn record_packet(report: &LeAdvertisingReport<'_>) {
    for entry in report.reports.iter() {
        let Ok(entry) = entry else { continue };
        let mut address = [0u8; 6];
        address.copy_from_slice(&entry.addr.raw()[..6]);
        record(&AdvReport::parse(
            BleAddress::new(address),
            entry.rssi,
            entry.data,
            entry.addr_kind.as_raw() & 0x01 != 0,
            0,
        ));
    }
}

type BleController = ExternalController<BleConnector<'static>, 1>;

pub async fn run(controller: BleController) -> ! {
    loop {
        match take_command() {
            Some(BleCommand::Scan) => scan_session(&controller).await,
            Some(BleCommand::Advertise(campaign)) => advertise_session(&controller, campaign).await,
            Some(BleCommand::Stop) => {}
            None => {}
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
    }
}

async fn scan_session(controller: &BleController) {
    set_status("scanning");
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.devices.clear();
        state.frames = 0;
        state.dropped = 0;
        state.busy = true;
    });
    let params = LeSetScanParams::new(
        LeScanKind::Passive,
        Duration::from_millis(SCAN_INTERVAL_MS),
        Duration::from_millis(SCAN_WINDOW_MS),
        AddrKind::new(0),
        ScanningFilterPolicy::BasicUnfiltered,
    );
    if let Err(_) = controller.exec(&params).await {
        set_status("scan parameters rejected");
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).busy = false);
        return;
    }
    if controller.exec(&LeSetScanEnable::new(true, true)).await.is_err() {
        set_status("scan enable rejected");
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).busy = false);
        return;
    }
    let mut buffer = [0u8; 260];
    while !stop_requested() {
        match embassy_time::with_timeout(
            embassy_time::Duration::from_millis(200),
            controller.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(bt_hci::ControllerToHostPacket::Event(packet))) => {
                if let Ok(report) = LeAdvertisingReport::from_hci_bytes_complete(packet.data) {
                    if !report.reports.is_empty() {
                        record_packet(&report);
                    }
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                set_status("HCI read failed");
                break;
            }
            Err(_) => {}
        }
    }
    let _ = controller.exec(&LeSetScanEnable::new(false, false)).await;
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.busy = false;
        state.status = alloc::format!("scan stopped: {} devices", state.devices.len());
    });
}

async fn advertise_session(controller: &BleController, campaign: SpamCampaign) {
    set_status(campaign.label());
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.busy = true;
        state.frames = 0;
    });
    let params = LeSetAdvParams::new(
        Duration::from_millis(ADV_INTERVAL_MS),
        Duration::from_millis(ADV_INTERVAL_MS),
        AdvKind::AdvNonconnInd,
        AddrKind::new(1),
        AddrKind::new(0),
        BdAddr::new([0u8; 6]),
        AdvChannelMap::new()
            .enable_channel_37(true)
            .enable_channel_38(true)
            .enable_channel_39(true),
        bt_hci::param::AdvFilterPolicy::Unfiltered,
    );
    if controller.exec(&params).await.is_err() {
        set_status("advertising parameters rejected");
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).busy = false);
        return;
    }
    let mut rotator = SpamRotator::new(campaign, 0x5EED_1234);
    let mut builder = cyberdeck_core::ble::ad::AdvBuilder::new();
    while !stop_requested() {
        if !rotator.next_payload(&mut builder) {
            break;
        }
        let mut data = [0u8; 31];
        let slice = builder.as_slice();
        let len = slice.len().min(31);
        data[..len].copy_from_slice(&slice[..len]);
        if controller.exec(&LeSetAdvData::new(len as u8, data)).await.is_err() {
            set_status("advertising data rejected");
            break;
        }
        if controller.exec(&LeSetAdvEnable::new(true)).await.is_err() {
            set_status("advertising enable rejected");
            break;
        }
        critical_section::with(|cs| {
            let mut state = STATE.borrow_ref_mut(cs);
            state.frames = rotator.frames();
        });
        embassy_time::Timer::after(embassy_time::Duration::from_millis(u64::from(ADV_INTERVAL_MS))).await;
    }
    let _ = controller.exec(&LeSetAdvEnable::new(false)).await;
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.busy = false;
        state.status = alloc::format!("{} frames advertised", state.frames);
    });
}

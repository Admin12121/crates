use alloc::string::String;
use core::cell::RefCell;

use critical_section::Mutex;
use cyberdeck_core::hid::ducky;
use cyberdeck_core::hid::engine::{HidEngine, Output};
use cyberdeck_core::hid::Layout;
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::class::hid::{Config as HidConfig, HidWriter, State as HidState};
use embassy_usb::{Builder, Config as UsbConfig};

const POLL_MS: u64 = 10;

/// Report IDs used by the composite descriptor below.
const REPORT_KEYBOARD: u8 = 1;
const REPORT_CONSUMER: u8 = 2;
const REPORT_MOUSE: u8 = 3;

const DEMO_SCRIPT: &str = "\
DELAY 1200\n\
TEXT CyberDeck HID ready\n\
ENTER\n\
DELAY 400\n\
TEXT https://example.com\n\
ENTER";

/// Keyboard (8-byte), consumer (2-byte) and mouse (4-byte) reports behind report IDs.
const REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x85, REPORT_KEYBOARD, //   Report ID
    0x05, 0x07, //   Usage Page (Keyboard)
    0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, //   modifiers
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, //   reserved byte
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
    0x81, 0x00, //   six keycodes
    0xC0, // End Collection
    0x05, 0x0C, // Usage Page (Consumer)
    0x09, 0x01, // Usage (Consumer Control)
    0xA1, 0x01, // Collection (Application)
    0x85, REPORT_CONSUMER, //   Report ID
    0x15, 0x00, 0x26, 0xFF, 0x03, 0x19, 0x00, 0x2A, 0xFF, 0x03, 0x75, 0x10, 0x95, 0x01,
    0x81, 0x00, //   one 16-bit usage
    0xC0, // End Collection
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xA1, 0x01, // Collection (Application)
    0x85, REPORT_MOUSE, //   Report ID
    0x09, 0x01, //   Usage (Pointer)
    0xA1, 0x00, //   Collection (Physical)
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01,
    0x81, 0x02, //     three buttons
    0x95, 0x01, 0x75, 0x05, 0x81, 0x01, //     padding
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08,
    0x95, 0x03, 0x81, 0x06, //     X, Y, wheel
    0xC0, //   End Collection
    0xC0, // End Collection
];

pub struct UsbStatus {
    pub installed: bool,
    pub running: bool,
    pub status: String,
    pub percent: u8,
    pub keystrokes: u32,
    pub unsupported: u32,
}

impl UsbStatus {
    const fn new() -> Self {
        Self {
            installed: false,
            running: false,
            status: String::new(),
            percent: 0,
            keystrokes: 0,
            unsupported: 0,
        }
    }
}

static STATE: Mutex<RefCell<UsbStatus>> = Mutex::new(RefCell::new(UsbStatus::new()));
static COMMAND: Mutex<RefCell<Option<UsbCommand>>> = Mutex::new(RefCell::new(None));

#[derive(Clone, Copy)]
pub enum UsbCommand {
    RunDemo,
    Stop,
}

pub fn is_installed() -> bool {
    critical_section::with(|cs| STATE.borrow_ref(cs).installed)
}

fn mark_installed() {
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.installed = true;
        state.status.clear();
        state.status.push_str("idle");
    });
}

pub fn submit(command: UsbCommand) -> bool {
    critical_section::with(|cs| {
        let mut slot = COMMAND.borrow_ref_mut(cs);
        if slot.is_some() {
            return false;
        }
        *slot = Some(command);
        true
    })
}

fn take_command() -> Option<UsbCommand> {
    critical_section::with(|cs| COMMAND.borrow_ref_mut(cs).take())
}

fn publish(status: &str, percent: u8, keystrokes: u32, unsupported: u32, running: bool) {
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.status.clear();
        state.status.push_str(status);
        state.percent = percent;
        state.keystrokes = keystrokes;
        state.unsupported = unsupported;
        state.running = running;
    });
}

pub fn snapshot() -> (String, u8, u32, u32, bool) {
    critical_section::with(|cs| {
        let state = STATE.borrow_ref(cs);
        (
            state.status.clone(),
            state.percent,
            state.keystrokes,
            state.unsupported,
            state.running,
        )
    })
}

fn encode(output: Output) -> ([u8; 9], usize) {
    let mut frame = [0u8; 9];
    match output {
        Output::Keyboard(report) => {
            frame[0] = REPORT_KEYBOARD;
            frame[1..9].copy_from_slice(&report.to_bytes());
            (frame, 9)
        }
        Output::Consumer(report) => {
            frame[0] = REPORT_CONSUMER;
            frame[1..3].copy_from_slice(&report.to_bytes());
            (frame, 3)
        }
        Output::Mouse(report) => {
            frame[0] = REPORT_MOUSE;
            frame[1..5].copy_from_slice(&report.to_bytes());
            (frame, 5)
        }
        Output::ReleaseAll => {
            frame[0] = REPORT_KEYBOARD;
            (frame, 9)
        }
    }
}

/// Run the USB stack and the script engine until the cable is pulled from the device side.
pub async fn run(usb: esp_hal::usb::otg::Usb<'static>) -> ! {
    let mut ep_out_buffer = [0u8; 128];
    let driver = esp_hal::usb::otg::embassy_usb_device::Driver::new(
        usb,
        &mut ep_out_buffer,
        esp_hal::usb::otg::embassy_usb_device::Config::default(),
    );
    let mut config = UsbConfig::new(0x303A, 0x4004);
    config.manufacturer = Some("CyberDeck");
    config.product = Some("CyberDeck HID");
    config.serial_number = Some("CD-0001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut config_descriptor = [0u8; 256];
    let mut bos_descriptor = [0u8; 256];
    let mut msos_descriptor = [0u8; 256];
    let mut control_buffer = [0u8; 64];
    let mut hid_state = HidState::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buffer,
    );

    let hid_config = HidConfig {
        report_descriptor: REPORT_DESCRIPTOR,
        request_handler: None,
        poll_ms: 10,
        max_packet_size: 9,
    };
    let mut writer = HidWriter::<_, 9>::new(&mut builder, &mut hid_state, hid_config);

    let mut device = builder.build();
    mark_installed();
    publish("idle", 0, 0, 0, false);

    let mut engine: Option<HidEngine> = None;
    let mut script_name = String::new();
    let mut finished_reported = false;

    loop {
        if let Some(command) = take_command() {
            match command {
                UsbCommand::RunDemo => match ducky::parse("demo.txt", DEMO_SCRIPT) {
                    Ok(script) => {
                        script_name.clear();
                        script_name.push_str("demo.txt");
                        publish("running demo.txt", 0, 0, 0, true);
                        engine = Some(HidEngine::new(&script, Layout::Us));
                        finished_reported = false;
                    }
                    Err(error) => publish(&error.describe(), 0, 0, 0, false),
                },
                UsbCommand::Stop => {
                    if let Some(engine) = engine.as_mut() {
                        engine.stop();
                    }
                }
            }
        }

        let mut write_failed = false;
        if let Some(active) = engine.as_mut() {
            let now = Instant::now().as_millis();
            while let Some(output) = active.next_report(now) {
                let (frame, len) = encode(output);
                // The endpoint only completes while the USB device future is polled,
                // so drive both here instead of awaiting the write on its own.
                let result = match embassy_futures::select::select(
                    device.run(),
                    writer.write(&frame[..len]),
                )
                .await
                {
                    embassy_futures::select::Either::Second(result) => result,
                    embassy_futures::select::Either::First(never) => match never {},
                };
                if result.is_err() {
                    write_failed = true;
                    break;
                }
            }
            let engine = active;
            if write_failed {
                publish("USB write failed", 0, 0, 0, false);
            } else if engine.is_finished() && !finished_reported {
                finished_reported = true;
                let progress = engine.progress();
                publish(
                    "script finished",
                    progress.percent,
                    engine.keystrokes(),
                    engine.unsupported_chars(),
                    false,
                );
            } else if !engine.is_finished() {
                let progress = engine.progress();
                let status = if engine.is_paused() {
                    "paused"
                } else {
                    script_name.as_str()
                };
                publish(
                    status,
                    progress.percent,
                    engine.keystrokes(),
                    engine.unsupported_chars(),
                    true,
                );
            }
        }
        if write_failed {
            engine = None;
        }

        // Drive the USB stack between engine polls; both must make progress.
        embassy_futures::select::select(device.run(), Timer::after(Duration::from_millis(POLL_MS)))
            .await;
    }
}

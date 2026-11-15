//! CyberDeck firmware entry point: hardware bring-up, dependency injection, loop.
//!
//! Composition only. Protocol logic lives in `cyberdeck-core`; drivers live in the
//! `platform` module. Every peripheral initialises independently so a missing SD
//! card, nRF24 module or radio never blocks the UI (master plan §3A.8).

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]
#![deny(clippy::large_stack_frames)]

extern crate alloc;

use cyberdeck_core::board::{self, BoardId, FIELD_PROFILE};
use cyberdeck_core::hardware::DeviceClass;
use cyberdeck_core::rf::capture::{NrfLog, NrfPacket};
use cyberdeck_core::rf::nrf24::DataRate;
use cyberdeck_core::rf::spectrum::Spectrum;
use cyberdeck_core::ui::Canvas;
use cyberdeck_firmware::app::{Action, App, Live, Tool};
use cyberdeck_firmware::platform::display::Display;
use cyberdeck_firmware::platform::nrf24::Nrf24;
use cyberdeck_firmware::platform::ble::{self, BleCommand};
use cyberdeck_firmware::platform::probe::ProbeReport;
use cyberdeck_firmware::platform::wifi::{self, WifiCommand};
use cyberdeck_firmware::platform::Buttons;
use bt_hci::controller::ExternalController;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode;
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::ble::controller::BleConnector;
use esp_radio::wifi::{ControllerConfig, WifiController};

esp_bootloader_esp_idf::esp_app_desc!();

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[embassy_executor::task]
async fn wifi_actor(controller: WifiController<'static>) {
    wifi::run(controller).await
}

#[embassy_executor::task]
async fn ble_actor(controller: ExternalController<BleConnector<'static>, 1>) {
    ble::run(controller).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RfMode {
    Off,
    Spectrum,
    Capture,
}

struct RfRuntime<'d> {
    radio: Option<Nrf24<'d>>,
    mode: RfMode,
    spectrum: Spectrum,
    log: NrfLog<24>,
    channel_cursor: usize,
    packets: u32,
}

impl<'d> RfRuntime<'d> {
    fn new(radio: Option<Nrf24<'d>>) -> Self {
        Self {
            radio,
            mode: RfMode::Off,
            spectrum: Spectrum::new(),
            log: NrfLog::new(),
            channel_cursor: 0,
            packets: 0,
        }
    }

    fn step(&mut self, now_ms: u64) {
        let Some(radio) = self.radio.as_mut() else {
            return;
        };
        match self.mode {
            RfMode::Off => {}
            RfMode::Spectrum => {
                let channels = cyberdeck_core::rf::nrf24::CHANNEL_COUNT as usize;
                let channel = 1 + (self.channel_cursor % channels.saturating_sub(2).max(1)) as u8;
                self.channel_cursor = self.channel_cursor.wrapping_add(1);
                if radio.set_channel(channel).is_ok() {
                    let _ = radio.sample(&mut self.spectrum);
                }
                if self.channel_cursor % 64 == 0 {
                    self.spectrum.finish_sweep();
                }
            }
            RfMode::Capture => {
                let mut buffer = [0u8; cyberdeck_core::rf::nrf24::MAX_PAYLOAD as usize];
                if let Ok(Some((pipe, len))) = radio.read_packet(&mut buffer) {
                    let payload = &buffer[..usize::from(len)];
                    if cyberdeck_core::rf::capture::plausible_length(len) {
                        self.log.push(NrfPacket::new(radio.channel(), pipe, payload, now_ms));
                        self.packets = self.packets.saturating_add(1);
                    }
                }
            }
        }
    }

    fn envelope(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0u8; 64];
        self.spectrum.envelope(&mut out);
        out
    }
}

#[allow(
    clippy::large_stack_frames,
    reason = "main owns the display/SPI buffers for the whole program lifetime"
)]
#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 73744);
    esp_alloc::heap_allocator!(size: 64 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // Board selection is a build-time switch (`CYBERDECK_BOARD=field`).
    #[cfg(cyberdeck_board_field)]
    const ACTIVE_BOARD: BoardId = BoardId::FieldS3;
    #[cfg(not(cyberdeck_board_field))]
    const ACTIVE_BOARD: BoardId = BoardId::CoreS3DevKit;
    let profile = board::profile(ACTIVE_BOARD);
    let mut probe = ProbeReport::new();

    // ---- display (CORE reference wiring: sck12 mosi11 cs10 dc9 rst14 bl13) ----
    let spi_config = SpiConfig::default()
        .with_frequency(Rate::from_mhz(40))
        .with_mode(Mode::_0);
    let mut display = match Spi::new(peripherals.SPI2, spi_config) {
        Ok(spi) => {
            let spi = spi
                .with_sck(peripherals.GPIO12)
                .with_mosi(peripherals.GPIO11);
            let output = OutputConfig::default();
            Display::new(
                spi,
                Output::new(peripherals.GPIO9, Level::Low, output),
                Output::new(peripherals.GPIO10, Level::High, output),
                Output::new(peripherals.GPIO14, Level::High, output),
                Some(Output::new(peripherals.GPIO13, Level::Low, output)),
                profile.display_geometry,
                profile.display_controller,
            )
            .map_err(|error| error.message())
        }
        Err(_) => Err("display SPI config failed"),
    };
    probe.record(
        DeviceClass::Display,
        match &display {
            Ok(panel) => Ok(Some(alloc::format!(
                "{} {}x{}",
                panel.controller().label(),
                profile.display_geometry.width,
                profile.display_geometry.height
            ))),
            Err(reason) => Err(*reason),
        },
    );

    // ---- buttons (up4 down5 select6 back7 home15) ----
    let input_config = InputConfig::default().with_pull(Pull::Up);
    let mut buttons = Buttons::new(
        Input::new(peripherals.GPIO4, input_config),
        Input::new(peripherals.GPIO5, input_config),
        Input::new(peripherals.GPIO6, input_config),
        Input::new(peripherals.GPIO7, input_config),
        Input::new(peripherals.GPIO15, input_config),
    );
    probe.record(DeviceClass::Input, Ok(Some(alloc::string::String::from("5 buttons"))));

    // ---- Wi-Fi radio ----
    let mut wifi_started = false;
    match WifiController::new(peripherals.WIFI, ControllerConfig::default()) {
        Ok(controller) => match wifi_actor(controller) {
            Ok(token) => {
                spawner.spawn(token);
                wifi_started = true;
                probe.record(
                    DeviceClass::WifiRadio,
                    Ok(Some(alloc::string::String::from("2.4 GHz"))),
                );
            }
            Err(_) => probe.record(DeviceClass::WifiRadio, Err("radio task could not start")),
        },
        Err(_) => probe.record(DeviceClass::WifiRadio, Err("Wi-Fi controller init failed")),
    }

    // ---- BLE radio ----
    let mut ble_started = false;
    match BleConnector::new(peripherals.BT, Default::default()) {
        Ok(connector) => {
            let controller = ExternalController::<_, 1>::new(connector);
            match ble_actor(controller) {
                Ok(token) => {
                    spawner.spawn(token);
                    ble::online();
                    ble_started = true;
                    probe.record(
                        DeviceClass::BleRadio,
                        Ok(Some(alloc::string::String::from("BLE HCI"))),
                    );
                }
                Err(_) => probe.record(DeviceClass::BleRadio, Err("BLE task could not start")),
            }
        }
        Err(_) => probe.record(DeviceClass::BleRadio, Err("BLE controller init failed")),
    }

    // ---- nRF24 (FIELD profile only; shares the SPI3 pins from the profile) ----
    let nrf = if profile.id == BoardId::FieldS3 && profile.nrf24.is_some() {
        let spi_config = SpiConfig::default()
            .with_frequency(Rate::from_mhz(8))
            .with_mode(Mode::_0);
        match Spi::new(peripherals.SPI3, spi_config) {
            Ok(spi) => {
                let spi = spi
                    .with_sck(peripherals.GPIO39)
                    .with_mosi(peripherals.GPIO40)
                    .with_miso(peripherals.GPIO41);
                let output = OutputConfig::default();
                let csn = Output::new(peripherals.GPIO1, Level::High, output);
                let ce = Output::new(peripherals.GPIO2, Level::Low, output);
                match Nrf24::new(spi, csn, ce, DataRate::Mbps1) {
                    Ok(radio) => {
                        probe.record(
                            DeviceClass::Nrf24,
                            Ok(Some(alloc::format!("ch{} 1 Mbps", radio.channel()))),
                        );
                        Some(radio)
                    }
                    Err(error) => {
                        probe.record(DeviceClass::Nrf24, Err(error.message()));
                        None
                    }
                }
            }
            Err(_) => {
                probe.record(DeviceClass::Nrf24, Err("nRF24 SPI config failed"));
                None
            }
        }
    } else {
        probe.record(
            DeviceClass::Nrf24,
            Err("not detected: connect an nRF24L01 module (FIELD profile)"),
        );
        None
    };

    let mut rf = RfRuntime::new(nrf);
    let mut app = App::new(probe.registry);
    let mut rf_mode = RfMode::Off;
    let mut last_render_ms = 0u64;

    // Keep the profile referenced so the FIELD constant cannot be optimised out of
    // the build without its pin map being validated.
    let _field_pins = FIELD_PROFILE.nrf24.map(|pins| (pins.ce, pins.csn));

    loop {
        let now_ms = embassy_time::Instant::now().as_millis();
        if let Some(button) = buttons.poll(now_ms) {
            match app.handle(button) {
                Action::Start(tool) => match tool {
                    Tool::WifiScan => {
                        if !wifi_started || !wifi::submit(WifiCommand::Scan) {
                            app.set_message("Wi-Fi radio busy");
                        }
                    }
                    Tool::WifiCapture | Tool::PktCapture => {
                        if !wifi_started || !wifi::submit(WifiCommand::Capture { channel: 6 }) {
                            app.set_message("Wi-Fi radio busy");
                        }
                    }
                    Tool::WifiBeacon => {
                        if !wifi_started
                            || !wifi::submit(WifiCommand::Attack {
                                mode: cyberdeck_core::wifi::attack::AttackMode::BeaconSpam,
                                channel: 6,
                            })
                        {
                            app.set_message("Wi-Fi radio busy");
                        }
                    }
                    Tool::WifiDeauth => {
                        if !wifi_started
                            || !wifi::submit(WifiCommand::Attack {
                                mode: cyberdeck_core::wifi::attack::AttackMode::Deauth,
                                channel: 6,
                            })
                        {
                            app.set_message("Wi-Fi radio busy");
                        }
                    }
                    Tool::PktAnalyse => {
                        app.set_message("live capture feeds the inspector");
                    }
                    Tool::BleScan => {
                        if !ble_started || !ble::submit(BleCommand::Scan) {
                            app.set_message("Bluetooth radio busy");
                        }
                    }
                    Tool::BleSpam => {
                        if !ble_started
                            || !ble::submit(BleCommand::Advertise(
                                cyberdeck_core::ble::spam::SpamCampaign::Apple,
                            ))
                        {
                            app.set_message("Bluetooth radio busy");
                        }
                    }
                    Tool::RfSpectrum => {
                        if rf.radio.is_some() {
                            rf_mode = RfMode::Spectrum;
                            rf.mode = RfMode::Spectrum;
                        } else {
                            app.set_message("No hardware detected: nRF24L01 radio");
                        }
                    }
                    Tool::RfCapture => {
                        if rf.radio.is_some() {
                            rf_mode = RfMode::Capture;
                            rf.mode = RfMode::Capture;
                            let _ = rf.radio.as_mut().map(|radio| radio.power_up_rx());
                        } else {
                            app.set_message("No hardware detected: nRF24L01 radio");
                        }
                    }
                    _ => {}
                },
                Action::Stop => {
                    if wifi_started {
                        wifi::submit(WifiCommand::Stop);
                    }
                    if ble_started {
                        ble::submit(BleCommand::Stop);
                    }
                    rf_mode = RfMode::Off;
                    rf.mode = RfMode::Off;
                }
                Action::None => {}
            }
        }

        rf.step(now_ms);

        let (status, aps, frames, dropped, _channel, _frame) = wifi::snapshot();
        let (ble_status, ble_devices, ble_frames, _ble_dropped) = ble::snapshot();
        let mut live = Live {
            wifi_status: status,
            wifi_busy: false,
            aps,
            wifi_frames: frames,
            wifi_dropped: dropped,
            rf_envelope: rf.envelope(),
            rf_peak: rf.spectrum.peak_channel().unwrap_or(0),
            rf_packets: rf.packets,
            rf_dropped: rf.log.dropped(),
            ble_status,
            ble_devices,
            ble_frames,
            probe_lines: probe.lines.clone(),
            message: None,
        };
        live.wifi_busy = matches!(rf_mode, RfMode::Off);
        app.set_live(live);

        // Coalesce repaints: a full 240x320 frame at 40 MHz takes longer than the
        // 20 ms input tick, so the UI refreshes at 4 Hz unless nothing changed.
        if now_ms.saturating_sub(last_render_ms) >= 250 {
            if let Ok(panel) = display.as_mut() {
                if app.take_dirty() {
                    app.render(panel);
                    panel.present();
                }
            }
            last_render_ms = now_ms;
        }

        Timer::after(Duration::from_millis(20)).await;
    }
}

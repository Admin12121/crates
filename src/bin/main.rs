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

use bt_hci::controller::ExternalController;
use cyberdeck_core::board::{self, BoardId, FIELD_PROFILE};
use cyberdeck_core::hardware::DeviceClass;
use cyberdeck_core::rf::capture::{NrfLog, NrfPacket};
#[cfg(cyberdeck_board_field)]
use cyberdeck_core::rf::nrf24::DataRate;
use cyberdeck_core::rf::spectrum::Spectrum;
use cyberdeck_core::ui::Canvas;
use cyberdeck_firmware::app::{Action, App, Live, Tool};
use cyberdeck_firmware::platform::Buttons;
use cyberdeck_firmware::platform::battery;
use cyberdeck_firmware::platform::ble::{self, BleCommand};
use cyberdeck_firmware::platform::display::Display;
use cyberdeck_firmware::platform::export;
use cyberdeck_firmware::platform::nrf24::Nrf24;
use cyberdeck_firmware::platform::probe::ProbeReport;
use cyberdeck_firmware::platform::sd::{self, SdBus};
use cyberdeck_firmware::platform::usb::{self, UsbCommand};
use cyberdeck_firmware::platform::wifi::{self, WifiCommand};
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_hal::analog::adc::{Adc, AdcConfig, Attenuation};
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
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

#[embassy_executor::task]
async fn sd_actor(bus: SdBus<'static>) {
    sd::run(bus).await
}

#[embassy_executor::task]
async fn usb_actor(usb: esp_hal::usb::otg::Usb<'static>) {
    usb::run(usb).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RfMode {
    Off,
    Spectrum,
    Capture,
}

struct RfRuntime<'d> {
    radio: Option<Nrf24<'d>>,
    delay: Delay,
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
            delay: Delay::new(),
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
                    // CE must be high for the RPD to reflect live channel energy.
                    radio.rx_mode(true);
                    self.delay.delay_micros(300);
                    let _ = radio.sample(&mut self.spectrum);
                    radio.rx_mode(false);
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
                        self.log
                            .push(NrfPacket::new(radio.channel(), pipe, payload, now_ms));
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
    // Wokwi offers an ILI9341; real board builds keep the ST7789 profile.
    let display_controller = if cfg!(cyberdeck_sim_wokwi) {
        board::DisplayController::Ili9341
    } else {
        profile.display_controller
    };
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
                display_controller,
                profile.display_orientation,
                profile.display_inverted,
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
    probe.record(
        DeviceClass::Input,
        Ok(Some(alloc::string::String::from("5 buttons"))),
    );

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

    // ---- battery monitor (ADC1 on the profile's battery pin) ----
    let mut battery_adc = if let Some(battery_pins) = profile.battery {
        let mut adc_config = AdcConfig::new();
        let pin = adc_config.enable_pin(peripherals.GPIO8, Attenuation::_11dB);
        let adc = Adc::new(peripherals.ADC1, adc_config);
        probe.record(
            DeviceClass::BatteryAdc,
            Ok(Some(alloc::format!(
                "ADC1 GPIO{} 1:{}",
                battery_pins.pin,
                battery_pins.divider
            ))),
        );
        Some((adc, pin, battery_pins.divider, 0u64))
    } else {
        probe.record(
            DeviceClass::BatteryAdc,
            Err("no battery pin in this profile"),
        );
        None
    };

    // ---- microSD (SPI3; the FIELD profile gives that bus to the nRF24) ----
    #[cfg(cyberdeck_board_field)]
    probe.record(
        DeviceClass::SdCard,
        Err("SPI3 shared with the nRF24 module"),
    );
    #[cfg(not(cyberdeck_board_field))]
    {
        let sd_config = SpiConfig::default()
            .with_frequency(Rate::from_khz(400))
            .with_mode(Mode::_0);
        match Spi::new(peripherals.SPI3, sd_config) {
            Ok(spi) => {
                let spi = spi
                    .with_sck(peripherals.GPIO39)
                    .with_mosi(peripherals.GPIO40)
                    .with_miso(peripherals.GPIO41);
                let cs = Output::new(peripherals.GPIO42, Level::High, OutputConfig::default());
                match sd_actor(SdBus::new(spi, cs)) {
                    Ok(token) => {
                        spawner.spawn(token);
                        let mut waited = 0;
                        while !sd::ready() && waited < 500 {
                            Timer::after(Duration::from_millis(10)).await;
                            waited += 10;
                        }
                        if sd::ready() {
                            probe.record(
                                DeviceClass::SdCard,
                                Ok(Some(alloc::string::String::from("FAT mounted"))),
                            );
                        } else {
                            probe.record(DeviceClass::SdCard, Err("no FAT volume"));
                        }
                    }
                    Err(_) => probe.record(DeviceClass::SdCard, Err("SD task could not start")),
                }
            }
            Err(_) => probe.record(DeviceClass::SdCard, Err("SPI3 config failed")),
        }
    }

    // ---- USB HID (Wokwi only models USB CDC, not composite HID) ----
    let mut usb_started = false;
    #[cfg(not(cyberdeck_sim_wokwi))]
    match usb_actor(esp_hal::usb::otg::Usb::new_fs(
        peripherals.USB_FS,
        peripherals.GPIO20,
        peripherals.GPIO19,
    )) {
        Ok(token) => {
            spawner.spawn(token);
            usb_started = true;
            // Give the task a moment to build the stack so the menu reflects reality.
            let mut waited = 0;
            while !usb::is_installed() && waited < 200 {
                Timer::after(Duration::from_millis(5)).await;
                waited += 5;
            }
            if usb::is_installed() {
                probe.record(
                    DeviceClass::UsbDevice,
                    Ok(Some(alloc::string::String::from("HID keyboard"))),
                );
            } else {
                probe.record(DeviceClass::UsbDevice, Err("USB stack did not start"));
            }
        }
        Err(_) => probe.record(DeviceClass::UsbDevice, Err("USB task could not start")),
    }
    #[cfg(cyberdeck_sim_wokwi)]
    probe.record(
        DeviceClass::UsbDevice,
        Err("USB HID not simulated by Wokwi"),
    );

    // ---- BLE radio (unsupported by Wokwi) ----
    let mut ble_started = false;
    #[cfg(not(cyberdeck_sim_wokwi))]
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
    #[cfg(cyberdeck_sim_wokwi)]
    probe.record(
        DeviceClass::BleRadio,
        Err("Bluetooth not simulated by Wokwi"),
    );

    // ---- nRF24 (FIELD profile only; SPI3 belongs to the SD card otherwise) ----
    #[cfg(cyberdeck_board_field)]
    let nrf = if profile.nrf24.is_some() {
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
    #[cfg(not(cyberdeck_board_field))]
    let nrf: Option<Nrf24<'static>> = {
        probe.record(
            DeviceClass::Nrf24,
            Err("not detected: connect an nRF24L01 module (FIELD profile)"),
        );
        None
    };

    let mut rf = RfRuntime::new(nrf);
    let mut app = App::new(probe.registry);
    let mut rf_mode = RfMode::Off;
    let mut active_tool: Option<Tool> = None;
    let mut last_render_ms = 0u64;

    // Keep the profile referenced so the FIELD constant cannot be optimised out of
    // the build without its pin map being validated.
    let _field_pins = FIELD_PROFILE.nrf24.map(|pins| (pins.ce, pins.csn));

    loop {
        let now_ms = embassy_time::Instant::now().as_millis();
        if let Some(button) = buttons.poll(now_ms) {
            match app.handle(button) {
                Action::Start(tool) => {
                    app.clear_message();
                    active_tool = Some(tool);
                    match tool {
                        // Tracked below so leaving a tool can export what it collected.
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
                        Tool::HidIntro | Tool::HidDucky => {
                            if !usb_started || !usb::submit(UsbCommand::RunDemo) {
                                app.set_message("USB HID busy");
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
                    }
                }
                Action::Stop => {
                    // Persist whatever the running tool collected before the radios stop.
                    match active_tool {
                        Some(Tool::WifiScan) => {
                            let (_, aps, _, _) = wifi::snapshot();
                            let _ = export::save_wifi_findings(&aps);
                        }
                        Some(Tool::BleScan | Tool::BleSpam) => {
                            let (_, devices, frames) = ble::snapshot();
                            let _ = export::save_ble_history(&devices, frames);
                        }
                        Some(Tool::RfCapture) => {
                            let _ = export::save_rf_capture(&rf.log);
                        }
                        _ => {}
                    }
                    active_tool = None;
                    if wifi_started {
                        wifi::submit(WifiCommand::Stop);
                    }
                    if ble_started {
                        ble::submit(BleCommand::Stop);
                    }
                    if usb_started {
                        usb::submit(UsbCommand::Stop);
                    }
                    rf_mode = RfMode::Off;
                    rf.mode = RfMode::Off;
                    if let Some(radio) = rf.radio.as_mut() {
                        let _ = radio.power_down();
                    }
                }
                Action::None => {}
            }
        }

        rf.step(now_ms);

        if let Some((adc, pin, divider, last)) = battery_adc.as_mut() {
            if now_ms.saturating_sub(*last) >= 500 {
                battery::publish(adc.read_blocking(pin), *divider);
                *last = now_ms;
            }
        }

        let (status, aps, frames, dropped) = wifi::snapshot();
        let (ble_status, ble_devices, ble_frames) = ble::snapshot();
        let (usb_status, usb_percent, usb_keystrokes, usb_unsupported) = usb::snapshot();
        let button_levels = buttons.levels();
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
            usb_status,
            usb_percent,
            usb_keystrokes,
            usb_unsupported,
            buttons: button_levels,
            probe_lines: {
                let mut lines = probe.lines.clone();
                lines.push(sd::status_line());
                lines.push(battery::status_line());
                lines
            },
            message: app.message(),
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

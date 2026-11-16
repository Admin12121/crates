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
mod control;

use bt_hci::controller::ExternalController;
use cyberdeck_core::board::{self, BoardId};
use cyberdeck_core::hardware::{DeviceClass, DeviceState};
use alloc::{rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;
use cyberdeck_firmware::platform::{gps, network};
use static_cell::StaticCell;
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
use cyberdeck_firmware::platform::payload;
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
#[cfg(cyberdeck_board_field)]
use esp_hal::uart::{UartRx, Config as UartConfig};

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

#[embassy_executor::task]
async fn network_runner(mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface>) {
    runner.run().await
}
#[embassy_executor::task]
async fn network_actor(stack: embassy_net::Stack<'static>) {
    network::run(stack).await
}
#[cfg(cyberdeck_board_field)]
#[embassy_executor::task]
async fn gps_actor(uart: UartRx<'static, esp_hal::Async>) {
    gps::run(uart).await
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
                let channel = (self.channel_cursor % channels) as u8;
                self.channel_cursor = self.channel_cursor.wrapping_add(1);
                if radio.set_channel(channel).is_ok() {
                    // CE must be high for the RPD to reflect live channel energy.
                    radio.rx_mode(true);
                    self.delay.delay_micros(300);
                    let _ = radio.sample(&mut self.spectrum);
                    radio.rx_mode(false);
                }
                if self.channel_cursor % cyberdeck_core::rf::nrf24::CHANNEL_COUNT as usize == 0 {
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

/// Persist whatever the finishing tool produced, on Stop and on auto-finish, so a
/// scan that ends by itself still leaves its findings on the card.
fn export_findings(tool:Option<Tool>,rf:&RfRuntime<'_>){
    if tool==Some(Tool::WifiScan){let(_,aps,_,_)=wifi::snapshot();let _=export::save_wifi_findings(&aps);}
    if tool==Some(Tool::WifiEvilTwin){let _=export::save_portal_credentials(&wifi::portal_csv());}
    if matches!(tool,Some(Tool::WifiScan|Tool::WifiCapture|Tool::WifiHandshake|Tool::WifiWps|Tool::WifiClients|Tool::WifiKarma|Tool::PktCapture|Tool::PktStream|Tool::PktAnalyse)){
        let _=export::save_wifi_hashes(&wifi::passive_hashes());
    }
    if matches!(tool,Some(Tool::BleScan|Tool::BleSpam|Tool::BleGatt)){let(_,devices,frames)=ble::snapshot();let _=export::save_ble_history(&devices,frames,&ble::gatt_snapshot());}
    if tool==Some(Tool::RfCapture){let _=export::save_rf_capture(&rf.log);}
}

/// Rebuild the payload picker from the built-in list plus any scripts on the card.
fn refresh_payloads(app:&mut App){
    let names=payload::names();
    let references:Vec<&str>=names.iter().map(|name|name.as_str()).collect();
    app.set_payloads(&references);
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
                if cfg!(cyberdeck_sim_wokwi) {
                    board::DisplayOrientation::Rotate0
                } else {
                    profile.display_orientation
                },
                profile.display_inverted,
                profile.display_bgr,
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

    // SPI3 is shared synchronously by SD and nRF. Neither transaction yields
    // while the bus is borrowed; both consumers run on this Embassy executor.
    let shared_spi = match Spi::new(peripherals.SPI3, SpiConfig::default()
        .with_frequency(Rate::from_khz(400)).with_mode(Mode::_0)) {
        Ok(spi) => Some(Rc::new(RefCell::new(spi.with_sck(peripherals.GPIO39)
            .with_mosi(peripherals.GPIO40).with_miso(peripherals.GPIO41)))),
        Err(_) => None,
    };
    if let Some(spi) = &shared_spi {
        let cs = Output::new(peripherals.GPIO42, Level::High, OutputConfig::default());
        match sd_actor(SdBus::from_shared(spi.clone(), cs)) {
            Ok(token) => {
                spawner.spawn(token);
                let deadline = embassy_time::Instant::now() + Duration::from_secs(2);
                while !sd::ready() && embassy_time::Instant::now() < deadline {
                    Timer::after(Duration::from_millis(10)).await;
                }
                probe.record(DeviceClass::SdCard, if sd::ready() {
                    Ok(Some(String::from("FAT mounted")))
                } else { Err("no writable FAT volume") });
            },
            Err(_) => probe.record(DeviceClass::SdCard, Err("SD task could not start")),
        }
    } else { probe.record(DeviceClass::SdCard, Err("SPI3 configuration failed")); }

    // ---- USB HID (Wokwi only models USB CDC, not composite HID) ----
    // Wokwi builds compile the USB actor out, so the binding is only mutated on hardware.
    #[allow(unused_mut)]
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
    // Wokwi builds compile the BLE actor out, so the binding is only mutated on hardware.
    #[allow(unused_mut)]
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

    // Optional FIELD nRF24 uses the same SPI3 bus with its own CSN.
    #[cfg(cyberdeck_board_field)]
    let nrf = if let Some(spi) = &shared_spi {
        let output = OutputConfig::default();
        match Nrf24::from_shared(spi.clone(),
            Output::new(peripherals.GPIO1, Level::High, output),
            Output::new(peripherals.GPIO2, Level::Low, output), DataRate::Mbps1) {
            Ok(radio) => {
                probe.record(DeviceClass::Nrf24, Ok(Some(String::from("nRF24L01+"))));
                Some(radio)
            },
            Err(error) => { probe.record(DeviceClass::Nrf24, Err(error.message())); None }
        }
    } else { probe.record(DeviceClass::Nrf24, Err("SPI3 unavailable")); None };
    #[cfg(not(cyberdeck_board_field))]
    let nrf: Option<Nrf24<'static>> = {
        probe.record(DeviceClass::Nrf24, Err("connect nRF24 using the FIELD profile"));
        None
    };
    // Only the FIELD profile assigns this; the attribute keeps CORE/Wokwi quiet.
    #[allow(unused_mut)]
    let mut gps_started = false;
    #[cfg(cyberdeck_board_field)]
    if let Some(pins) = profile.gps {
        match UartRx::new(peripherals.UART1, UartConfig::default().with_baudrate(pins.baud)) {
            Ok(uart) => match gps_actor(uart.with_rx(peripherals.GPIO18).into_async()) {
                Ok(token) => {spawner.spawn(token); gps_started = true;
                    probe.record(DeviceClass::Gps, Err("UART configured; waiting for GPS receiver"));}
                Err(_) => probe.record(DeviceClass::Gps, Err("GPS task could not start")),
            },
            Err(_) => probe.record(DeviceClass::Gps, Err("GPS UART configuration failed")),
        }
    }
    #[cfg(not(cyberdeck_board_field))]
    probe.record(DeviceClass::Gps, Err("connect UART GPS using the FIELD profile"));

    let mut net_started = false;
    if wifi_started {
        if let Some(interface) = esp_radio::wifi::Interface::try_station() {
            static NETWORK_RESOURCES: StaticCell<embassy_net::StackResources<4>> = StaticCell::new();
            let seed = u64::from(esp_hal::rng::Rng::new().random()) << 32
                | u64::from(esp_hal::rng::Rng::new().random());
            let (stack, runner) = embassy_net::new(interface,
                embassy_net::Config::dhcpv4(Default::default()),
                NETWORK_RESOURCES.init(embassy_net::StackResources::new()), seed);
            if let Ok(token) = network_runner(runner) {spawner.spawn(token);}
            if let Ok(token) = network_actor(stack) {spawner.spawn(token);net_started = true;}
        }
    }

    let mut rf = RfRuntime::new(nrf);
    let mut app = App::new(probe.registry);
    let flags=control::Flags{wifi:wifi_started,ble:ble_started,usb:usb_started,gps:gps_started,network:net_started};
    control::enable(&mut app,flags);
    // Built-in demo scripts plus any `*.TXT` payloads on the card.
    refresh_payloads(&mut app);
    sd::request_payload_scan();
    let mut active_tool:Option<Tool>=None;
    let mut pending_rf:Option<(Tool,u64)>=None;
    let mut last_payload_scan=0u64;
    let mut started_ms=0u64;
    let mut last_render_ms=0u64;
    let mut last_wardrive_scan=0u64;
    let mut gps_seen=false;
    let mut file_action:Option<(usize,bool)>=None;
    let mut file_last_name=String::new();
    loop {
        let now_ms=embassy_time::Instant::now().as_millis();
        if let Some(button)=buttons.poll(now_ms) {
            match app.handle(button) {
                Action::Start(tool)=>{
                    app.clear_message();started_ms=now_ms;
                    if matches!(tool,Tool::RfSpectrum|Tool::RfCapture) {
                        control::stop(&mut rf);pending_rf=Some((tool,now_ms));active_tool=None;
                    } else {
                        match control::start(tool,&mut app,&mut rf,flags) {
                            Ok(())=>{active_tool=Some(tool);if tool==Tool::GpsWardrive{last_wardrive_scan=now_ms;}},
                            Err(reason)=>{app.finish(reason);active_tool=None;},
                        }
                    }
                },
                Action::Stop=>{
                    export_findings(active_tool,&rf);
                    control::stop(&mut rf);active_tool=None;pending_rf=None;
                },
                Action::Pause(paused)=>{
                    if active_tool==Some(Tool::BleHid){ble::submit(if paused{BleCommand::HidPause}else{BleCommand::HidResume});}
                    else{usb::submit(if paused{UsbCommand::Pause}else{UsbCommand::Resume});}
                },
                Action::FilePreview(index)=>{file_action=Some((index as usize,false));sd::request_list();},
                Action::FileRecover(index)=>{file_action=Some((index as usize,true));sd::request_list();},
                Action::None=>{},
            }
        }
        if let Some((tool,since))=pending_rf {
            if !wifi::busy()&&!ble::busy(){
                match control::start(tool,&mut app,&mut rf,flags){Ok(())=>{active_tool=Some(tool);started_ms=now_ms;},Err(reason)=>app.finish(reason)}
                pending_rf=None;
            }else if now_ms.saturating_sub(since)>3000{app.finish("Radio is still stopping. Try again in a moment");pending_rf=None;}
        }
        while let Some(line)=usb::take_console_line(){
            if let Some(value)=line.strip_prefix("NET "){
                if let Some((ssid,password))=value.split_once('|'){
                    match cyberdeck_core::network::Credentials::new(ssid,password) {
                        Ok(credentials)=>{if wifi::submit(WifiCommand::Connect{ssid:credentials.ssid,password:credentials.password}){app.set_message("Joining that network...");}else{app.set_message("Wi-Fi busy. Stop the running tool first");}},
                        Err(reason)=>app.set_message(reason),
                    }
                }else{app.set_message("USB console: NET name|password");}
            }else if line=="STOP"{export_findings(active_tool,&rf);control::stop(&mut rf);active_tool=None;pending_rf=None;app.finish("Stopped from the USB console");}
        }
        if let Some((index,recover))=file_action {
            let(status,files)=sd::library_snapshot();
            if !files.is_empty(){
                if let Some(file)=files.get(index){
                    file_last_name=file.name.clone();
                    let accepted=if recover{sd::request_recover(&file.name)}else{sd::request_preview(&file.name)};
                    app.set_message(if accepted{"Opening the file..."}else{"Card busy. Try again"});
                }else{app.set_message("Pick a file in Saved captures");}
                file_action=None;
            }else if status.starts_with("0 files")||status.contains("empty")||status.contains("failed")||status.contains("unavailable"){app.set_message(&status);file_action=None;}
        }
        rf.step(now_ms);
        if payload::sync_from_storage(){refresh_payloads(&mut app);}
        if app.wants_payloads()&&sd::ready()&&now_ms.saturating_sub(last_payload_scan)>=3000{
            if sd::request_payload_scan(){last_payload_scan=now_ms;}
        }
        if let Some((adc,pin,divider,last))=battery_adc.as_mut(){if now_ms.saturating_sub(*last)>=500{battery::publish(adc.read_blocking(pin),*divider);*last=now_ms;}}
        if active_tool==Some(Tool::GpsWardrive)&&now_ms.saturating_sub(last_wardrive_scan)>=10_000&&!wifi::busy(){wifi::submit(WifiCommand::Scan);last_wardrive_scan=now_ms;}
        if gps::detected()!=gps_seen {gps_seen=gps::detected();app.set_device_state(DeviceClass::Gps,if gps_seen{DeviceState::Ready}else{DeviceState::NotDetected},Some("UART NMEA receiver"));}
        if now_ms.saturating_sub(last_render_ms)>=250 {
            let(wifi_status,aps,wifi_frames,wifi_dropped)=wifi::snapshot();
            let(ble_status,ble_devices,ble_frames)=ble::snapshot();
            // BLE HID reports through the same progress fields as USB HID.
            let(usb_status,usb_percent,usb_keystrokes,usb_unsupported)=if active_tool==Some(Tool::BleHid){ble::hid_snapshot()}else{usb::snapshot()};
            let(net_status,mut net_lines,net_busy)=network::snapshot();
            net_lines.insert(0,net_status.clone());
            let passive=wifi::passive_snapshot();
            let(portal_clients,portal_requests)=wifi::portal_snapshot();
            let mut packet_lines=Vec::new();
            match active_tool {
                Some(Tool::WifiClients)=>{
                    packet_lines.extend(passive.clients.iter().map(|row|row.line()));
                    if passive.clients.is_empty(){packet_lines.push(String::from("No devices seen yet"));}
                },
                Some(Tool::WifiWps)=>{
                    packet_lines.extend(passive.wps.iter().map(|row|row.line()));
                    if passive.wps.is_empty(){packet_lines.push(String::from("No WPS details seen yet"));}
                },
                Some(Tool::WifiHandshake)=>{},
                _=>{for frame in passive.frames.iter().take(4){packet_lines.push(frame.summary.clone());packet_lines.push(frame.metadata.clone());packet_lines.push(frame.hex.clone());}},
            }
            if active_tool==Some(Tool::PktAnalyse){packet_lines=wifi::dissect_latest();}
            if active_tool==Some(Tool::WifiKarma){packet_lines=passive.probes.iter().map(|row|row.line()).collect();}
            if active_tool==Some(Tool::RfCapture){
                let mut packets:Vec<String>=rf.log.iter().map(|packet|packet.render_line(34)).collect();
                packets.reverse();
                packet_lines=packets.into_iter().take(16).collect();
            }
            let(storage_status,files)=sd::library_snapshot();
            let capture_files=files.iter().enumerate().map(|(i,file)|alloc::format!("{} {} {} B",i+1,file.name,file.bytes)).collect();
            if active_tool==Some(Tool::PktFiles){packet_lines=alloc::vec![storage_status];if !file_last_name.is_empty(){packet_lines.push(file_last_name.clone());}packet_lines.extend(sd::preview().lines().take(24).map(String::from));}
            if active_tool==Some(Tool::BleGatt){packet_lines=ble::gatt_snapshot();}
            let mut probe_lines=probe.lines.clone();probe_lines.push(sd::status_line());probe_lines.push(battery::status_line());
            let preview=usb::preview(app.settings().payload).map(|text|text.lines().take(20).map(String::from).collect()).unwrap_or_default();
            let live=Live{wifi_status:wifi_status.clone(),wifi_busy:wifi::busy(),aps,wifi_frames,wifi_dropped,
                eapol:passive.eapol,handshakes:passive.handshakes,pmkids:passive.pmkids,
                portal_clients,portal_requests,
                probe_ssids:passive.probe_ssids,probe_rows:passive.probes.len() as u32,
                rf_envelope:rf.envelope(),rf_peak:rf.spectrum.peak_channel().unwrap_or(0),rf_packets:rf.packets,rf_dropped:rf.log.dropped(),
                ble_status:ble_status.clone(),ble_devices,ble_frames,usb_status:usb_status.clone(),usb_percent,usb_keystrokes,usb_unsupported,
                buttons:buttons.levels(),probe_lines,message:app.message(),usb_paused:app.usb_paused(),
                gps_lines:gps::snapshot(),net_lines,packet_lines,result_lines:Vec::new(),usb_preview:preview,capture_files,export_status:if sd::ready(){None}else{Some(sd::status_line())}};
            app.set_live(live);
            if now_ms.saturating_sub(started_ms)>300 {
                let finished=match active_tool{
                    Some(Tool::WifiScan|Tool::WifiCapture|Tool::WifiHandshake|Tool::WifiWps|Tool::WifiClients|Tool::PktCapture|Tool::PktAnalyse|Tool::PktStream) if !wifi::busy()=>Some(wifi_status.as_str()),
                    Some(Tool::NetInfo|Tool::NetDiscover|Tool::NetProbe|Tool::NetServices) if !net_busy=>Some(net_status.as_str()),
                    Some(Tool::HidIntro|Tool::HidDucky) if usb_status=="Script sent"||usb_status.starts_with("Sending failed")||usb_status.starts_with("parse")=>Some(usb_status.as_str()),
                    Some(Tool::BleGatt) if !ble::busy()=>Some(ble_status.as_str()),
                    _=>None,
                };
                if let Some(status)=finished{export_findings(active_tool,&rf);app.finish(status);active_tool=None;}
            }
            if let Ok(panel)=display.as_mut(){if app.take_dirty(){app.render(panel);panel.present();}}
            last_render_ms=now_ms;
        }
        Timer::after(Duration::from_millis(20)).await;
    }
}

//! Screen composition, navigation and rendering.
//!
//! The app owns *UI state only*: which screen is open, the selection and the last
//! bounded snapshot handed to it by `main`. Hardware work is requested by returning
//! an [`Action`], so the view never touches a driver (master plan §3A.2).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use cyberdeck_core::hardware::{DeviceClass, PeripheralRegistry};
use cyberdeck_core::ui::font;
use cyberdeck_core::ui::menu::{ItemStatus, MenuItem, MenuList};
use cyberdeck_core::ui::{Canvas, Rect, theme};

use crate::platform::ble::BleDevice;
use crate::platform::wifi::ApRow;

/// Capability groups implemented by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Wifi,
    Packet,
    Ble,
    UsbHid,
    Rf,
}

impl Group {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Wifi => "G01 WIFI SECURITY",
            Self::Packet => "G02 PACKET CAPTURE",
            Self::Ble => "G03 BLUETOOTH",
            Self::UsbHid => "G04 USB HID",
            Self::Rf => "G05 NRF24 RF",
        }
    }

    const fn device(self) -> DeviceClass {
        match self {
            Self::Wifi | Self::Packet => DeviceClass::WifiRadio,
            Self::Ble => DeviceClass::BleRadio,
            Self::UsbHid => DeviceClass::UsbDevice,
            Self::Rf => DeviceClass::Nrf24,
        }
    }
}

/// Runnable tool identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    WifiScan,
    WifiCapture,
    WifiBeacon,
    WifiDeauth,
    PktCapture,
    PktAnalyse,
    BleScan,
    BleSpam,
    HidIntro,
    HidDucky,
    RfSpectrum,
    RfCapture,
}

impl Tool {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WifiScan => "AP Scan",
            Self::WifiCapture => "Monitor Capture",
            Self::WifiBeacon => "Beacon Spam",
            Self::WifiDeauth => "Deauth Test",
            Self::PktCapture => "Live Capture",
            Self::PktAnalyse => "Frame Inspector",
            Self::BleScan => "BLE Scan",
            Self::BleSpam => "BLE Advertising",
            Self::HidIntro => "HID Device",
            Self::HidDucky => "DuckyScript",
            Self::RfSpectrum => "Channel Monitor",
            Self::RfCapture => "Packet Capture",
        }
    }

    /// Tools whose hardware path is wired in this build.
    pub const fn is_wired(self) -> bool {
        matches!(
            self,
            Self::WifiScan
                | Self::WifiCapture
                | Self::WifiBeacon
                | Self::WifiDeauth
                | Self::PktCapture
                | Self::PktAnalyse
                | Self::BleScan
                | Self::BleSpam
                | Self::HidIntro
                | Self::HidDucky
                | Self::RfSpectrum
                | Self::RfCapture
        )
    }
}

/// Requested hardware work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Start(Tool),
    Stop,
}

/// Bounded snapshot of live data for rendering.
#[derive(Default, Clone)]
pub struct Live {
    pub wifi_status: String,
    pub wifi_busy: bool,
    pub aps: Vec<ApRow>,
    pub wifi_frames: u32,
    pub wifi_dropped: u32,
    pub rf_envelope: Vec<u8>,
    pub rf_peak: u8,
    pub rf_packets: u32,
    pub rf_dropped: u32,
    pub ble_status: String,
    pub ble_devices: Vec<BleDevice>,
    pub ble_frames: u32,
    pub usb_status: String,
    pub usb_percent: u8,
    pub usb_keystrokes: u32,
    pub usb_unsupported: u32,
    pub probe_lines: Vec<String>,
    pub message: Option<String>,
}

enum Screen {
    Home,
    Group(Group),
    Running(Tool),
    Diagnostics,
}

/// The whole UI state machine.
pub struct App {
    screen: Screen,
    home: MenuList,
    group: Option<MenuList>,
    registry: PeripheralRegistry,
    live: Live,
    needs_render: bool,
}

const ROWS_PER_SCREEN: usize = 9;

impl App {
    pub fn new(registry: PeripheralRegistry) -> Self {
        let mut app = Self {
            screen: Screen::Home,
            home: MenuList::new("CYBERDECK", Vec::new(), ROWS_PER_SCREEN),
            group: None,
            registry,
            live: Live::default(),
            needs_render: true,
        };
        app.home = MenuList::new(
            "CYBERDECK",
            Self::home_items(&app.registry),
            ROWS_PER_SCREEN,
        );
        app
    }

    fn home_items(registry: &PeripheralRegistry) -> Vec<MenuItem> {
        let mut items = Vec::new();
        for (group, label) in [
            (Group::Wifi, "Wi-Fi Security"),
            (Group::Packet, "Packet Capture"),
            (Group::Ble, "Bluetooth / BLE"),
            (Group::UsbHid, "USB / HID"),
            (Group::Rf, "nRF24 RF"),
        ] {
            let status = if registry.is_ready(group.device()) {
                ItemStatus::Implemented
            } else {
                ItemStatus::RequiresHardware {
                    device: group.device().label(),
                }
            };
            items.push(MenuItem {
                label: String::from(label),
                status,
                detail: Some(String::from(group.title().split(' ').next().unwrap_or(""))),
            });
        }
        items.push(MenuItem::ready("Diagnostics"));
        items
    }

    fn group_items(group: Group, registry: &PeripheralRegistry) -> Vec<MenuItem> {
        let tools: &[(Tool, &str)] = match group {
            Group::Wifi => &[
                (Tool::WifiScan, "AP Scan"),
                (Tool::WifiCapture, "Monitor Capture"),
                (Tool::WifiBeacon, "Beacon Spam"),
                (Tool::WifiDeauth, "Deauth Test"),
            ],
            Group::Packet => &[
                (Tool::PktCapture, "Live Capture"),
                (Tool::PktAnalyse, "Frame Inspector"),
            ],
            Group::Ble => &[
                (Tool::BleScan, "BLE Scan"),
                (Tool::BleSpam, "Advertising Tests"),
            ],
            Group::UsbHid => &[
                (Tool::HidIntro, "HID Device"),
                (Tool::HidDucky, "DuckyScript"),
            ],
            Group::Rf => &[
                (Tool::RfSpectrum, "Channel Monitor"),
                (Tool::RfCapture, "Packet Capture"),
            ],
        };
        let ready = registry.is_ready(group.device());
        tools
            .iter()
            .map(|(tool, label)| {
                let status = if !ready {
                    ItemStatus::RequiresHardware {
                        device: group.device().label(),
                    }
                } else if tool.is_wired() {
                    ItemStatus::Implemented
                } else {
                    ItemStatus::ComingSoon
                };
                let _ = format!("");
                MenuItem {
                    label: String::from(*label),
                    status,
                    detail: None,
                }
            })
            .collect()
    }

    pub fn set_live(&mut self, live: Live) {
        self.live = live;
        self.needs_render = true;
    }

    pub fn message(&self) -> Option<String> {
        self.live.message.clone()
    }

    pub fn clear_message(&mut self) {
        self.live.message = None;
    }

    pub fn set_message(&mut self, message: &str) {
        self.live.message = Some(String::from(message));
        self.needs_render = true;
    }

    pub fn take_dirty(&mut self) -> bool {
        let dirty = self.needs_render;
        self.needs_render = false;
        dirty
    }

    pub fn mark_dirty(&mut self) {
        self.needs_render = true;
    }

    /// Handle one button press.
    pub fn handle(&mut self, button: crate::platform::Button) -> Action {
        use crate::platform::Button;
        self.needs_render = true;
        match &self.screen {
            Screen::Home => {
                match button {
                    Button::Down => self.home.next(),
                    Button::Up => self.home.previous(),
                    Button::Select => {
                        let index = self.home.selected();
                        if index < 5 {
                            let group = [
                                Group::Wifi,
                                Group::Packet,
                                Group::Ble,
                                Group::UsbHid,
                                Group::Rf,
                            ][index];
                            self.group = Some(MenuList::new(
                                group.title(),
                                Self::group_items(group, &self.registry),
                                ROWS_PER_SCREEN,
                            ));
                            self.screen = Screen::Group(group);
                        } else {
                            self.screen = Screen::Diagnostics;
                        }
                    }
                    Button::Back | Button::Home => {}
                }
                Action::None
            }
            Screen::Group(group) => {
                let group = *group;
                match button {
                    Button::Down => {
                        if let Some(menu) = self.group.as_mut() {
                            menu.next();
                        }
                    }
                    Button::Up => {
                        if let Some(menu) = self.group.as_mut() {
                            menu.previous();
                        }
                    }
                    Button::Select => {
                        let tool = match (group, self.group.as_ref().map(|m| m.selected())) {
                            (Group::Wifi, Some(0)) => Some(Tool::WifiScan),
                            (Group::Wifi, Some(1)) => Some(Tool::WifiCapture),
                            (Group::Wifi, Some(2)) => Some(Tool::WifiBeacon),
                            (Group::Wifi, Some(3)) => Some(Tool::WifiDeauth),
                            (Group::Packet, Some(0)) => Some(Tool::PktCapture),
                            (Group::Packet, Some(1)) => Some(Tool::PktAnalyse),
                            (Group::Ble, Some(0)) => Some(Tool::BleScan),
                            (Group::Ble, Some(1)) => Some(Tool::BleSpam),
                            (Group::UsbHid, Some(0)) => Some(Tool::HidIntro),
                            (Group::UsbHid, Some(1)) => Some(Tool::HidDucky),
                            (Group::Rf, Some(0)) => Some(Tool::RfSpectrum),
                            (Group::Rf, Some(1)) => Some(Tool::RfCapture),
                            _ => None,
                        };
                        if let Some(tool) = tool {
                            let ready = self
                                .group
                                .as_ref()
                                .and_then(|menu| menu.selected_item())
                                .map(|item| item.status.is_selectable())
                                .unwrap_or(false);
                            if ready {
                                self.screen = Screen::Running(tool);
                                return Action::Start(tool);
                            }
                        }
                        return Action::None;
                    }
                    Button::Back => {
                        self.screen = Screen::Home;
                    }
                    Button::Home => self.screen = Screen::Home,
                }
                Action::None
            }
            Screen::Running(_) => match button {
                Button::Back | Button::Home => {
                    self.screen = Screen::Home;
                    Action::Stop
                }
                _ => Action::None,
            },
            Screen::Diagnostics => match button {
                Button::Back | Button::Home | Button::Select => {
                    self.screen = Screen::Home;
                    Action::None
                }
                _ => Action::None,
            },
        }
    }

    pub fn render(&self, canvas: &mut impl Canvas) {
        canvas.fill_rect(
            Rect::new(0, 0, canvas.width(), canvas.height()),
            theme::BACKGROUND,
        );
        let title = match &self.screen {
            Screen::Home => "CYBERDECK",
            Screen::Group(group) => group.title(),
            Screen::Running(tool) => tool.title(),
            Screen::Diagnostics => "DIAGNOSTICS",
        };
        canvas.fill_rect(Rect::new(0, 0, canvas.width(), 20), theme::SURFACE);
        canvas.draw_text(4, 4, title, theme::ACCENT, theme::SURFACE, 2);
        match &self.screen {
            Screen::Home => self.render_menu(canvas, &self.home, 24),
            Screen::Group(_) => {
                if let Some(menu) = &self.group {
                    self.render_menu(canvas, menu, 24);
                }
            }
            Screen::Running(tool) => self.render_running(canvas, *tool),
            Screen::Diagnostics => self.render_diagnostics(canvas),
        }
        self.render_footer(canvas);
    }

    fn render_menu(&self, canvas: &mut impl Canvas, menu: &MenuList, top: i16) {
        let width = canvas.width();
        canvas.fill_rect(
            Rect::new(0, top, width, canvas.height() - top as u16 - 16),
            theme::BACKGROUND,
        );
        let columns = (width / (font::ADVANCE as u16 * theme::BODY_SCALE as u16)) as usize;
        for (row, (index, item)) in menu.visible().enumerate() {
            let y = top + row as i16 * 20;
            let selected = index == menu.selected();
            if selected {
                canvas.fill_rect(Rect::new(0, y, width, 18), theme::SELECTION);
            }
            let colour = match item.status {
                ItemStatus::Ready => theme::TEXT,
                ItemStatus::Implemented => theme::ACCENT,
                ItemStatus::Running => theme::ACCENT,
                ItemStatus::RequiresHardware { .. } => theme::WARNING,
                ItemStatus::ComingSoon => theme::TEXT_DIM,
            };
            let line = item.render_line(columns);
            canvas.draw_text(
                4,
                y + 4,
                &line,
                colour,
                if selected {
                    theme::SELECTION
                } else {
                    theme::BACKGROUND
                },
                1,
            );
        }
    }

    fn render_running(&self, canvas: &mut impl Canvas, tool: Tool) {
        let mut lines: Vec<String> = Vec::new();
        match tool {
            Tool::WifiScan | Tool::WifiCapture | Tool::WifiBeacon | Tool::WifiDeauth => {
                lines.push(self.live.wifi_status.clone());
                lines.push(format!(
                    "frames {}  drops {}",
                    self.live.wifi_frames, self.live.wifi_dropped
                ));
                if matches!(tool, Tool::WifiScan | Tool::PktAnalyse) {
                    for ap in self.live.aps.iter().take(8) {
                        lines.push(format!(
                            "{:<16} {:>4}dB {}{}",
                            ap.ssid, ap.rssi, ap.channel, ap.security
                        ));
                    }
                }
            }
            Tool::PktCapture | Tool::PktAnalyse => {
                lines.push(format!("frames {}", self.live.wifi_frames));
                lines.push(format!("drops {}", self.live.wifi_dropped));
                if let Some(message) = &self.live.message {
                    lines.push(message.clone());
                }
            }
            Tool::RfSpectrum => {
                lines.push(format!("peak ch {}", self.live.rf_peak));
                lines.push(format!("packets {}", self.live.rf_packets));
            }
            Tool::RfCapture => {
                lines.push(format!("packets {}", self.live.rf_packets));
                lines.push(format!("dropped {}", self.live.rf_dropped));
            }
            Tool::BleScan | Tool::BleSpam => {
                lines.push(self.live.ble_status.clone());
                lines.push(format!("frames {}", self.live.ble_frames));
                for device in self.live.ble_devices.iter().take(6) {
                    lines.push(format!(
                        "{:<16} {:>4}dB {}",
                        device.name, device.rssi, device.kind
                    ));
                }
            }
            Tool::HidIntro | Tool::HidDucky => {
                lines.push(self.live.usb_status.clone());
                lines.push(format!("{}% typed", self.live.usb_percent));
                lines.push(format!("keys {}", self.live.usb_keystrokes));
                if self.live.usb_unsupported > 0 {
                    lines.push(format!("skipped {}", self.live.usb_unsupported));
                }
            }
        }
        let mut y = 26;
        if tool == Tool::RfSpectrum && !self.live.rf_envelope.is_empty() {
            let width = canvas.width().saturating_sub(8);
            let bars = self.live.rf_envelope.len().max(1) as u16;
            let bar_width = (width / bars).max(1);
            for (index, level) in self.live.rf_envelope.iter().enumerate() {
                let height = 4 + (u16::from(*level) * 60) / 255;
                let x = 4 + index as i16 * bar_width as i16;
                canvas.fill_rect(
                    Rect::new(x, 100 - height as i16, bar_width.saturating_sub(1), height),
                    theme::ACCENT,
                );
            }
            y = 112;
        }
        for line in lines.iter().take(8) {
            canvas.draw_text(4, y, line, theme::TEXT, theme::BACKGROUND, 1);
            y += 12;
        }
        if let Some(message) = &self.live.message {
            canvas.draw_text(
                4,
                canvas.height() as i16 - 30,
                message,
                theme::WARNING,
                theme::BACKGROUND,
                1,
            );
        }
    }

    fn render_diagnostics(&self, canvas: &mut impl Canvas) {
        let mut y = 26;
        for line in self.live.probe_lines.iter().take(12) {
            canvas.draw_text(4, y, line, theme::TEXT_DIM, theme::BACKGROUND, 1);
            y += 12;
        }
        if self.live.probe_lines.is_empty() {
            canvas.draw_text(4, y, "no probe data", theme::WARNING, theme::BACKGROUND, 1);
        }
    }

    fn render_footer(&self, canvas: &mut impl Canvas) {
        let y = canvas.height() as i16 - 14;
        canvas.fill_rect(Rect::new(0, y, canvas.width(), 14), theme::SURFACE);
        let hint = match &self.screen {
            Screen::Home => "UP/DOWN  SELECT  BACK",
            Screen::Group(_) => "SELECT run   BACK menu",
            Screen::Running(_) => "BACK stops",
            Screen::Diagnostics => "BACK returns",
        };
        canvas.draw_text(4, y + 3, hint, theme::TEXT_DIM, theme::SURFACE, 1);
    }
}

//! Device navigation and Canvas rendering. Drivers only run in response to Action.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use cyberdeck_core::hardware::{DeviceClass, DeviceState, PeripheralRegistry};
use cyberdeck_core::ui::{Canvas, Rect, Rgb565, draw_bar, ellipsize, font, theme, wrap};
use crate::platform::ble::BleDevice;
use crate::platform::wifi::ApRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group { Wifi, Packet, Ble, UsbHid, Rf, Gps, Network }
const GROUPS: [Group; 7] = [Group::Wifi, Group::Packet, Group::Ble, Group::UsbHid, Group::Rf, Group::Gps, Group::Network];
impl Group {
    pub const fn title(self) -> &'static str {
        match self { Self::Wifi=>"Wi-Fi",Self::Packet=>"Packet",Self::Ble=>"Bluetooth",Self::UsbHid=>"USB / HID",Self::Rf=>"Radio",Self::Gps=>"GPS",Self::Network=>"Network" }
    }
    const fn summary(self)->&'static str {
        match self {Self::Wifi=>"Networks and passive observations",Self::Packet=>"Capture, inspect and export",Self::Ble=>"Nearby devices and advertising",Self::UsbHid=>"Payloads, keyboard and controls",Self::Rf=>"2.4 GHz channel observations",Self::Gps=>"Position, tracks and wardriving",Self::Network=>"Connection and local diagnostics"}
    }
    const fn device(self)->DeviceClass {
        match self {Self::Wifi|Self::Packet|Self::Network=>DeviceClass::WifiRadio,Self::Ble=>DeviceClass::BleRadio,Self::UsbHid=>DeviceClass::UsbDevice,Self::Rf=>DeviceClass::Nrf24,Self::Gps=>DeviceClass::Gps}
    }
    pub const fn tools(self)->&'static [Tool] {
        match self {
            Self::Wifi=>&[Tool::WifiScan,Tool::WifiCapture,Tool::WifiHandshake,Tool::WifiWps,Tool::WifiClients,Tool::WifiBeacon,Tool::WifiDeauth],
            Self::Packet=>&[Tool::PktCapture,Tool::PktAnalyse,Tool::PktFiles,Tool::PktStream],
            Self::Ble=>&[Tool::BleScan,Tool::BleSpam,Tool::BleGatt,Tool::BleHid],
            Self::UsbHid=>&[Tool::HidIntro,Tool::HidDucky],
            Self::Rf=>&[Tool::RfSpectrum,Tool::RfCapture],
            Self::Gps=>&[Tool::GpsStatus,Tool::GpsRecord,Tool::GpsWardrive],
            Self::Network=>&[Tool::NetInfo,Tool::NetDiscover,Tool::NetProbe,Tool::NetServices],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    WifiScan, WifiCapture, WifiBeacon, WifiDeauth, WifiHandshake, WifiWps, WifiClients,
    PktCapture, PktAnalyse, PktFiles, PktStream,
    BleScan, BleSpam, BleGatt, BleHid, HidIntro, HidDucky,
    RfSpectrum, RfCapture, GpsStatus, GpsRecord, GpsWardrive,
    NetInfo, NetDiscover, NetProbe, NetServices,
}
impl Tool {
    pub const fn title(self)->&'static str {
        match self {
            Self::WifiScan=>"AP scan",Self::WifiCapture=>"Monitor capture",Self::WifiBeacon=>"Beacon test",Self::WifiDeauth=>"Deauth test",
            Self::WifiHandshake=>"Handshake observer",Self::WifiWps=>"WPS information",Self::WifiClients=>"Nearby clients",
            Self::PktCapture=>"Live capture",Self::PktAnalyse=>"Frame inspector",Self::PktFiles=>"Capture files",Self::PktStream=>"USB packet stream",
            Self::BleScan=>"Device scan",Self::BleSpam=>"Advertising",Self::BleGatt=>"GATT services",Self::BleHid=>"BLE keyboard",
            Self::HidIntro=>"HID test",Self::HidDucky=>"Payload library",Self::RfSpectrum=>"Channel monitor",Self::RfCapture=>"Packet capture",
            Self::GpsStatus=>"Position and fix",Self::GpsRecord=>"Record track",Self::GpsWardrive=>"Wardrive log",
            Self::NetInfo=>"Connect / info",Self::NetDiscover=>"Discover hosts",Self::NetProbe=>"Probe host",Self::NetServices=>"Service check",
        }
    }
    pub const fn group(self)->Group {
        match self {
            Self::WifiScan|Self::WifiCapture|Self::WifiBeacon|Self::WifiDeauth|Self::WifiHandshake|Self::WifiWps|Self::WifiClients=>Group::Wifi,
            Self::PktCapture|Self::PktAnalyse|Self::PktFiles|Self::PktStream=>Group::Packet,
            Self::BleScan|Self::BleSpam|Self::BleGatt|Self::BleHid=>Group::Ble,
            Self::HidIntro|Self::HidDucky=>Group::UsbHid,Self::RfSpectrum|Self::RfCapture=>Group::Rf,
            Self::GpsStatus|Self::GpsRecord|Self::GpsWardrive=>Group::Gps,
            Self::NetInfo|Self::NetDiscover|Self::NetProbe|Self::NetServices=>Group::Network,
        }
    }
    const fn description(self)->&'static str {
        match self {
            Self::WifiScan=>"Signal, channel and security",Self::WifiCapture=>"Listen and save received frames",
            Self::WifiHandshake=>"Passive EAPOL / PMKID findings",Self::WifiWps=>"Read advertised WPS attributes",Self::WifiClients=>"Observed stations and access points",
            Self::WifiBeacon=>"Existing laboratory beacon test",Self::WifiDeauth=>"Existing laboratory deauth test",
            Self::PktCapture=>"Bounded capture with drop counts",Self::PktAnalyse=>"Frame summary, metadata and bytes",
            Self::PktFiles=>"Browse saved captures and recovery",Self::PktStream=>"Send capture records over USB",
            Self::BleScan=>"Names, addresses and signal",Self::BleSpam=>"Local advertising experiments",
            Self::BleGatt=>"Inspect a selected device",Self::BleHid=>"Bluetooth keyboard connection",
            Self::HidIntro=>"Check the local USB connection",Self::HidDucky=>"Choose and preview a local script",
            Self::RfSpectrum=>"Energy envelope across channels",Self::RfCapture=>"Receive on a selected channel",
            Self::GpsStatus=>"Fix quality and coordinates",Self::GpsRecord=>"Save a bounded GPS track",Self::GpsWardrive=>"Combine Wi-Fi observations and GPS",
            Self::NetInfo=>"Join a network and show address",Self::NetDiscover=>"Find hosts on the local subnet",
            Self::NetProbe=>"Reachability of a selected host",Self::NetServices=>"Ordinary TCP service diagnostics",
        }
    }
    /// Existing hardware routes. New routes require explicit integration enablement.
    pub const fn is_wired(self)->bool {
        matches!(self,Self::WifiScan|Self::WifiCapture|Self::WifiBeacon|Self::WifiDeauth|Self::PktCapture|Self::PktAnalyse|Self::BleScan|Self::BleSpam|Self::HidIntro|Self::HidDucky|Self::RfSpectrum|Self::RfCapture)
    }
    const fn is_usb(self)->bool {matches!(self,Self::HidIntro|Self::HidDucky)}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFilter { All, Management, Data, Eapol }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardLayout { Us, Uk, De }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Wi-Fi: 0 = hop, 1..13 = fixed. nRF: 0..125 = fixed channel.
    pub channel:u8,
    pub filter:PacketFilter,
    pub layout:KeyboardLayout,
    pub payload:u8,
    /// AP/device/file index, or last octet of a local network host.
    pub target:u8,
    pub stream:bool,
    pub rf_rate:u8,
    pub rf_payload_len:u8,
}
impl Default for Settings {
    fn default()->Self {Self {channel:1,filter:PacketFilter::All,layout:KeyboardLayout::Us,payload:0,target:0,stream:false,rf_rate:1,rf_payload_len:32}}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { None, Start(Tool), Stop, Pause(bool), FilePreview(u8), FileRecover(u8) }

#[derive(Default, Clone)]
pub struct Live {
    pub wifi_status:String,pub wifi_busy:bool,pub aps:Vec<ApRow>,pub wifi_frames:u32,pub wifi_dropped:u32,
    pub rf_envelope:Vec<u8>,pub rf_peak:u8,pub rf_packets:u32,pub rf_dropped:u32,
    pub ble_status:String,pub ble_devices:Vec<BleDevice>,pub ble_frames:u32,
    pub usb_status:String,pub usb_percent:u8,pub usb_keystrokes:u32,pub usb_unsupported:u32,pub usb_paused:bool,
    pub buttons:[bool;5],pub probe_lines:Vec<String>,pub message:Option<String>,
    pub gps_lines:Vec<String>,pub net_lines:Vec<String>,pub packet_lines:Vec<String>,pub result_lines:Vec<String>,
    pub usb_preview:Vec<String>,pub capture_files:Vec<String>,pub export_status:Option<String>,
}
impl Live {
    fn same_visual(&self,other:&Self)->bool {
        self.wifi_status==other.wifi_status && self.wifi_busy==other.wifi_busy &&
        self.aps.len()==other.aps.len() && self.aps.iter().zip(&other.aps).all(|(a,b)| a.ssid==b.ssid&&a.bssid==b.bssid&&a.channel==b.channel&&a.rssi==b.rssi&&a.security==b.security) &&
        self.ble_devices.len()==other.ble_devices.len() && self.ble_devices.iter().zip(&other.ble_devices).all(|(a,b)|a.address==b.address&&a.name==b.name&&a.rssi==b.rssi&&a.kind==b.kind&&a.detail==b.detail) &&
        self.wifi_frames==other.wifi_frames&&self.wifi_dropped==other.wifi_dropped&&self.ble_status==other.ble_status&&self.ble_frames==other.ble_frames&&
        self.rf_envelope==other.rf_envelope&&self.rf_peak==other.rf_peak&&self.rf_packets==other.rf_packets&&self.rf_dropped==other.rf_dropped&&
        self.usb_status==other.usb_status&&self.usb_percent==other.usb_percent&&self.usb_keystrokes==other.usb_keystrokes&&self.usb_unsupported==other.usb_unsupported&&self.usb_paused==other.usb_paused&&
        self.gps_lines==other.gps_lines&&self.net_lines==other.net_lines&&self.packet_lines==other.packet_lines&&self.result_lines==other.result_lines&&self.usb_preview==other.usb_preview&&self.capture_files==other.capture_files&&self.export_status==other.export_status&&self.message==other.message
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen { Home, Group(Group), Setup(Tool), Running(Tool), Results(Tool), Unavailable(Tool), Edit(Tool,bool), Diagnostics }
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
enum Field { Run, Channel, Filter, Layout, Payload, Target, Stream, Network, Ssid, Password, Previous, RfRate, RfLength, FileRecover }
pub struct App {
    screen:Screen,home_index:usize,tool_index:usize,setup_index:usize,scroll:usize,
    registry:PeripheralRegistry,live:Live,settings:Settings,availability:Vec<(Tool,Option<String>)>,payloads:Vec<String>,
    ssid:String,password:String,edit_text:String,edit_char:u8,
    results:Option<(Tool,Live)>,needs_render:bool,last_rendered:Option<Screen>,last_selection:usize,last_page:usize,last_notice:bool,columns:usize,
}
impl App {
    pub fn new(registry:PeripheralRegistry)->Self {
        Self {screen:Screen::Home,home_index:0,tool_index:0,setup_index:0,scroll:0,registry,live:Live::default(),settings:Settings::default(),availability:Vec::new(),payloads:Vec::new(),ssid:String::new(),password:String::new(),edit_text:String::new(),edit_char:b'a',results:None,needs_render:true,last_rendered:None,last_selection:0,last_page:usize::MAX,last_notice:false,columns:36}
    }
    pub fn settings(&self)->Settings {self.settings}
    pub fn active_tool(&self)->Option<Tool> {if let Screen::Running(tool)=self.screen {Some(tool)} else {None}}
    pub fn usb_paused(&self)->bool {self.live.usb_paused}
    /// True while a screen that lists payloads is visible, so storage can rescan it.
    pub fn wants_payloads(&self)->bool {
        matches!(self.screen,
            Screen::Group(Group::UsbHid)
            |Screen::Setup(Tool::HidIntro|Tool::HidDucky)
            |Screen::Running(Tool::HidIntro|Tool::HidDucky))
    }
    pub fn set_device_state(&mut self,class:DeviceClass,state:DeviceState,detail:Option<&str>) {self.registry.upsert(class,state,detail);self.needs_render=true;}
    pub fn network_credentials(&self)->(String,String) {(self.ssid.clone(),self.password.clone())}
    pub fn set_payloads(&mut self,names:&[&str]) {
        self.payloads=names.iter().take(256).map(|name|String::from(*name)).collect();
        self.settings.payload=self.settings.payload.min(self.payloads.len().saturating_sub(1) as u8);
        self.needs_render=true;
    }
    pub fn set_tool_available(&mut self,tool:Tool) {self.availability(tool,None);}
    pub fn set_tool_unavailable(&mut self,tool:Tool,reason:&str) {self.availability(tool,Some(String::from(reason)));}
    fn availability(&mut self,tool:Tool,reason:Option<String>) {
        if let Some(entry)=self.availability.iter_mut().find(|entry|entry.0==tool) {entry.1=reason;} else {self.availability.push((tool,reason));}
        self.needs_render=true;
    }
    pub fn set_registry(&mut self,registry:PeripheralRegistry) {self.registry=registry;self.needs_render=true;}
    fn unavailable(&self,tool:Tool)->Option<String> {
        if let Some((_,Some(reason)))=self.availability.iter().find(|entry|entry.0==tool) {return Some(reason.clone());}
        if !tool.is_wired() && !self.availability.iter().any(|entry|entry.0==tool&&entry.1.is_none()) {
            return Some(String::from(match tool {
                Tool::BleGatt=>"GATT connections are not enabled in this firmware.",
                Tool::BleHid=>"Bluetooth keyboard mode is not enabled in this firmware.",
                Tool::PktStream=>"USB capture streaming is not enabled in this firmware.",
                _=>"This tool is not enabled in this firmware.",
            }));
        }
        let device=tool.group().device();
        if !self.registry.is_ready(device) {
            return Some(match self.registry.state(device) {
                Some(DeviceState::InitFailed {reason})=>format!("{} could not start: {}.",device.label(),reason),
                Some(DeviceState::Busy {owner})=>format!("{} is in use by {}.",device.label(),owner),
                Some(DeviceState::Incompatible {detected})=>format!("Detected {}. This tool needs {}.",detected.label(),device.label()),
                _=>format!("Connect and initialize {} to use this tool.",device.label()),
            });
        }
        if tool==Tool::PktStream && !self.registry.is_ready(DeviceClass::UsbDevice) {return Some(String::from("Connect the native USB data port for packet streaming."));}
        if tool==Tool::GpsWardrive && !self.registry.is_ready(DeviceClass::WifiRadio) {return Some(String::from("Wardriving needs the Wi-Fi radio and a GPS receiver."));}
        None
    }
    /// Snapshot updates do not repaint idle menus. Every visible live field is compared.
    pub fn set_live(&mut self,live:Live) {
        let changed=match self.screen {
            Screen::Running(_)=>!self.live.same_visual(&live),
            Screen::Setup(_)=>self.live.usb_preview!=live.usb_preview||self.live.aps.len()!=live.aps.len()||!self.live.same_visual(&live),
            Screen::Diagnostics=>self.live.probe_lines!=live.probe_lines||self.live.buttons!=live.buttons,
            Screen::Results(_)=>self.live.result_lines!=live.result_lines||self.live.export_status!=live.export_status||self.live.message!=live.message,
            _=>self.live.message!=live.message,
        };
        if let Screen::Results(tool)=self.screen {
            if let Some((saved_tool,saved))=&mut self.results {
                if *saved_tool==tool {if live.export_status.is_some(){saved.export_status=live.export_status.clone();}if !live.result_lines.is_empty(){saved.result_lines=live.result_lines.clone();}}
            }
        }
        self.live=live;self.needs_render|=changed;
    }
    pub fn message(&self)->Option<String> {self.live.message.clone()}
    pub fn clear_message(&mut self) {if self.live.message.take().is_some(){self.needs_render=true;}}
    pub fn set_message(&mut self,message:&str) {self.live.message=Some(String::from(message));self.needs_render=true;}
    pub fn take_dirty(&mut self)->bool {let dirty=self.needs_render;self.needs_render=false;dirty}
    pub fn mark_dirty(&mut self) {self.needs_render=true;}
    pub fn finish(&mut self,message:&str) {
        if let Screen::Running(tool)=self.screen {
            self.live.message=Some(String::from(message));self.save_results(tool);self.screen=Screen::Results(tool);self.scroll=0;self.needs_render=true;
        }
    }
    fn save_results(&mut self,tool:Tool) {self.results=Some((tool,self.live.clone()));}
    fn fields(&self,tool:Tool)->Vec<Field> {
        let mut fields=alloc::vec![Field::Run];
        match tool {
            Tool::WifiScan|Tool::WifiCapture|Tool::WifiHandshake|Tool::WifiWps|Tool::WifiClients|Tool::PktCapture|Tool::PktAnalyse=>fields.extend([Field::Channel,Field::Filter]),
            Tool::WifiBeacon|Tool::WifiDeauth=>fields.extend([Field::Channel,Field::Target]),
            Tool::PktStream=>fields.extend([Field::Channel,Field::Filter,Field::Stream]),
            Tool::PktFiles=>fields.extend([Field::Target,Field::FileRecover]),
            Tool::BleScan|Tool::BleSpam|Tool::BleGatt|Tool::BleHid=>fields.push(Field::Target),
            Tool::HidIntro|Tool::HidDucky=>fields.extend([Field::Payload,Field::Layout]),
            Tool::RfSpectrum=>fields.push(Field::Channel),
            Tool::RfCapture=>fields.extend([Field::Channel,Field::RfRate,Field::RfLength]),
            Tool::NetInfo=>fields.extend([Field::Network,Field::Ssid,Field::Password]),
            Tool::NetProbe|Tool::NetServices=>fields.push(Field::Target),
            _=>{},
        }
        if self.results.as_ref().is_some_and(|result|result.0==tool) {fields.push(Field::Previous);}
        fields
    }
    fn change_field(&mut self,field:Field,tool:Tool) {
        match field {
            Field::Channel=>self.settings.channel=if tool.group()==Group::Rf {(self.settings.channel+1)%126}else{(self.settings.channel+1)%14},
            Field::Filter=>self.settings.filter=match self.settings.filter {PacketFilter::All=>PacketFilter::Management,PacketFilter::Management=>PacketFilter::Data,PacketFilter::Data=>PacketFilter::Eapol,PacketFilter::Eapol=>PacketFilter::All},
            Field::Layout=>self.settings.layout=match self.settings.layout {KeyboardLayout::Us=>KeyboardLayout::Uk,KeyboardLayout::Uk=>KeyboardLayout::De,KeyboardLayout::De=>KeyboardLayout::Us},
            Field::Payload=>if !self.payloads.is_empty(){self.settings.payload=((usize::from(self.settings.payload)+1)%self.payloads.len()) as u8;},
            Field::Target=>{
                let count=match tool {Tool::PktFiles=>self.live.capture_files.len(),Tool::WifiBeacon|Tool::WifiDeauth=>self.live.aps.len(),Tool::BleScan|Tool::BleSpam|Tool::BleGatt|Tool::BleHid=>self.live.ble_devices.len(),_=>255};
                self.settings.target=if matches!(tool,Tool::NetProbe|Tool::NetServices|Tool::NetDiscover){self.settings.target%254+1}else{((usize::from(self.settings.target)+1)%count.max(1)) as u8};
            },
            Field::Stream=>self.settings.stream=!self.settings.stream,
            Field::RfRate=>self.settings.rf_rate=(self.settings.rf_rate+1)%3,
            Field::RfLength=>self.settings.rf_payload_len=self.settings.rf_payload_len%32+1,
            Field::FileRecover=>{},
            Field::Network=>if !self.live.aps.is_empty() {
                if !self.ssid.is_empty(){self.settings.target=((usize::from(self.settings.target)+1)%self.live.aps.len()) as u8;}
                self.ssid=self.live.aps[usize::from(self.settings.target)].ssid.clone();
            },
            Field::Ssid|Field::Password=>{let password=field==Field::Password;self.edit_text=if password {self.password.clone()}else{self.ssid.clone()};self.edit_char=b'a';self.screen=Screen::Edit(tool,password);},
            Field::Previous=>{self.screen=Screen::Results(tool);self.scroll=0;},
            Field::Run=>{},
        }
    }
    pub fn handle(&mut self,button:crate::platform::Button)->Action {
        use crate::platform::Button;
        self.needs_render=true;
        match self.screen {
            Screen::Home=>match button {
                Button::Down=>self.home_index=(self.home_index+1)%8,Button::Up=>self.home_index=(self.home_index+7)%8,
                Button::Select=>{self.scroll=0;self.tool_index=0;self.screen=if self.home_index<7 {Screen::Group(GROUPS[self.home_index])}else{Screen::Diagnostics};},
                _=>{},
            },
            Screen::Group(group)=>match button {
                Button::Down=>self.tool_index=(self.tool_index+1)%group.tools().len(),
                Button::Up=>self.tool_index=(self.tool_index+group.tools().len()-1)%group.tools().len(),
                Button::Select=>{let tool=group.tools()[self.tool_index];if group==Group::Network{self.settings.target=self.settings.target.clamp(1,254);}self.setup_index=0;self.scroll=0;self.settings.channel=self.settings.channel.min(if group==Group::Rf {125}else{13});self.screen=if self.unavailable(tool).is_some(){Screen::Unavailable(tool)}else{Screen::Setup(tool)};},
                Button::Back|Button::Home=>self.screen=Screen::Home,
            },
            Screen::Setup(tool)=>match button {
                Button::Up=>{let len=self.fields(tool).len();self.setup_index=(self.setup_index+len-1)%len;},
                Button::Down=>self.setup_index=(self.setup_index+1)%self.fields(tool).len(),
                Button::Select=>{
                    let field=self.fields(tool)[self.setup_index];
                    if field==Field::Run {
                        if self.unavailable(tool).is_some(){self.screen=Screen::Unavailable(tool);} else {
                            self.screen=Screen::Running(tool);self.scroll=0;self.live.message=None;self.live.result_lines.clear();self.live.export_status=None;self.live.usb_paused=false;
                            return Action::Start(tool);
                        }
                    } else if field==Field::FileRecover {return Action::FileRecover(self.settings.target);} else {self.change_field(field,tool);}
                },
                Button::Back=>self.screen=Screen::Group(tool.group()),Button::Home=>self.screen=Screen::Home,
            },
            Screen::Edit(tool,password)=>match button {
                Button::Up=>self.edit_char=if self.edit_char>=126 {31}else{self.edit_char+1},
                Button::Down=>self.edit_char=if self.edit_char<=31 {126}else{self.edit_char-1},
                Button::Select=>if self.edit_char==31 {self.edit_text.pop();}else if self.edit_text.len()<if password {63}else{32} {self.edit_text.push(self.edit_char as char);},
                Button::Back=>{if password {self.password=self.edit_text.clone();}else{self.ssid=self.edit_text.clone();}self.edit_text.clear();self.screen=Screen::Setup(tool);},
                Button::Home=>{self.edit_text.clear();self.screen=Screen::Setup(tool);},
            },
            Screen::Running(tool)=>match button {
                Button::Up if tool==Tool::PktFiles=>{let count=self.live.capture_files.len().max(1);self.settings.target=((usize::from(self.settings.target)+count-1)%count) as u8;},
                Button::Down if tool==Tool::PktFiles=>self.change_field(Field::Target,tool),
                Button::Select if tool==Tool::PktFiles=>return Action::FilePreview(self.settings.target),
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>self.scroll=(self.scroll+1).min(self.scroll_limit(&self.lines(tool,&self.live))),
                Button::Select if tool.is_usb()=>{self.live.usb_paused=!self.live.usb_paused;return Action::Pause(self.live.usb_paused);},
                Button::Select|Button::Back|Button::Home=>{self.save_results(tool);self.scroll=0;self.screen=if matches!(button,Button::Home){Screen::Home}else{Screen::Results(tool)};return Action::Stop;},
            },
            Screen::Results(tool)=>match button {
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>{let live=self.results.as_ref().map(|result|&result.1).unwrap_or(&self.live);self.scroll=(self.scroll+1).min(self.scroll_limit(&self.lines(tool,live)));},
                Button::Select=>{self.setup_index=0;self.screen=Screen::Setup(tool);},Button::Back=>self.screen=Screen::Group(tool.group()),Button::Home=>self.screen=Screen::Home,
            },
            Screen::Unavailable(tool)=>match button {Button::Home=>self.screen=Screen::Home,Button::Back|Button::Select=>self.screen=Screen::Group(tool.group()),_=>{}},
            Screen::Diagnostics=>match button {
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>self.scroll=(self.scroll+1).min(self.live.probe_lines.len().saturating_sub(1)),
                Button::Back|Button::Home|Button::Select=>self.screen=Screen::Home,
            },
        }
        Action::None
    }
    fn scroll_limit(&self,lines:&[String])->usize {lines.iter().map(|line|wrap(line,self.columns).len()).sum::<usize>().saturating_sub(1)}
    fn lines(&self,tool:Tool,live:&Live)->Vec<String> {
        let mut lines=Vec::new();
        match tool.group() {
            Group::Wifi|Group::Packet=>{
                if !live.wifi_status.is_empty(){lines.push(live.wifi_status.clone());}
                lines.push(format!("{} frames   {} dropped",live.wifi_frames,live.wifi_dropped));
                if matches!(tool,Tool::WifiScan|Tool::WifiBeacon|Tool::WifiDeauth) {
                    for (index,ap) in live.aps.iter().take(32).enumerate() {
                        lines.push(format!("{}  {}",index+1,if ap.ssid.is_empty(){"Hidden network"}else{&ap.ssid}));
                        lines.push(format!("Ch {}  {} dBm  {}",ap.channel,ap.rssi,ap.security));
                        lines.push(format!("{}",ap.bssid));
                    }
                    if live.aps.is_empty(){lines.push(String::from("No networks observed yet."));}
                }
                if tool==Tool::PktFiles {for (index,name) in live.capture_files.iter().enumerate(){lines.push(format!("{} {}",if index==usize::from(self.settings.target){">"}else{" "},name));}}
                lines.extend(live.packet_lines.iter().take(128).cloned());
            },
            Group::Ble=>{
                lines.push(live.ble_status.clone());lines.push(format!("{} reports   {} devices",live.ble_frames,live.ble_devices.len()));
                for (index,device) in live.ble_devices.iter().take(32).enumerate() {
                    lines.push(format!("{}  {}",index+1,if device.name.is_empty(){"Unnamed device"}else{&device.name}));
                    lines.push(format!("{} dBm  {}",device.rssi,device.kind));lines.push(device.address.clone());
                    if !device.detail.is_empty(){lines.push(device.detail.clone());}
                }
            },
            Group::UsbHid=>{
                lines.push(live.usb_status.clone());lines.push(format!("{}% complete",live.usb_percent));lines.push(format!("{} keystrokes",live.usb_keystrokes));
                if live.usb_paused{lines.push(String::from("Paused. Select to resume."));}
                if live.usb_unsupported>0 {lines.push(format!("{} unsupported characters",live.usb_unsupported));}
            },
            Group::Rf=>{lines.push(format!("Peak channel {}",live.rf_peak));lines.push(format!("{} packets",live.rf_packets));lines.push(format!("{} dropped",live.rf_dropped));},
            Group::Gps=>lines.extend(live.gps_lines.iter().take(128).cloned()),
            Group::Network=>lines.extend(live.net_lines.iter().take(128).cloned()),
        }
        lines.extend(live.result_lines.iter().take(128).cloned());
        if let Some(status)=&live.export_status{lines.push(status.clone());}
        if let Some(message)=&live.message{lines.push(message.clone());}
        if lines.is_empty(){lines.push(String::from("Waiting for device data..."));}
        lines
    }
    fn field_label(&self,field:Field,tool:Tool)->(String,String) {
        match field {
            Field::Run=>(String::from(if tool==Tool::NetInfo {"Connect / refresh"}else{"Run"}),String::from("Select to start")),
            Field::Channel=>(String::from("Channel"),if self.settings.channel==0&&tool.group()!=Group::Rf {String::from("Hop")}else{format!("{}",self.settings.channel)}),
            Field::Filter=>(String::from("Frame filter"),String::from(match self.settings.filter {PacketFilter::All=>"All frames",PacketFilter::Management=>"Management",PacketFilter::Data=>"Data",PacketFilter::Eapol=>"EAPOL"})),
            Field::Layout=>(String::from("Keyboard layout"),String::from(match self.settings.layout {KeyboardLayout::Us=>"US",KeyboardLayout::Uk=>"UK",KeyboardLayout::De=>"German"})),
            Field::Payload=>(String::from("Payload"),self.payloads.get(usize::from(self.settings.payload)).cloned().unwrap_or_else(||String::from("No payloads loaded"))),
            Field::RfRate=>(String::from("RF data rate"),String::from(match self.settings.rf_rate {0=>"250 kbps",2=>"2 Mbps",_=>"1 Mbps"})),
            Field::RfLength=>(String::from("RF payload length"),format!("{} bytes",self.settings.rf_payload_len)),
            Field::FileRecover=>(String::from("Recover selected file"),String::from("Repair an interrupted capture")),
            Field::Target=>{
                let target=usize::from(self.settings.target);
                let name=match tool {
                    Tool::WifiBeacon|Tool::WifiDeauth=>self.live.aps.get(target).map(|ap|ap.ssid.clone()).unwrap_or_else(||String::from("No network observed")),
                    Tool::BleScan|Tool::BleSpam|Tool::BleGatt|Tool::BleHid=>self.live.ble_devices.get(target).map(|device|if device.name.is_empty(){device.address.clone()}else{device.name.clone()}).unwrap_or_else(||String::from("No device observed")),
                    Tool::NetProbe|Tool::NetServices=>format!("Local host .{}",self.settings.target),
                    Tool::PktFiles=>self.live.capture_files.get(target).cloned().unwrap_or_else(||String::from("No capture selected")),
                    _=>format!("Item {}",target+1),
                };
                (String::from("Target"),name)
            },
            Field::Stream=>(String::from("USB stream"),String::from(if self.settings.stream {"Enabled"}else{"Disabled"})),
            Field::Network=>(String::from("Scanned network"),self.live.aps.get(usize::from(self.settings.target)).map(|ap|ap.ssid.clone()).unwrap_or_else(||String::from("Scan Wi-Fi first"))),
            Field::Ssid=>(String::from("SSID"),if self.ssid.is_empty(){String::from("Select to enter")}else{self.ssid.clone()}),
            Field::Password=>(String::from("Password"),if self.password.is_empty(){String::from("Open / select to enter")}else{"*".repeat(self.password.len().min(16))}),
            Field::Previous=>(String::from("Last result"),String::from("Open saved session")),
        }
    }
    fn text(canvas:&mut impl Canvas,x:i16,y:i16,width:u16,text:&str,fg:Rgb565,bg:Rgb565,scale:u8) {
        if y<0||y.saturating_add(7*i16::from(scale))>canvas.height() as i16||x<0{return;}
        let width=width.min(canvas.width().saturating_sub(x as u16));
        let columns=usize::from(width/(u16::from(font::ADVANCE)*u16::from(scale)));
        if columns>0 {canvas.draw_text(x,y,&ellipsize(text,columns),fg,bg,scale);}
    }
    fn footer_y(canvas:&impl Canvas)->i16 {canvas.height().saturating_sub(20) as i16}
    fn bottom(&self,canvas:&impl Canvas)->i16 {Self::footer_y(canvas)-if self.live.message.is_some() {32}else{4}}
    fn header(&self,canvas:&mut impl Canvas,title:&str,subtitle:&str) {
        let width=canvas.width();canvas.fill_rect(Rect::new(0,0,width,44.min(canvas.height())),theme::SURFACE);
        let scale=if title.chars().count()*12<=usize::from(width.saturating_sub(16)){2}else{1};
        Self::text(canvas,8,8,width.saturating_sub(16),title,theme::TEXT,theme::SURFACE,scale);
        Self::text(canvas,8,31,width.saturating_sub(16),subtitle,theme::TEXT_DIM,theme::SURFACE,1);
        canvas.draw_hline(0,43,width,theme::SURFACE_ALT);
    }
    /// Selection moves repaint only old/new cards unless the page changed.
    pub fn render(&mut self,canvas:&mut impl Canvas) {
        self.columns=usize::from(canvas.width().saturating_sub(24)/6).max(1);
        let changed=self.last_rendered!=Some(self.screen)||self.last_notice!=self.live.message.is_some();
        if changed {canvas.fill_rect(Rect::new(0,0,canvas.width(),canvas.height()),theme::BACKGROUND);}
        let (title,subtitle)=match self.screen {
            Screen::Home=>(cyberdeck_core::DEVICE_NAME,if self.home_index<7{GROUPS[self.home_index].summary()}else{"Hardware, buttons and system status"}),
            Screen::Group(group)=>(group.title(),group.summary()),
            Screen::Setup(tool)=>(tool.title(),"SETUP  /  choose an option"),
            Screen::Running(tool)=>(tool.title(),if self.live.usb_paused{"PAUSED  /  select to resume"}else{"LIVE  /  scroll for details"}),
            Screen::Results(tool)=>(tool.title(),"RESULTS  /  select to run again"),
            Screen::Unavailable(tool)=>(tool.title(),"Unavailable"),
            Screen::Edit(_,password)=>(if password{"Enter password"}else{"Enter SSID"},"UP/DOWN character  SELECT add"),
            Screen::Diagnostics=>("Diagnostics","Hardware and input status"),
        };
        self.header(canvas,title,subtitle);
        let mut selection=0;let mut page=0;
        match self.screen {
            Screen::Home=>{
                selection=self.home_index;
                let columns=if canvas.width()>=200{2}else{1};
                let rows=((self.bottom(canvas)-50).max(58) as usize/58).max(1);
                let count=rows*columns;page=self.home_index/count;
                let full=changed||page!=self.last_page||self.live.message.is_some();
                if full {canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);}
                let tile_w=canvas.width().saturating_sub(20)/columns as u16;
                for slot in 0..count {
                    let index=page*count+slot;if index>=8{break;}
                    if !full&&index!=self.home_index&&index!=self.last_selection{continue;}
                    let x=8+(slot%columns) as i16*tile_w as i16;let y=50+(slot/columns) as i16*58;
                    let selected=index==self.home_index;let bg=if selected{theme::SELECTION}else{theme::SURFACE};
                    let rect=Rect::new(x,y,tile_w.saturating_sub(6),52);canvas.fill_rect(rect,bg);
                    if selected {canvas.fill_rect(Rect::new(x,y,3,52),theme::ACCENT);}
                    let code=["WI","PC","BT","US","RF","GP","IP","DG"][index];
                    let label=if index<7 {GROUPS[index].title()}else{"Diagnostics"};
                    Self::text(canvas,x+10,y+8,rect.w.saturating_sub(16),code,if selected{theme::ACCENT}else{theme::TEXT_DIM},bg,2);
                    Self::text(canvas,x+10,y+35,rect.w.saturating_sub(16),label,theme::TEXT,bg,1);
                }
            },
            Screen::Group(group)=>{
                selection=self.tool_index;
                let rows=((self.bottom(canvas)-50).max(44) as usize/44).max(1);page=selection/rows;
                let full=changed||page!=self.last_page||self.live.message.is_some();
                if full {canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);}
                for (row,tool) in group.tools().iter().skip(page*rows).take(rows).enumerate() {
                    let index=page*rows+row;if !full&&index!=selection&&index!=self.last_selection{continue;}
                    let y=50+row as i16*44;let selected=index==selection;let bg=if selected{theme::SELECTION}else{theme::SURFACE};
                    canvas.fill_rect(Rect::new(8,y,canvas.width().saturating_sub(20),38),bg);
                    if selected {canvas.fill_rect(Rect::new(8,y,3,38),theme::ACCENT);}
                    Self::text(canvas,18,y+7,canvas.width().saturating_sub(36),tool.title(),theme::TEXT,bg,1);
                    Self::text(canvas,18,y+22,canvas.width().saturating_sub(36),tool.description(),theme::TEXT_DIM,bg,1);
                }
            },
            Screen::Setup(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let fields=self.fields(tool);selection=self.setup_index;
                let rows=((self.bottom(canvas)-50).max(36) as usize/36).max(1);page=selection/rows;
                for (row,field) in fields.iter().skip(page*rows).take(rows).enumerate() {
                    let index=page*rows+row;let y=50+row as i16*36;let bg=if index==selection{theme::SELECTION}else{theme::SURFACE};
                    canvas.fill_rect(Rect::new(8,y,canvas.width().saturating_sub(20),32),bg);
                    if index==selection {canvas.fill_rect(Rect::new(8,y,3,32),theme::ACCENT);}
                    let (label,value)=self.field_label(*field,tool);
                    Self::text(canvas,18,y+5,canvas.width().saturating_sub(36),&label,if *field==Field::Run{theme::ACCENT}else{theme::TEXT},bg,1);
                    Self::text(canvas,18,y+19,canvas.width().saturating_sub(36),&value,theme::TEXT_DIM,bg,1);
                }
                if tool.is_usb() {
                    let y=50+fields.len().min(rows) as i16*36;
                    if y+18<self.bottom(canvas) {Self::text(canvas,10,y+4,canvas.width().saturating_sub(20),"Payload preview",theme::TEXT_DIM,theme::BACKGROUND,1);self.render_lines(canvas,&self.live.usb_preview,y+20,0);}
                }
            },
            Screen::Running(tool)|Screen::Results(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let live=if matches!(self.screen,Screen::Results(_)){self.results.as_ref().map(|result|&result.1).unwrap_or(&self.live)}else{&self.live};
                let mut top=54;
                if tool.is_usb() {draw_bar(canvas,Rect::new(10,52,canvas.width().saturating_sub(24),6),u16::from(live.usb_percent)*10,theme::ACCENT);top=70;}
                if tool==Tool::RfSpectrum&&!live.rf_envelope.is_empty()&&self.bottom(canvas)>140 {
                    let width=canvas.width().saturating_sub(24);let count=live.rf_envelope.len().min(usize::from(width)).max(1);
                    for index in 0..count {
                        let x=10+((index as u32*u32::from(width))/count as u32) as i16;
                        let next=10+(((index+1) as u32*u32::from(width))/count as u32) as i16;
                        let sample=index*live.rf_envelope.len()/count;
                        let h=1+u16::from(live.rf_envelope[sample])*48/255;
                        canvas.fill_rect(Rect::new(x,106-h as i16,(next-x).max(1) as u16,h),theme::ACCENT);
                    }
                    canvas.draw_hline(10,108,width,theme::SURFACE_ALT);top=120;
                }
                self.render_lines(canvas,&self.lines(tool,live),top,self.scroll);
            },
            Screen::Unavailable(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let reason=self.unavailable(tool).unwrap_or_else(||String::from("This tool is available. Return and select it again."));
                self.render_lines(canvas,&[reason,String::from("Other modules remain available.")],56,0);
            },
            Screen::Edit(_,password)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let display=if password{"*".repeat(self.edit_text.len())}else{self.edit_text.clone()};
                self.render_lines(canvas,&[display,format!("{} characters",self.edit_text.len()),String::from("BACK saves  HOME cancels")],54,0);
                let y=(self.bottom(canvas)-48).max(104);
                let label=if self.edit_char==31 {String::from("DELETE")}else{format!("{}  ASCII {}",self.edit_char as char,self.edit_char)};
                Self::text(canvas,10,y,canvas.width().saturating_sub(24),&label,theme::ACCENT,theme::BACKGROUND,2);
            },
            Screen::Diagnostics=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let mut lines=self.live.probe_lines.clone();
                if lines.is_empty(){lines.push(String::from("Waiting for hardware probes..."));}
                lines.push(String::from("UP DOWN SEL BACK HOME"));
                lines.push(self.live.buttons.iter().map(|pressed|if *pressed{'#'}else{'.'}).collect());
                self.render_lines(canvas,&lines,54,self.scroll);
            },
        }
        self.render_footer(canvas);
        self.last_rendered=Some(self.screen);self.last_selection=selection;self.last_page=page;self.last_notice=self.live.message.is_some();
    }
    fn render_lines(&self,canvas:&mut impl Canvas,lines:&[String],top:i16,scroll:usize) {
        let columns=usize::from(canvas.width().saturating_sub(24)/6).max(1);
        let mut wrapped=Vec::new();
        for line in lines {wrapped.extend(wrap(line,columns));}
        let rows=((self.bottom(canvas)-top).max(0) as usize/14).max(1);
        let offset=scroll.min(wrapped.len().saturating_sub(rows));
        for (row,line) in wrapped.iter().skip(offset).take(rows).enumerate() {
            let y=top+row as i16*14;if y+7>self.bottom(canvas){break;}
            Self::text(canvas,10,y,canvas.width().saturating_sub(24),line,if row==0{theme::ACCENT}else{theme::TEXT},theme::BACKGROUND,1);
        }
        if wrapped.len()>rows {
            let h=(self.bottom(canvas)-top).max(0) as u16;
            let thumb=(usize::from(h)*rows/wrapped.len()).max(4).min(usize::from(h)) as u16;
            let y=top+((usize::from(h.saturating_sub(thumb))*offset)/wrapped.len().saturating_sub(rows).max(1)) as i16;
            canvas.fill_rect(Rect::new(canvas.width().saturating_sub(5) as i16,top,2,h),theme::SURFACE_ALT);
            canvas.fill_rect(Rect::new(canvas.width().saturating_sub(5) as i16,y,2,thumb),theme::ACCENT);
        }
    }
    fn render_footer(&self,canvas:&mut impl Canvas) {
        let y=Self::footer_y(canvas);canvas.fill_rect(Rect::new(0,y,canvas.width(),20),theme::SURFACE);
        let hint=match self.screen {
            Screen::Home=>"UP/DOWN  SEL open",Screen::Group(_)=>"SEL setup  BACK home",
            Screen::Setup(_)=>"SEL choose  BACK tools",Screen::Running(tool) if tool.is_usb()=>"SEL pause  BACK stop",
            Screen::Running(Tool::PktFiles)=>"SEL preview  BACK stop",
            Screen::Running(_)=>"SEL/BACK stop",Screen::Results(_)=>"SEL setup  BACK tools",
            Screen::Edit(_,_)=>"BACK save  HOME cancel",_=>"BACK returns",
        };
        Self::text(canvas,8,y+6,canvas.width().saturating_sub(16),hint,theme::TEXT_DIM,theme::SURFACE,1);
        if let Some(message)=&self.live.message {
            let top=y-32;canvas.fill_rect(Rect::new(0,top,canvas.width(),32),theme::SURFACE_ALT);
            let columns=usize::from(canvas.width().saturating_sub(16)/6).max(1);
            for (row,line) in wrap(message,columns).iter().take(2).enumerate(){Self::text(canvas,8,top+5+row as i16*12,canvas.width().saturating_sub(16),line,theme::WARNING,theme::SURFACE_ALT,1);}
        }
    }
}

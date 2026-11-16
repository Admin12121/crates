//! Device navigation and Canvas rendering. Drivers only run in response to Action.
pub mod assets;

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
        match self { Self::Wifi=>"Wi-Fi",Self::Packet=>"Capture",Self::Ble=>"Bluetooth",Self::UsbHid=>"USB Typing",Self::Rf=>"Radio",Self::Gps=>"GPS",Self::Network=>"Network" }
    }
    const fn device(self)->DeviceClass {
        match self {Self::Wifi|Self::Packet|Self::Network=>DeviceClass::WifiRadio,Self::Ble=>DeviceClass::BleRadio,Self::UsbHid=>DeviceClass::UsbDevice,Self::Rf=>DeviceClass::Nrf24,Self::Gps=>DeviceClass::Gps}
    }
    pub const fn tools(self)->&'static [Tool] {
        match self {
            Self::Wifi=>&[Tool::WifiScan,Tool::WifiCapture,Tool::WifiHandshake,Tool::WifiWps,Tool::WifiClients,Tool::WifiEvilTwin,Tool::WifiKarma,Tool::WifiBeacon,Tool::WifiDeauth,Tool::WifiDisassoc,Tool::WifiAuthFlood,Tool::WifiProbeFlood],
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
    WifiScan, WifiCapture, WifiBeacon, WifiDeauth, WifiDisassoc, WifiAuthFlood, WifiProbeFlood, WifiHandshake, WifiWps, WifiClients, WifiEvilTwin, WifiKarma,
    PktCapture, PktAnalyse, PktFiles, PktStream,
    BleScan, BleSpam, BleGatt, BleHid, HidIntro, HidDucky,
    RfSpectrum, RfCapture, GpsStatus, GpsRecord, GpsWardrive,
    NetInfo, NetDiscover, NetProbe, NetServices,
}
impl Tool {
    pub const fn title(self)->&'static str {
        match self {
            Self::WifiScan=>"Scan Wi-Fi",Self::WifiCapture=>"Record Wi-Fi",Self::WifiBeacon=>"Fake networks",Self::WifiDeauth=>"Disconnect test",Self::WifiDisassoc=>"Soft disconnect",Self::WifiAuthFlood=>"Join flood",Self::WifiProbeFlood=>"Name flood",
            Self::WifiHandshake=>"Password capture",Self::WifiWps=>"WPS info",Self::WifiClients=>"Nearby devices",
            Self::WifiEvilTwin=>"Evil twin",Self::WifiKarma=>"Name requests",
            Self::PktCapture=>"Live capture",Self::PktAnalyse=>"Packet details",Self::PktFiles=>"Saved captures",Self::PktStream=>"Stream to PC",
            Self::BleScan=>"Scan Bluetooth",Self::BleSpam=>"Fake devices",Self::BleGatt=>"Device services",Self::BleHid=>"Bluetooth keyboard",
            Self::HidIntro=>"Typing test",Self::HidDucky=>"Script library",Self::RfSpectrum=>"Channel activity",Self::RfCapture=>"Radio capture",
            Self::GpsStatus=>"GPS position",Self::GpsRecord=>"Record route",Self::GpsWardrive=>"Wardrive log",
            Self::NetInfo=>"Join Wi-Fi",Self::NetDiscover=>"Find devices",Self::NetProbe=>"Check device",Self::NetServices=>"Open ports",
        }
    }
    pub const fn group(self)->Group {
        match self {
            Self::WifiScan|Self::WifiCapture|Self::WifiBeacon|Self::WifiDeauth|Self::WifiDisassoc|Self::WifiAuthFlood|Self::WifiProbeFlood|Self::WifiHandshake|Self::WifiWps|Self::WifiClients|Self::WifiEvilTwin|Self::WifiKarma=>Group::Wifi,
            Self::PktCapture|Self::PktAnalyse|Self::PktFiles|Self::PktStream=>Group::Packet,
            Self::BleScan|Self::BleSpam|Self::BleGatt|Self::BleHid=>Group::Ble,
            Self::HidIntro|Self::HidDucky=>Group::UsbHid,Self::RfSpectrum|Self::RfCapture=>Group::Rf,
            Self::GpsStatus|Self::GpsRecord|Self::GpsWardrive=>Group::Gps,
            Self::NetInfo|Self::NetDiscover|Self::NetProbe|Self::NetServices=>Group::Network,
        }
    }
    const fn is_usb(self)->bool {matches!(self,Self::HidIntro|Self::HidDucky)}
    /// Screens that drive a HID payload, over USB or BLE.
    const fn is_pausable(self)->bool {self.is_usb()||matches!(self,Self::BleHid)}
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
    /// BLE advertising campaign index for the Bluetooth screen.
    pub campaign:u8,
    pub stream:bool,
    pub rf_rate:u8,
    pub rf_payload_len:u8,
}
impl Default for Settings {
    fn default()->Self {Self {channel:1,filter:PacketFilter::All,layout:KeyboardLayout::Us,payload:0,target:0,campaign:0,stream:false,rf_rate:1,rf_payload_len:32}}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { None, Start(Tool), Stop, Pause(bool), FilePreview(u8), FileRecover(u8) }

#[derive(Default, Clone)]
pub struct Live {
    pub wifi_status:String,pub wifi_busy:bool,pub aps:Vec<ApRow>,pub wifi_frames:u32,pub wifi_dropped:u32,
    /// Passive EAPOL/PMKID findings, shown as the handshake screen's headline.
    pub eapol:u32,pub handshakes:u32,pub pmkids:u32,
    /// Captive-portal activity, shown on the Evil Twin screen.
    pub portal_clients:u32,pub portal_requests:u32,
    /// Karma view: distinct requested SSIDs and the station count behind them.
    pub probe_ssids:u32,pub probe_rows:u32,
    pub rf_envelope:Vec<u8>,pub rf_waterfall:Vec<u8>,pub rf_peak:u8,pub rf_packets:u32,pub rf_dropped:u32,
    pub ble_status:String,pub ble_devices:Vec<BleDevice>,pub ble_frames:u32,
    pub usb_status:String,pub usb_percent:u8,pub usb_keystrokes:u32,pub usb_unsupported:u32,pub usb_paused:bool,
    pub buttons:[bool;5],pub probe_lines:Vec<String>,pub message:Option<String>,pub battery:Option<u8>,pub tick:u8,
    pub gps_lines:Vec<String>,pub net_lines:Vec<String>,pub packet_lines:Vec<String>,pub result_lines:Vec<String>,
    pub usb_preview:Vec<String>,pub capture_files:Vec<String>,pub export_status:Option<String>,
}
impl Live {
    fn same_visual(&self,other:&Self)->bool {
        self.wifi_status==other.wifi_status && self.wifi_busy==other.wifi_busy &&
        self.aps.len()==other.aps.len() && self.aps.iter().zip(&other.aps).all(|(a,b)| a.ssid==b.ssid&&a.bssid==b.bssid&&a.channel==b.channel&&a.rssi==b.rssi&&a.security==b.security) &&
        self.ble_devices.len()==other.ble_devices.len() && self.ble_devices.iter().zip(&other.ble_devices).all(|(a,b)|a.address==b.address&&a.name==b.name&&a.rssi==b.rssi&&a.kind==b.kind&&a.detail==b.detail) &&
        self.wifi_frames==other.wifi_frames&&self.wifi_dropped==other.wifi_dropped&&
        self.eapol==other.eapol&&self.handshakes==other.handshakes&&self.pmkids==other.pmkids&&
        self.portal_clients==other.portal_clients&&self.portal_requests==other.portal_requests&&
        self.probe_ssids==other.probe_ssids&&self.probe_rows==other.probe_rows&&
        self.ble_status==other.ble_status&&self.ble_frames==other.ble_frames&&
        self.rf_envelope==other.rf_envelope&&self.rf_waterfall==other.rf_waterfall&&self.rf_peak==other.rf_peak&&self.rf_packets==other.rf_packets&&self.rf_dropped==other.rf_dropped&&
        self.usb_status==other.usb_status&&self.usb_percent==other.usb_percent&&self.usb_keystrokes==other.usb_keystrokes&&self.usb_unsupported==other.usb_unsupported&&self.usb_paused==other.usb_paused&&
        self.gps_lines==other.gps_lines&&self.net_lines==other.net_lines&&self.packet_lines==other.packet_lines&&self.result_lines==other.result_lines&&self.usb_preview==other.usb_preview&&self.capture_files==other.capture_files&&self.export_status==other.export_status&&self.message==other.message
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen { Splash, CategoryIntro(usize), Group(Group), Setup(Tool), Running(Tool), Results(Tool), Unavailable(Tool), Edit(Tool,bool), Diagnostics }
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
enum Field { Run, Channel, Filter, Layout, Payload, Target, Stream, Network, Ssid, Password, Previous, RfRate, RfLength, FileRecover, Campaign }
const SIN5:[u16;19]=[0,22,44,66,88,108,128,147,165,181,196,210,222,232,241,247,252,255,256];
pub struct App {
    screen:Screen,tool_index:usize,setup_index:usize,scroll:usize,
    registry:PeripheralRegistry,live:Live,settings:Settings,availability:Vec<(Tool,Option<String>)>,payloads:Vec<String>,
    ssid:String,password:String,edit_text:String,edit_char:u8,
    results:Option<(Tool,Live)>,needs_render:bool,last_rendered:Option<Screen>,last_selection:usize,last_page:usize,last_notice:bool,columns:usize,
    splash_start:u64,splash_elapsed:u64,splash_reveal:usize,intro_start:u64,intro_elapsed:u64,anim_now:u64,
}
impl App {
    pub fn new(registry:PeripheralRegistry)->Self {
        Self {screen:Screen::CategoryIntro(0),splash_start:0,splash_elapsed:0,splash_reveal:0,intro_start:0,intro_elapsed:0,anim_now:0,tool_index:0,setup_index:0,scroll:0,registry,live:Live::default(),settings:Settings::default(),availability:Vec::new(),payloads:Vec::new(),ssid:String::new(),password:String::new(),edit_text:String::new(),edit_char:b'a',results:None,needs_render:true,last_rendered:None,last_selection:0,last_page:usize::MAX,last_notice:false,columns:36}
    }
    pub fn intro_active(&self)->bool {matches!(self.screen,Screen::CategoryIntro(_))}
    /// Wall clock for screens that need one. The category intro draws once and
    /// stays put (no refresh loop); after 5 s it self-advances to the tool list
    /// so a dead button can never trap the user on it.
    pub fn set_anim_clock(&mut self,now:u64) {
        self.anim_now=now;
        if let Screen::CategoryIntro(index)=self.screen {
            self.intro_elapsed=now.saturating_sub(self.intro_start);
            if self.intro_elapsed>=5000 {
                self.scroll=0;self.tool_index=0;self.screen=Screen::CategoryIntro(index);self.needs_render=true;
            }
        }
    }
    /// Show the boot splash; `splash_tick` drives its reveal and auto-dismiss.
    pub fn enter_splash(&mut self,now:u64) {
        self.screen=Screen::Splash;self.splash_start=now;self.splash_elapsed=0;self.splash_reveal=0;self.needs_render=true;
    }
    pub fn splash_active(&self)->bool {self.screen==Screen::Splash}
    pub fn splash_tick(&mut self,now:u64) {
        if self.screen!=Screen::Splash {return;}
        self.splash_elapsed=now.saturating_sub(self.splash_start);
        // One boot line every 120 ms after the logo has had a moment on screen.
        self.splash_reveal=usize::try_from(self.splash_elapsed.saturating_sub(300)/120).unwrap_or(usize::MAX);
        self.needs_render=true;
        if self.splash_elapsed>=2600 {self.screen=Screen::CategoryIntro(0);self.needs_render=true;}
    }
    fn group_index(group:Group)->usize {GROUPS.iter().position(|g|*g==group).unwrap_or(0)}
    /// Per-category accent color.
    fn group_accent(group:Group)->Rgb565 {
        match group {
            Group::Wifi=>Rgb565::rgb(0,190,255),
            Group::Packet=>Rgb565::rgb(0,230,118),
            Group::Ble=>Rgb565::rgb(187,134,252),
            Group::UsbHid=>Rgb565::rgb(255,193,7),
            Group::Rf=>Rgb565::rgb(255,87,34),
            Group::Gps=>Rgb565::rgb(105,240,174),
            Group::Network=>Rgb565::rgb(64,158,255),
        }
    }
    /// The boot probe checklist in first-boot order: (passed, short label).
    fn boot_lines(&self)->Vec<(bool,String)> {
        const ORDER:[(DeviceClass,&str);9]=[
            (DeviceClass::Display,"DISPLAY"),(DeviceClass::Input,"INPUT"),(DeviceClass::BatteryAdc,"BATTERY"),
            (DeviceClass::WifiRadio,"WI-FI"),(DeviceClass::SdCard,"SD CARD"),(DeviceClass::UsbDevice,"USB"),
            (DeviceClass::BleRadio,"BLUETOOTH"),(DeviceClass::Nrf24,"NRF24"),(DeviceClass::Gps,"GPS"),
        ];
        let mut out=Vec::new();
        for (class,label) in ORDER {
            if let Some(state)=self.registry.state(class) {
                let ok=matches!(state,DeviceState::Ready);
                out.push((ok,alloc::format!("[{}] {}",if ok {"OK"}else{"--"},label)));
            }
        }
        out
    }
    pub fn settings(&self)->Settings {self.settings}
    pub fn active_tool(&self)->Option<Tool> {if let Screen::Running(tool)=self.screen {Some(tool)} else {None}}
    pub fn usb_paused(&self)->bool {self.live.usb_paused}
    /// True while a screen that lists payloads is visible, so storage can rescan it.
    pub fn wants_payloads(&self)->bool {
        matches!(self.screen,
            Screen::Group(Group::UsbHid)
            |Screen::Setup(Tool::HidIntro|Tool::HidDucky|Tool::BleHid)
            |Screen::Running(Tool::HidIntro|Tool::HidDucky|Tool::BleHid))
    }
    /// True while a screen that reads the passive Wi-Fi tables is visible, so
    /// the snapshot cost is only paid where the data is shown.
    pub fn wants_passive(&self)->bool {
        match self.screen {
            Screen::Setup(tool)|Screen::Running(tool)|Screen::Results(tool)|Screen::Unavailable(tool)=>matches!(tool.group(),Group::Wifi|Group::Packet),
            _=>false,
        }
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
        if let Screen::Results(tool)=self.screen
            && let Some((saved_tool,saved))=&mut self.results
                && *saved_tool==tool {
                    if live.export_status.is_some(){saved.export_status=live.export_status.clone();}
                    if !live.result_lines.is_empty(){saved.result_lines=live.result_lines.clone();}
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
            Tool::WifiEvilTwin=>fields.extend([Field::Channel,Field::Ssid]),
            Tool::WifiKarma=>fields.push(Field::Channel),
            Tool::WifiDeauth|Tool::WifiDisassoc=>fields.extend([Field::Channel,Field::Target]),
            Tool::WifiBeacon|Tool::WifiAuthFlood|Tool::WifiProbeFlood=>fields.push(Field::Channel),
            Tool::PktStream=>fields.extend([Field::Channel,Field::Filter,Field::Stream]),
            Tool::PktFiles=>fields.extend([Field::Target,Field::FileRecover]),
            Tool::BleScan|Tool::BleGatt=>fields.push(Field::Target),
            Tool::BleSpam=>fields.push(Field::Campaign),
            Tool::BleHid=>fields.extend([Field::Payload,Field::Layout]),
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
                let count=match tool {Tool::PktFiles=>self.live.capture_files.len(),Tool::WifiBeacon|Tool::WifiDeauth|Tool::WifiDisassoc=>self.live.aps.len(),Tool::BleScan|Tool::BleGatt|Tool::BleHid=>self.live.ble_devices.len(),_=>255};
                self.settings.target=if matches!(tool,Tool::NetProbe|Tool::NetServices|Tool::NetDiscover){self.settings.target%254+1}else{((usize::from(self.settings.target)+1)%count.max(1)) as u8};
            },
            Field::Campaign=>self.settings.campaign=(self.settings.campaign+1)%cyberdeck_core::ble::spam::SpamCampaign::all().len() as u8,
            Field::Stream=>self.settings.stream= !self.settings.stream,
            Field::RfRate=>self.settings.rf_rate=(self.settings.rf_rate+1)%3,
            Field::RfLength=>self.settings.rf_payload_len=self.settings.rf_payload_len%32+1,
            Field::FileRecover=>{},
            Field::Network=>if !self.live.aps.is_empty() {
                // The shared target may still be a host octet or an index from an older scan.
                let target=usize::from(self.settings.target).min(self.live.aps.len()-1);
                let target=if self.ssid.is_empty(){target}else{(target+1)%self.live.aps.len()};
                self.settings.target=target as u8;
                self.ssid=self.live.aps[target].ssid.clone();
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
            Screen::Splash=>{self.screen=Screen::CategoryIntro(0);}
            // The intro IS the menu: up/down switches module, select opens it.
            Screen::CategoryIntro(index)=>match button {
                Button::Up=>{self.scroll=0;self.screen=Screen::CategoryIntro((index+7)%8);}
                Button::Down=>{self.scroll=0;self.screen=Screen::CategoryIntro((index+1)%8);}
                Button::Select=>{self.scroll=0;self.tool_index=0;self.screen=if index<7 {Screen::Group(GROUPS[index])}else{Screen::Diagnostics};}
                _=>{}
            },
            Screen::Group(group)=>match button {
                Button::Down=>self.tool_index=(self.tool_index+1)%group.tools().len(),
                Button::Up=>self.tool_index=(self.tool_index+group.tools().len()-1)%group.tools().len(),
                Button::Select=>{let tool=group.tools()[self.tool_index];if matches!(tool,Tool::NetDiscover|Tool::NetProbe|Tool::NetServices){self.settings.target=self.settings.target.clamp(1,254);}self.setup_index=0;self.scroll=0;self.settings.channel=self.settings.channel.min(if group==Group::Rf {125}else{13});self.screen=if self.unavailable(tool).is_some(){Screen::Unavailable(tool)}else{Screen::Setup(tool)};},
                Button::Back|Button::Home=>{self.scroll=0;self.screen=Screen::CategoryIntro(Self::group_index(group));}
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
                Button::Back=>self.screen=Screen::Group(tool.group()),Button::Home=>{self.scroll=0;self.screen=Screen::CategoryIntro(Self::group_index(tool.group()));},
            },
            Screen::Edit(tool,password)=>match button {
                Button::Up=>self.edit_char=if self.edit_char>=126 {31}else{self.edit_char+1},
                Button::Down=>self.edit_char=if self.edit_char<=31 {126}else{self.edit_char-1},
                Button::Select=>if self.edit_char==31 {self.edit_text.pop();}else if self.edit_text.len()<if password {63}else{32} {self.edit_text.push(self.edit_char as char);},
                Button::Back=>{if password {self.password=self.edit_text.clone();}else{self.ssid=self.edit_text.clone();}self.edit_text.clear();self.screen=Screen::Setup(tool);},
                Button::Home=>{self.edit_text.clear();self.screen=Screen::CategoryIntro(Self::group_index(tool.group()));},
            },
            Screen::Running(tool)=>match button {
                Button::Up if tool==Tool::PktFiles=>{let count=self.live.capture_files.len().max(1);self.settings.target=((usize::from(self.settings.target)+count-1)%count) as u8;},
                Button::Down if tool==Tool::PktFiles=>self.change_field(Field::Target,tool),
                Button::Select if tool==Tool::PktFiles=>return Action::FilePreview(self.settings.target),
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>self.scroll=(self.scroll+1).min(self.scroll_limit(&self.lines(tool,&self.live))),
                Button::Select if tool.is_pausable()=>{self.live.usb_paused= !self.live.usb_paused;return Action::Pause(self.live.usb_paused);},
                Button::Select=>{self.save_results(tool);self.scroll=0;self.screen=Screen::Results(tool);return Action::Stop;},
                Button::Back=>{self.save_results(tool);self.scroll=0;self.screen=Screen::Results(tool);return Action::Stop;},
                Button::Home=>{self.save_results(tool);self.scroll=0;self.screen=Screen::CategoryIntro(Self::group_index(tool.group()));return Action::Stop;},
            },
            Screen::Results(tool)=>match button {
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>{let live=self.results.as_ref().map(|result|&result.1).unwrap_or(&self.live);self.scroll=(self.scroll+1).min(self.scroll_limit(&self.lines(tool,live)));},
                Button::Select=>{self.setup_index=0;self.screen=Screen::Setup(tool);},Button::Back|Button::Home=>{self.scroll=0;self.screen=Screen::CategoryIntro(Self::group_index(tool.group()));},
            },
            Screen::Unavailable(tool)=>match button {Button::Home|Button::Back|Button::Select=>{self.scroll=0;self.screen=Screen::CategoryIntro(Self::group_index(tool.group()));},_=>{}},
            Screen::Diagnostics=>match button {
                Button::Up=>self.scroll=self.scroll.saturating_sub(1),Button::Down=>self.scroll=(self.scroll+1).min(self.live.probe_lines.len().saturating_sub(1)),
                Button::Back|Button::Home|Button::Select=>{self.scroll=0;self.screen=Screen::CategoryIntro(7);},
            },
        }
        Action::None
    }
    fn scroll_limit(&self,lines:&[String])->usize {
        lines.iter().map(|line|{
            let indent=line.chars().take_while(|ch|*ch==' ').count().min(8).min(self.columns.saturating_sub(2));
            wrap(line.trim_start_matches(' '),self.columns.saturating_sub(indent).max(1)).len()
        }).sum::<usize>().saturating_sub(1)
    }
    fn lines(&self,tool:Tool,live:&Live)->Vec<String> {
        let mut lines=Vec::new();
        match tool.group() {
            Group::Wifi|Group::Packet=>{
                if !live.wifi_status.is_empty(){lines.push(live.wifi_status.clone());}
                if matches!(tool,Tool::WifiScan|Tool::WifiBeacon|Tool::WifiDeauth|Tool::WifiDisassoc) {
                    // One line per network: name first, then the two numbers that matter.
                    for ap in live.aps.iter().take(32) {
                        let name=if ap.ssid.is_empty(){"HIDDEN"}else{ap.ssid.as_str()};
                        lines.push(format!("{name}  CH {}  SIG {}",ap.channel,ap.rssi));
                    }
                    if live.aps.is_empty(){lines.push(String::from("No networks found yet"));}
                }
                if tool==Tool::PktFiles {for (index,name) in live.capture_files.iter().enumerate(){lines.push(format!("{} {}",if index==usize::from(self.settings.target){">"}else{" "},name));}}
                lines.extend(live.packet_lines.iter().take(128).cloned());
            },
            Group::Ble=>{
                if tool==Tool::BleHid {
                    lines.push(live.usb_status.clone());
                } else {
                    lines.push(live.ble_status.clone());
                    if tool==Tool::BleGatt {lines.extend(live.packet_lines.iter().take(128).cloned());}
                    for device in live.ble_devices.iter().take(32) {
                        let name=if device.name.is_empty(){"UNNAMED"}else{device.name.as_str()};
                        lines.push(format!("{name}  SIG {}  {}",device.rssi,device.kind));
                    }
                }
            },
            Group::UsbHid=>lines.push(live.usb_status.clone()),
            Group::Rf=>lines.push(format!("{} MISSED",live.rf_dropped)),
            Group::Gps=>lines.extend(live.gps_lines.iter().take(128).cloned()),
            Group::Network=>lines.extend(live.net_lines.iter().take(128).cloned()),
        }
        if tool.is_pausable() {
            if live.usb_paused{lines.push(String::from("PAUSED"));}
            if live.usb_unsupported>0 {lines.push(format!("{} SKIPPED",live.usb_unsupported));}
        }
        lines.extend(live.result_lines.iter().take(128).cloned());
        if let Some(status)=&live.export_status{lines.push(status.clone());}
        // The outcome often repeats the status line; show it only once.
        if let Some(message)=&live.message&& lines.first().map(String::as_str)!=Some(message.as_str()){lines.push(message.clone());}
        if lines.is_empty(){lines.push(String::from("Waiting for data..."));}
        lines
    }
    fn field_label(&self,field:Field,tool:Tool)->(String,String) {
        match field {
            Field::Run=>(String::from(if tool==Tool::NetInfo {"Join / refresh"}else{"Start"}),String::from("GO")),
            Field::Channel=>(String::from("Channel"),if self.settings.channel==0&&tool.group()!=Group::Rf {String::from("All")}else{format!("{}",self.settings.channel)}),
            Field::Filter=>(String::from("Packet type"),String::from(match self.settings.filter {PacketFilter::All=>"Everything",PacketFilter::Management=>"Beacons",PacketFilter::Data=>"Data",PacketFilter::Eapol=>"Logins"})),
            Field::Layout=>(String::from("Keyboard layout"),String::from(match self.settings.layout {KeyboardLayout::Us=>"US",KeyboardLayout::Uk=>"UK",KeyboardLayout::De=>"German"})),
            Field::Payload=>(String::from("Script"),self.payloads.get(usize::from(self.settings.payload)).cloned().unwrap_or_else(||String::from("No scripts yet"))),
            Field::RfRate=>(String::from("Radio speed"),String::from(match self.settings.rf_rate {0=>"Slow",2=>"Fast",_=>"Normal"})),
            Field::RfLength=>(String::from("Packet size"),format!("{} bytes",self.settings.rf_payload_len)),
            Field::FileRecover=>(String::from("Fix broken capture"),String::from("Repair a partial file")),
            Field::Target=>{
                let target=usize::from(self.settings.target);
                let name=match tool {
                    Tool::WifiBeacon|Tool::WifiDeauth|Tool::WifiDisassoc=>self.live.aps.get(target).map(|ap|ap.ssid.clone()).unwrap_or_else(||String::from("No network observed")),
                    Tool::BleScan|Tool::BleGatt|Tool::BleHid=>self.live.ble_devices.get(target).map(|device|if device.name.is_empty(){device.address.clone()}else{device.name.clone()}).unwrap_or_else(||String::from("No device observed")),
                    Tool::NetProbe|Tool::NetServices=>format!("Local device .{}",self.settings.target),
                    Tool::PktFiles=>self.live.capture_files.get(target).cloned().unwrap_or_else(||String::from("No capture selected")),
                    _=>format!("Item {}",target+1),
                };
                let label=match tool {
                    Tool::WifiDeauth|Tool::WifiDisassoc=>"Pick network",Tool::BleScan|Tool::BleGatt|Tool::BleHid=>"Pick device",
                    Tool::PktFiles=>"Pick file",Tool::NetProbe|Tool::NetServices=>"Device IP",_=>"Target",
                };
                (String::from(label),name)
            },
            Field::Campaign=>{
                let label=cyberdeck_core::ble::spam::SpamCampaign::from_index(usize::from(self.settings.campaign)).map(|campaign|campaign.label()).unwrap_or("Unknown");
                (String::from("Campaign"),String::from(label))
            },
            Field::Stream=>(String::from("Stream to PC"),String::from(if self.settings.stream {"On"}else{"Off"})),
            Field::Network=>(String::from("Wi-Fi network"),self.live.aps.get(usize::from(self.settings.target)).map(|ap|ap.ssid.clone()).unwrap_or_else(||String::from("Run a scan first"))),
            Field::Ssid=>(String::from("Network name"),if self.ssid.is_empty(){String::from("Press to type")}else{self.ssid.clone()}),
            Field::Password=>(String::from("Password"),if self.password.is_empty(){String::from("Press to type")}else{"*".repeat(self.password.len().min(16))}),
            Field::Previous=>(String::from("Last run"),String::from("View the last results")),
        }
    }
    #[allow(clippy::too_many_arguments, reason = "draw call passes position, box, text and the two colors it needs")]
    fn text(canvas:&mut impl Canvas,x:i16,y:i16,width:u16,text:&str,fg:Rgb565,bg:Rgb565,scale:u8) {
        if y<0||y.saturating_add(7*i16::from(scale))>canvas.height() as i16||x<0{return;}
        let width=width.min(canvas.width().saturating_sub(x as u16));
        let columns=usize::from(width/(u16::from(font::ADVANCE)*u16::from(scale)));
        if columns>0 {canvas.draw_text(x,y,&ellipsize(text,columns),fg,bg,scale);}
    }
    /// Right-aligned, ellipsized text for label/value form rows.
    #[allow(clippy::too_many_arguments, reason = "draw call passes position, box, text and the two colors it needs")]
    fn text_right(canvas:&mut impl Canvas,right:i16,y:i16,max_width:u16,text:&str,fg:Rgb565,bg:Rgb565,scale:u8) {
        let columns=usize::from(max_width/(u16::from(font::ADVANCE)*u16::from(scale)));
        if columns==0 {return;}
        let fitted=ellipsize(text,columns);
        let width=(fitted.chars().count() as u16)*u16::from(font::ADVANCE)*u16::from(scale);
        Self::text(canvas,(right-width as i16).max(0),y,width,&fitted,fg,bg,scale);
    }
    /// The one number that screen exists to show, plus a caption and a side note.
    fn headline(tool:Tool,live:&Live)->Option<(String,String,String)> {
        let plural=|n:usize,one:&str,many:&str|String::from(if n==1 {one}else{many});
        match tool {
            Tool::WifiScan|Tool::WifiBeacon|Tool::WifiDeauth|Tool::WifiDisassoc=>{
                let count=live.aps.len();
                Some((format!("{count}"),plural(count,"NETWORK","NETWORKS"),if live.wifi_frames>0 {format!("{} PACKETS",live.wifi_frames)}else{String::new()}))
            },
            Tool::WifiHandshake=>Some((format!("{}",live.handshakes),plural(live.handshakes as usize,"LOGIN","LOGINS"),format!("{} KEYS",live.pmkids))),
            Tool::WifiEvilTwin=>Some((format!("{}",live.portal_clients),String::from("JOINED"),format!("{} VISITS",live.portal_requests))),
            Tool::WifiKarma=>Some((format!("{}",live.probe_ssids),plural(live.probe_ssids as usize,"NAME","NAMES"),format!("{} DEVICES",live.probe_rows))),
            Tool::WifiAuthFlood|Tool::WifiProbeFlood=>Some((format!("{}",live.wifi_frames),String::from("SENT"),String::new())),
            Tool::WifiCapture|Tool::WifiWps|Tool::WifiClients|Tool::PktCapture|Tool::PktAnalyse=>
                Some((format!("{}",live.wifi_frames),plural(live.wifi_frames as usize,"PACKET","PACKETS"),format!("{} MISSED",live.wifi_dropped))),
            Tool::BleScan=>Some((format!("{}",live.ble_devices.len()),plural(live.ble_devices.len(),"DEVICE","DEVICES"),format!("{} SIGNALS",live.ble_frames))),
            Tool::BleSpam=>Some((format!("{}",live.ble_frames),String::from("SENT"),String::new())),
            Tool::HidIntro|Tool::HidDucky=>Some((format!("{}%",live.usb_percent),String::from("COMPLETE"),format!("{} KEYS",live.usb_keystrokes))),
            Tool::BleHid=>Some((format!("{}%",live.usb_percent),String::from("COMPLETE"),format!("{} KEYS",live.usb_keystrokes))),
            Tool::RfSpectrum=>Some((format!("{}",live.rf_peak),String::from("CHANNEL"),String::from("BUSIEST"))),
            Tool::RfCapture=>Some((format!("{}",live.rf_packets),plural(live.rf_packets as usize,"PACKET","PACKETS"),format!("{} MISSED",live.rf_dropped))),
            _=>None,
        }
    }
    fn footer_y(canvas:&impl Canvas)->i16 {canvas.height().saturating_sub(20) as i16}
    fn bottom(&self,canvas:&impl Canvas)->i16 {Self::footer_y(canvas)-if self.live.message.is_some() {32}else{4}}
    /// The module this screen belongs to, for the accent underline.
    fn screen_group(&self)->Option<Group> {
        match self.screen {
            Screen::Group(group)=>Some(group),
            Screen::Setup(tool)|Screen::Running(tool)|Screen::Results(tool)|Screen::Unavailable(tool)=>Some(tool.group()),
            _=>None,
        }
    }
    fn header(&self,canvas:&mut impl Canvas,title:&str,subtitle:&str) {
        let width=canvas.width();
        canvas.fill_rect(Rect::new(0,0,width,44.min(canvas.height())),theme::SURFACE);
        let scale=if title.chars().count()*12<=usize::from(width.saturating_sub(16)){2}else{1};
        // A screen without a subtitle centres its title instead of leaving a gap.
        let y=if subtitle.is_empty(){15}else{10};
        // Reserve the right edge for the battery pill so long titles never collide.
        let title_room=width.saturating_sub(52);
        Self::text(canvas,8,y,title_room,title,theme::TEXT,theme::SURFACE,scale);
        if !subtitle.is_empty(){Self::text(canvas,8,31,width.saturating_sub(52),subtitle,theme::TEXT_DIM,theme::SURFACE,1);}
        if let Some(percent)=self.live.battery {
            let bx=width.saturating_sub(34) as i16;let by=10;
            let level=if percent<=10 {theme::DANGER}else if percent<=35 {theme::WARNING}else{theme::SUCCESS};
            canvas.fill_rect(Rect::new(bx,by,20,10),theme::TEXT_DIM);
            canvas.fill_rect(Rect::new(bx+1,by+1,18,8),theme::SURFACE);
            canvas.fill_rect(Rect::new(bx+20,by+2,2,6),theme::TEXT_DIM);
            let fill=(u16::from(percent)*18/100).min(18);
            if fill>0 {canvas.fill_rect(Rect::new(bx+1,by+1,fill,8),level);}
        }
        canvas.draw_hline(0,43,width,theme::SURFACE_ALT);
        // Category accent underline on every screen that belongs to a module.
        if let Some(group)=self.screen_group() {
            canvas.fill_rect(Rect::new(0,44,width,2),Self::group_accent(group));
        }
    }
    /// Thin scroll indicator for paged lists: shape instead of words.
    fn page_indicator(canvas:&mut impl Canvas,page:usize,pages:usize,top:i16,bottom:i16) {
        if pages<=1||bottom<=top+10 {return;}
        let x=canvas.width().saturating_sub(4) as i16;
        let height=(bottom-top) as u16;
        canvas.fill_rect(Rect::new(x,top,2,height),theme::SURFACE_ALT);
        let thumb=(height/pages as u16).max(10).min(height);
        let span=u32::from(height-thumb);
        let y=top+(span*page as u32/(pages as u32-1).max(1)) as i16;
        canvas.fill_rect(Rect::new(x,y,2,thumb),theme::TEXT_DIM);
    }
    /// Pictogram per module, drawn from filled rectangles: no image assets needed.
    /// Selection moves repaint only old/new cards unless the page changed.
    pub fn render(&mut self,canvas:&mut impl Canvas) {
        self.columns=usize::from(canvas.width().saturating_sub(24)/6).max(1);
        if self.screen==Screen::Splash {self.render_splash(canvas);self.last_rendered=Some(self.screen);self.last_selection=0;self.last_page=0;self.last_notice=false;return;}
        if let Screen::CategoryIntro(index)=self.screen {
            // Static intro: drawn once, self-advances, keeps input responsive.
            self.render_intro(canvas,index);
            self.last_rendered=Some(self.screen);self.last_selection=0;self.last_page=0;self.last_notice=false;return;
        }
        let changed=self.last_rendered!=Some(self.screen)||self.last_notice!=self.live.message.is_some();
        if changed {canvas.fill_rect(Rect::new(0,0,canvas.width(),canvas.height()),theme::BACKGROUND);}
        let spinner=['/','-','\\','|'][usize::from(self.live.tick)%4];
        let (title,subtitle)=match self.screen {
            Screen::Splash|Screen::CategoryIntro(_)=>(String::new(),String::new()),
            Screen::Group(group)=>(group.title().into(),String::new()),
            Screen::Setup(tool)=>(tool.title().into(),String::from("SETTINGS")),
            Screen::Running(tool)=>(tool.title().into(),if self.live.usb_paused{String::from("PAUSED")}else{alloc::format!("{spinner} LIVE")}),
            Screen::Results(tool)=>(tool.title().into(),String::from("RESULTS")),
            Screen::Unavailable(tool)=>(tool.title().into(),String::from("CAN'T START")),
            Screen::Edit(_,password)=>((if password{"PASSWORD"}else{"NETWORK NAME"}).into(),String::new()),
            Screen::Diagnostics=>(String::from("Diagnostics"),String::new()),
        };
        self.header(canvas,&title,&subtitle);
        let mut selection=0;let mut page=0;
        match self.screen {
            Screen::Splash|Screen::CategoryIntro(_)=>{}
            Screen::Group(group)=>{
                selection=self.tool_index;
                let rows=((self.bottom(canvas)-50).max(44) as usize/44).max(1);page=selection/rows;
                let full=changed||page!=self.last_page||self.live.message.is_some();
                if full {canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);}
                for (row,tool) in group.tools().iter().skip(page*rows).take(rows).enumerate() {
                    let index=page*rows+row;if !full&&index!=selection&&index!=self.last_selection{continue;}
                    let y=50+row as i16*44;let selected=index==selection;let bg=if selected{theme::SURFACE_ALT}else{theme::SURFACE};
                    let accent=Self::group_accent(group);
                    canvas.fill_rect(Rect::new(8,y,canvas.width().saturating_sub(20),38),bg);
                    if selected {
                        // Lupala-style: accent underline + chevron instead of a side bar.
                        canvas.fill_rect(Rect::new(8,y+36,canvas.width().saturating_sub(20),2),accent);
                        Self::text(canvas,(canvas.width().saturating_sub(44)) as i16,y+16,24,">>",accent,bg,1);
                    }
                    // A dot carries availability without adding a text row.
                    let dot=match self.registry.state(group.device()) {Some(DeviceState::Ready)=>theme::SUCCESS,Some(_)=>theme::DANGER,None=>theme::TEXT_DIM};
                    canvas.fill_rect(Rect::new(canvas.width().saturating_sub(16) as i16,y+18,3,3),dot);
                    Self::text(canvas,18,y+16,canvas.width().saturating_sub(40),tool.title(),if selected{theme::TEXT}else{theme::TEXT_DIM},bg,1);
                }
                if full {Self::page_indicator(canvas,page,group.tools().len().div_ceil(rows),50,self.bottom(canvas));}
            },
            Screen::Setup(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let fields=self.fields(tool);selection=self.setup_index;
                let rows=((self.bottom(canvas)-50).max(30) as usize/30).max(1);page=selection/rows;
                for (row,field) in fields.iter().skip(page*rows).take(rows).enumerate() {
                    let index=page*rows+row;let y=50+row as i16*30;
                    let selected=index==selection;
                    let bg=if selected{theme::SURFACE_ALT}else{theme::SURFACE};
                    canvas.fill_rect(Rect::new(8,y,canvas.width().saturating_sub(20),26),bg);
                    if selected {canvas.fill_rect(Rect::new(8,y,2,26),theme::TEXT);}
                    let (label,value)=self.field_label(*field,tool);
                    let run=*field==Field::Run;
                    Self::text(canvas,18,y+10,canvas.width()/2,&label,if run{theme::ACCENT}else if selected{theme::TEXT}else{theme::TEXT_DIM},bg,1);
                    Self::text_right(canvas,canvas.width().saturating_sub(16) as i16,y+10,canvas.width()/2,&value,if run{theme::ACCENT}else{theme::TEXT},bg,1);
                }
                if tool.is_pausable() {
                    let y=50+fields.len().min(rows) as i16*30;
                    if y+18<self.bottom(canvas) {Self::text(canvas,10,y+2,canvas.width().saturating_sub(20),"SCRIPT",theme::TEXT_DIM,theme::BACKGROUND,1);self.render_lines(canvas,&self.live.usb_preview,y+16,0);}
                }
            },
            Screen::Running(tool)|Screen::Results(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let live=if matches!(self.screen,Screen::Results(_)){self.results.as_ref().map(|result|&result.1).unwrap_or(&self.live)}else{&self.live};
                let mut top=56;
                if let Some((big,caption,secondary))=Self::headline(tool,live) {
                    Self::text(canvas,10,top,canvas.width().saturating_sub(20),&big,theme::TEXT,theme::BACKGROUND,3);
                    Self::text(canvas,12,top+26,canvas.width().saturating_sub(20),&caption,theme::TEXT_DIM,theme::BACKGROUND,1);
                    if !secondary.is_empty() {Self::text_right(canvas,canvas.width().saturating_sub(12) as i16,top+8,canvas.width()/2,&secondary,theme::TEXT_DIM,theme::BACKGROUND,1);}
                    top+=44;
                }
                if tool.is_pausable() {draw_bar(canvas,Rect::new(10,top,canvas.width().saturating_sub(24),5),u16::from(live.usb_percent)*10,theme::ACCENT);top+=14;}
                // Scanner radar: sweeping beam + expanding ring while the air is
                // still being searched; the AP list takes over once results land.
                if tool==Tool::WifiScan&&matches!(self.screen,Screen::Running(_))&&live.aps.is_empty()&&self.bottom(canvas)>top+120 {
                    let width=canvas.width().saturating_sub(40);
                    let r=(width/2) as i16;let cx=(canvas.width()/2) as i16;let cy=top+8+r;
                    for ring in [1i16,2,3] {
                        Self::draw_arc(canvas,cx,cy,r*ring/3,0,360,theme::SURFACE_ALT);
                    }
                    let sweep=((u16::from(live.tick)*45)%360) as i16;
                    for i in 0..12i16 {
                        let deg=sweep-i*3;
                        let dim=i>=6i16;
                        Self::draw_line(canvas,cx,cy,
                            cx+(Self::icos(deg as i32)*r as i32/256) as i16,
                            cy+(Self::isin(deg as i32)*r as i32/256) as i16,
                            if dim {theme::SURFACE_ALT}else{theme::ACCENT});
                    }
                    Self::plot(canvas,cx-1,cy-1,3,3,theme::ACCENT);
                    top+=r*2+16;
                }
                if tool==Tool::RfSpectrum&&!live.rf_envelope.is_empty()&&self.bottom(canvas)>top+46 {
                    let width=canvas.width().saturating_sub(24);let count=live.rf_envelope.len().min(usize::from(width)).max(1);
                    let baseline=top+44;
                    for index in 0..count {
                        let x=10+((index as u32*u32::from(width))/count as u32) as i16;
                        let next=10+(((index+1) as u32*u32::from(width))/count as u32) as i16;
                        let sample=index*live.rf_envelope.len()/count;
                        let h=1+u16::from(live.rf_envelope[sample])*40/255;
                        canvas.fill_rect(Rect::new(x,baseline-h as i16,(next-x).max(1) as u16,h),theme::ACCENT);
                    }
                    canvas.draw_hline(10,baseline+1,width,theme::SURFACE_ALT);
                    top=baseline+10;
                }
                // Waterfall: the four most recent sweeps, oldest at the top, as
                // one small cell each — a history of where activity has been.
                if tool==Tool::RfSpectrum&&!live.rf_waterfall.is_empty()&&live.rf_waterfall.len()%64==0&&self.bottom(canvas)>top+26 {
                    let rows=(live.rf_waterfall.len()/64) as u16;
                    let cell=(canvas.width().saturating_sub(24)/64).max(2);
                    for row in 0..rows {
                        let y=top+(row as i16)*((cell as i16)+1);
                        for column in 0..64usize {
                            let value=live.rf_waterfall[row as usize*64+column];
                            if value<8 {continue;}
                            let color=if value>=64 {theme::ACCENT}else if value>=32 {theme::TEXT}else{theme::TEXT_DIM};
                            canvas.fill_rect(Rect::new(10+(column as u16*cell) as i16,y,cell,cell),color);
                        }
                    }
                    top+=(rows as i16)*((cell as i16)+1)+6;
                }
                self.render_lines(canvas,&self.lines(tool,live),top,self.scroll);
            },
            Screen::Unavailable(tool)=>{
                canvas.fill_rect(Rect::new(0,45,canvas.width(),canvas.height().saturating_sub(65)),theme::BACKGROUND);
                let reason=self.unavailable(tool).unwrap_or_else(||String::from("This tool is ready. Go back and open it again."));
                self.render_lines(canvas,&[reason,String::from("Other tools still work.")],56,0);
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
        // Leading spaces are a nesting depth (dissector output), so they become a
        // pixel offset instead of being folded away by word-wrap.
        let mut wrapped:Vec<(usize,String)>=Vec::new();
        for line in lines {
            let indent=line.chars().take_while(|ch|*ch==' ').count().min(8).min(columns.saturating_sub(2));
            let width=columns.saturating_sub(indent).max(1);
            for part in wrap(line.trim_start_matches(' '),width) {wrapped.push((indent,part));}
        }
        let rows=((self.bottom(canvas)-top).max(0) as usize/14).max(1);
        let offset=scroll.min(wrapped.len().saturating_sub(rows));
        for (row,(indent,line)) in wrapped.iter().skip(offset).take(rows).enumerate() {
            let y=top+row as i16*14;if y+7>self.bottom(canvas){break;}
            let x=10+(*indent as i16)*6;
            Self::text(canvas,x,y,canvas.width().saturating_sub(24).saturating_sub((*indent as u16)*6),line,if row==0{theme::ACCENT}else{theme::TEXT},theme::BACKGROUND,1);
        }
        if wrapped.len()>rows {
            let h=(self.bottom(canvas)-top).max(0) as u16;
            let thumb=(usize::from(h)*rows/wrapped.len()).max(4).min(usize::from(h)) as u16;
            let y=top+((usize::from(h.saturating_sub(thumb))*offset)/wrapped.len().saturating_sub(rows).max(1)) as i16;
            canvas.fill_rect(Rect::new(canvas.width().saturating_sub(5) as i16,top,2,h),theme::SURFACE_ALT);
            canvas.fill_rect(Rect::new(canvas.width().saturating_sub(5) as i16,y,2,thumb),theme::ACCENT);
        }
    }
    // ---- category icon primitives: everything is drawn from filled rects ----
    fn plot(canvas:&mut impl Canvas,x:i16,y:i16,w:u16,h:u16,color:Rgb565) {
        canvas.fill_rect(Rect::new(x,y,w,h),color);
    }
    // Sine at 5-degree resolution, x256; `icos(deg)` is the cosine twin.
    fn isin(deg:i32)->i32 {
        let d=deg.rem_euclid(360);
        let (d,sign)=if d<180 {(d,1)}else{(d-180,-1)};
        // sin is symmetric around 90 degrees.
        let d=if d>90 {180-d}else{d};
        let idx=(d/5) as usize;
        let a=SIN5[idx] as i32;
        let b=if idx<18 {SIN5[idx+1] as i32}else{a};
        sign*(a+(b-a)*(d%5)/5)
    }
    fn icos(deg:i32)->i32 {Self::isin(deg+90)}
    fn draw_arc(canvas:&mut impl Canvas,cx:i16,cy:i16,r:i16,from_deg:i16,to_deg:i16,color:Rgb565) {
        let mut deg=from_deg;
        while deg<=to_deg {
            let x=cx+(Self::icos(deg as i32)*r as i32/256) as i16;
            let y=cy+(Self::isin(deg as i32)*r as i32/256) as i16;
            Self::plot(canvas,x,y,2,2,color);
            deg+=5;
        }
    }
    fn draw_line(canvas:&mut impl Canvas,x0:i16,y0:i16,x1:i16,y1:i16,color:Rgb565) {
        let steps=(x1-x0).abs().max((y1-y0).abs()).max(1) as i32;
        for i in 0..=steps {
            let t=i;
            let x=x0+((x1-x0) as i32*t/steps) as i16;
            let y=y0+((y1-y0) as i32*t/steps) as i16;
            Self::plot(canvas,x,y,2,2,color);
        }
    }
    /// Animated category emblem, centered on (cx,cy). `phase` advances 10 ms.
    fn draw_category_icon(canvas:&mut impl Canvas,index:usize,cx:i16,cy:i16,r:i16,accent:Rgb565,phase:u64) {
        if index>=7 {
            // Diagnostics: heartbeat trace.
            let rr=r*8/10;
            for (x0,y0,x1,y1) in [(-rr,0,-rr/2,0),(-rr/2,0,-rr/4,-rr*6/10),(0,rr*6/10,rr/4,-rr*4/10),(rr/4,-rr*4/10,rr,0)] {
                Self::draw_line(canvas,cx+x0,cy+y0,cx+x1,cy+y1,accent);
            }
            return;
        }
        let group=GROUPS[index];
        let p=(phase%40) as i16; // 0..=39, loops every ~4 s
        match group {
            Group::Wifi=>{
                // Pulsing arcs over a fixed dot.
                let pulse=p%20;
                Self::plot(canvas,cx-2,cy-2,4,4,accent);
                for (i,base) in [10i16,18,26].iter().enumerate() {
                    let rr=base+pulse*i as i16/7;
                    if rr>base+10 {continue;}
                    Self::draw_arc(canvas,cx,cy+8,rr,205,335,accent);
                }
            }
            Group::Packet=>{
                // Sliding capture layers.
                for (i,y) in [-8i16,0,8].iter().enumerate() {
                    let slide=((p as i32+i as i32*13)%20-10) as i16;
                    Self::plot(canvas,cx-r+slide.abs(),cy+y-1,(r*2-4) as u16,4,accent);
                }
            }
            Group::Ble=>{
                // Bluetooth rune with a breathing scale.
                let rr=r+p%3-1;
                Self::draw_line(canvas,cx,cy-rr,cx,cy+rr,accent);
                Self::draw_line(canvas,cx,cy-rr,cx+rr*6/10,cy-rr*3/10,accent);
                Self::draw_line(canvas,cx+rr*6/10,cy-rr*3/10,cx,cy,accent);
                Self::draw_line(canvas,cx,cy,cx+rr*6/10,cy+rr*3/10,accent);
                Self::draw_line(canvas,cx+rr*6/10,cy+rr*3/10,cx,cy+rr,accent);
            }
            Group::UsbHid=>{
                // Trident: shaft, two prongs, arrow tip, base.
                Self::draw_line(canvas,cx,cy-r/2,cx,cy+r,accent);
                Self::draw_line(canvas,cx,cy-r/2,cx-r*6/10,cy-r,accent);
                Self::draw_line(canvas,cx,cy-r/2,cx+r*6/10,cy-r,accent);
                Self::plot(canvas,cx-1,cy-r-3,3,3,accent);
                Self::plot(canvas,cx-r/2,cy+r-3,6,5,accent);
            }
            Group::Rf=>{
                // Antenna mast with an expanding sweep ring.
                Self::draw_line(canvas,cx,cy-r/2,cx,cy+r/2,accent);
                Self::draw_line(canvas,cx-8,cy+r/2,cx+8,cy+r/2,accent);
                let ring=6+(p%20);
                Self::draw_arc(canvas,cx,cy-r/2,ring,0,360,accent);
                Self::plot(canvas,cx-1,cy-r/2-1,3,3,accent);
            }
            Group::Gps=>{
                // Rotating crosshair with an orbiting satellite.
                Self::draw_arc(canvas,cx,cy,r*7/10,0,360,accent);
                Self::plot(canvas,cx-1,cy-1,3,3,accent);
                for (deg,(dx,dy)) in [(0i16,(0i16,-(r+3))),(90,(r+3,0)),(180,(0,r+3)),(270,(-(r+3),0))] {
                    Self::draw_line(canvas,cx+dx/3,cy+dy/3,cx+dx,cy+dy,accent);
                    let _=deg;
                }
                let orb=p*9;
                let ox=cx+(Self::icos(orb as i32)*r as i32/256) as i16;
                let oy=cy+(Self::isin(orb as i32)*r as i32/256) as i16;
                Self::plot(canvas,ox,oy,3,3,theme::SUCCESS);
            }
            Group::Network=>{
                // Three linked nodes; links blink in sequence.
                let (ax,ay)=(cx-r*7/10,cy-r*5/10);let (bx2,by2)=(cx+r*7/10,cy-r*5/10);let (cx2,cy2)=(cx,cy+r*6/10);
                let blink=p%3;
                if blink!=0 {Self::draw_line(canvas,ax,ay,bx2,by2,accent);}
                if blink!=1 {Self::draw_line(canvas,bx2,by2,cx2,cy2,accent);}
                if blink!=2 {Self::draw_line(canvas,cx2,cy2,ax,ay,accent);}
                for (x,y) in [(ax,ay),(bx2,by2),(cx2,cy2)] {
                    Self::plot(canvas,x-2,y-2,6,6,accent);
                }
            }
        }
    }
    fn category_blurb(index:usize)->(&'static str,&'static str) {
        if index>=7 {return ("SYSTEM HEALTH","BATTERY - BOARDS - LOGS");}
        match GROUPS[index] {
            Group::Wifi=>("WIRELESS OPERATIONS","SCAN - CAPTURE - PORTAL"),
            Group::Packet=>("PACKET ANALYSIS","CAPTURE - INSPECT - STREAM"),
            Group::Ble=>("BLUETOOTH LE","SCAN - SPAM - GATT - HID"),
            Group::UsbHid=>("USB SCRIPTING","DUCKYSCRIPT - PAYLOADS"),
            Group::Rf=>("2.4 GHZ RADIO","SPECTRUM - CAPTURE"),
            Group::Gps=>("POSITIONING","TRACK - WARDRIVE"),
            Group::Network=>("LOCAL NETWORK","DISCOVER - PROBE - PORTS"),
        }
    }
    /// Lupala-style category intro: accent frame, animated emblem, taglines.
    fn render_intro(&self,canvas:&mut impl Canvas,index:usize) {
        let width=canvas.width();let height=canvas.height();
        let accent=if index<7 {Self::group_accent(GROUPS[index])}else{theme::TEXT_DIM};
        canvas.fill_rect(Rect::new(0,0,width,height),theme::BACKGROUND);
        // Full accent frame, 2 px.
        canvas.fill_rect(Rect::new(0,0,width,2),accent);
        canvas.fill_rect(Rect::new(0,(height.saturating_sub(2)) as i16,width,2),accent);
        canvas.fill_rect(Rect::new(0,0,2,height),accent);
        canvas.fill_rect(Rect::new((width.saturating_sub(2)) as i16,0,2,height),accent);
        let big=width>=200;
        let (headline,feature)=Self::category_blurb(index);
        // Title bar + module name.
        let title=if index<7 {GROUPS[index].title()}else{"Diagnostics"};
        Self::text(canvas,10,10,width.saturating_sub(20),title,theme::TEXT,theme::BACKGROUND,if big {2}else{1});
        Self::text(canvas,10,if big {30}else{22},width.saturating_sub(20),headline,theme::ACCENT,theme::BACKGROUND,1);
        // Animated emblem, centered.
        let r=if big {30}else{20};
        Self::draw_category_icon(canvas,index,(width/2) as i16,(if big {118}else{74}) as i16,r,accent,12);
        // Blurb + footer hints.
        let desc_y=(if big {168}else{104}) as i16;
        // Center with a left clamp: narrow panels ellipsize instead of underflowing.
        let center=|len:usize|((width as i16)/2-(len as i16)*3).max(2);
        Self::text(canvas,center(headline.len()),desc_y,width,headline,theme::TEXT_DIM,theme::BACKGROUND,1);
        Self::text(canvas,center(feature.len()),desc_y+14,width,feature,theme::ACCENT,theme::BACKGROUND,1);
        let hint="SEL  TOOLS    BACK  MENU";
        Self::text(canvas,center(hint.len()),height.saturating_sub(22) as i16,width,hint,theme::TEXT_DIM,theme::BACKGROUND,1);
    }
    /// Boot splash: logo, title, reveal-in boot checklist and a blinking hint.
    fn render_splash(&self,canvas:&mut impl Canvas) {
        canvas.fill_rect(Rect::new(0,0,canvas.width(),canvas.height()),theme::BACKGROUND);
        let width=canvas.width();
        let big=width>=200;
        let logo=u16::min(if big {96}else{56},canvas.height()/3);
        let lx=((width-logo)/2) as i16;
        let ly=if big {44}else{20};
        canvas.draw_bitmap(lx,ly,assets::LOGO_W,assets::LOGO_H,logo,logo,assets::LOGO);
        let mut top=ly+logo as i16+10;
        let title=cyberdeck_core::DEVICE_NAME;
        let scale=if big {2}else{1};
        let text_width=(title.chars().count() as u16)*6*u16::from(scale);
        Self::text(canvas,((width-text_width)/2) as i16,top,text_width,title,theme::TEXT,theme::BACKGROUND,scale);
        top+=4+14*scale as i16;
        let tagline=alloc::format!("CYBERDECK // V{}",cyberdeck_core::FIRMWARE_VERSION);
        let tag_width=(tagline.len() as u16)*6;
        Self::text(canvas,((width-tag_width)/2) as i16,top,tag_width,&tagline,theme::ACCENT,theme::BACKGROUND,1);
        top+=18;
        // Reveal progress bar: accent fill over a dim track, percent at the right.
        let lines=self.boot_lines();
        let bar_x=8;let bar_w=width.saturating_sub(58);
        canvas.fill_rect(Rect::new(bar_x,top,bar_w,4),theme::SURFACE_ALT);
        let total=lines.len().max(1);
        let shown=self.splash_reveal.min(total);
        let pct=(shown*100/total) as u16;
        canvas.fill_rect(Rect::new(bar_x,top,bar_w*pct/100,4),theme::ACCENT);
        Self::text(canvas,bar_x+(bar_w as i16)+6,top.saturating_sub(2),50,&format!("{pct}%"),theme::TEXT_DIM,theme::BACKGROUND,1);
        top+=14;
        for (passed,line) in lines.iter().take(self.splash_reveal).take(if big {7}else{4}) {
            Self::text(canvas,10,top,width.saturating_sub(20),line,if *passed {theme::TEXT_DIM}else{theme::WARNING},theme::BACKGROUND,1);
            top+=12;
        }
        if (self.splash_elapsed / 350).is_multiple_of(2) {
            let hint="PRESS ANY KEY";
            let hint_width=(hint.len() as u16)*6;
            Self::text(canvas,((width-hint_width)/2) as i16,canvas.height().saturating_sub(24) as i16,width,hint,theme::ACCENT,theme::BACKGROUND,1);
        }
    }
    fn render_footer(&self,canvas:&mut impl Canvas) {
        let y=Self::footer_y(canvas);canvas.fill_rect(Rect::new(0,y,canvas.width(),20),theme::SURFACE);
        let hint=match self.screen {
            Screen::Group(_)=>"SEL  START",
            Screen::Setup(_)=>"SEL  CHANGE",Screen::Running(tool) if tool.is_pausable()=>"SEL  PAUSE",
            Screen::Running(Tool::PktFiles)=>"SEL  PREVIEW",
            Screen::Running(_)=>"BACK  STOP",Screen::Results(_)=>"SEL  SETTINGS",
            Screen::Edit(_,_)=>"BACK  SAVE",_=>"BACK  RETURN",
        };
        Self::text(canvas,10,y+6,canvas.width().saturating_sub(60),hint,theme::TEXT_DIM,theme::SURFACE,1);
        // Results screens already show the outcome as content; the pop-up band
        // would repeat it.
        if let Some(message)=&self.live.message {
            if matches!(self.screen,Screen::Results(_)){return;}
            let top=y-32;canvas.fill_rect(Rect::new(0,top,canvas.width(),32),theme::SURFACE_ALT);
            let columns=usize::from(canvas.width().saturating_sub(16)/6).max(1);
            for (row,line) in wrap(message,columns).iter().take(2).enumerate(){Self::text(canvas,8,top+5+row as i16*12,canvas.width().saturating_sub(16),line,theme::WARNING,theme::SURFACE_ALT,1);}
        }
    }
}

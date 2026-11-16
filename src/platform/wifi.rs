//! Wi-Fi radio actor: scanning, monitor capture and management-frame injection.
//!
//! The ESP32-S3 has one 2.4 GHz front end, so the radio is owned by a single actor
//! task. The UI submits a command through [`WIFI_COMMAND`] and reads bounded state
//! from [`WIFI_STATE`]; no packet processing ever runs on the UI path.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use critical_section::Mutex;
use static_cell::StaticCell;
use cyberdeck_core::net::{MacAddr,Channel};
use cyberdeck_core::packet::{CaptureFilter,passive::PassiveEngine,storage::SessionGate};
use embassy_futures::select::{select,Either};
use cyberdeck_core::pcap::{MAX_CAPTURE_BYTES,PcapSink,PcapWriter,Radiotap,strip_fcs};
use cyberdeck_core::time::Timestamp;
use cyberdeck_core::wifi::ap::{Ssid,ChannelHopper};
use cyberdeck_core::wifi::attack::{AttackMode, AttackPlan, AttackRunner};
use cyberdeck_core::wifi::dhcp::{self,Lease};
use cyberdeck_core::wifi::portal::{self,PortalConfig,PortalTemplate};
use cyberdeck_core::wifi::frame::{self, FrameBuffer};
use esp_radio::wifi::ap::AccessPointInfo;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::ap::AccessPointConfig;
use esp_radio::wifi::{AuthenticationMethodConfig,Config,SecondaryChannel,WifiController};

static SESSION:Mutex<RefCell<SessionGate>>=Mutex::new(RefCell::new(SessionGate::new()));
static ACTIVE_TOKEN:AtomicU32=AtomicU32::new(0);
pub const SNAP_LEN:usize=512;
const RX_SLOTS:usize=8;
pub const MAX_APS:usize=24;
const PCAP_CHUNK_BYTES:usize=8192;
#[derive(Clone,Copy)]
pub struct CapturedFrame{pub len:u16,pub original_len:u32,pub timestamp_us:u64,pub channel:u8,pub rssi:i8,pub data:[u8;SNAP_LEN]}
impl CapturedFrame{
    const EMPTY:Self=Self{len:0,original_len:0,timestamp_us:0,channel:0,rssi:0,data:[0;SNAP_LEN]};
    pub fn bytes(&self)->&[u8]{&self.data[..usize::from(self.len).min(SNAP_LEN)]}
    fn parser_bytes(&self)->&[u8]{if u32::from(self.len)==self.original_len{strip_fcs(self.bytes())}else{self.bytes()}}
}
struct RxRing{slots:[CapturedFrame;RX_SLOTS],head:usize,tail:usize,dropped:u32,last_stamp:u32,epoch:u64}
impl RxRing{
    const fn new()->Self{Self{slots:[CapturedFrame::EMPTY;RX_SLOTS],head:0,tail:0,dropped:0,last_stamp:0,epoch:0}}
    fn push(&mut self,mut f:CapturedFrame){
        let raw=f.timestamp_us as u32;
        if raw<self.last_stamp&&self.last_stamp-raw>0x8000_0000{self.epoch=self.epoch.saturating_add(1u64<<32)}
        self.last_stamp=raw;f.timestamp_us=self.epoch+u64::from(raw);
        let next=(self.head+1)%RX_SLOTS;if next==self.tail{self.dropped=self.dropped.saturating_add(1);return}
        self.slots[self.head]=f;self.head=next;
    }
    fn pop(&mut self)->Option<CapturedFrame>{if self.head==self.tail{return None}let f=self.slots[self.tail];self.tail=(self.tail+1)%RX_SLOTS;Some(f)}
}
static RX:Mutex<RefCell<RxRing>>=Mutex::new(RefCell::new(RxRing::new()));
fn receive(packet:esp_radio::wifi::sniffer::PromiscuousPkt){
    if packet.frame_type==3 || packet.rx_cntl.rx_state!=0{return}
    let len=packet.len.min(packet.data.len()).min(SNAP_LEN);
    let mut f=CapturedFrame::EMPTY;f.len=len as u16;f.original_len=packet.len as u32;
    f.timestamp_us=packet.rx_cntl.timestamp.duration_since_epoch().as_micros();
    f.channel=packet.rx_cntl.channel as u8;f.rssi=packet.rx_cntl.rssi as i8;f.data[..len].copy_from_slice(&packet.data[..len]);
    critical_section::with(|cs|RX.borrow_ref_mut(cs).push(f));
}
struct ChunkSink{name:String,buffer:Vec<u8>,bytes:u64,last_ticket:Option<u32>,stream:bool}
impl ChunkSink{
    fn new(name:String,stream:bool)->Self{Self{name,buffer:Vec::new(),bytes:0,last_ticket:None,stream}}
    fn queue(&mut self)->Result<(),cyberdeck_core::error::DeckError>{
        if self.buffer.is_empty(){return Ok(())}
        let bytes=core::mem::take(&mut self.buffer);let len=bytes.len()as u64;
        match super::sd::enqueue_owned(&self.name,bytes,self.last_ticket.is_some()){
            Ok(ticket)=>{self.last_ticket=Some(ticket);self.bytes+=len;Ok(())}
            Err(bytes)=>{self.buffer=bytes;Err(cyberdeck_core::error::DeckError::Storage{reason:"SD queue full or absent"})}
        }
    }
    async fn finish(mut self)->Result<u64,String>{
        if self.stream{super::usb::pcap_finish();return Ok(0)}
        let deadline=embassy_time::Instant::now()+embassy_time::Duration::from_secs(5);
        while self.queue().is_err(){
            if embassy_time::Instant::now()>=deadline{return Err(String::from("SD queue timeout; buffered records unsaved"))}
            embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
        }
        if let Some(ticket)=self.last_ticket{loop{
            if let Some(result)=super::sd::completion(ticket){return if result.success{Ok(self.bytes)}else{Err(result.error)}}
            if embassy_time::Instant::now()>=deadline{return Err(String::from("SD completion timeout"))}
            embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
        }}
        Ok(0)
    }
}
impl PcapSink for ChunkSink{
    fn write_all(&mut self,data:&[u8])->Result<(),cyberdeck_core::error::DeckError>{
        if self.stream{
            return if super::usb::pcap_write(data){Ok(())}else{Err(cyberdeck_core::error::DeckError::Storage{reason:"USB stream queue full or disconnected"})}
        }
        if self.buffer.len()+data.len()>PCAP_CHUNK_BYTES{self.queue()?}
        if data.len()>PCAP_CHUNK_BYTES{return Err(cyberdeck_core::error::DeckError::Storage{reason:"oversize PCAP record"})}
        self.buffer.extend_from_slice(data);Ok(())
    }
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

pub struct WifiState {
    pub busy: bool,
    pub status: String,
    pub aps: Vec<ApRow>,
    scan_aps: Vec<ApRow>,
    scan_ms: u64,
    pub frames: u32,
    pub bytes: u64,
    pub dropped: u32,
    pub channel: u8,
    /// Captive-portal counters, shown on the Evil Twin screen.
    pub portal_clients: u32,
    pub portal_requests: u32,
}

impl WifiState {
    const fn new() -> Self {
        Self {
            busy: false,
            status: String::new(),
            aps: Vec::new(),
            scan_aps: Vec::new(),
            scan_ms: 0,
            frames: 0,
            bytes: 0,
            dropped: 0,
            channel: 1,
            portal_clients: 0,
            portal_requests: 0,
        }
    }
}

static WIFI_STATE: Mutex<RefCell<WifiState>> = Mutex::new(RefCell::new(WifiState::new()));
static WIFI_COMMAND: Mutex<RefCell<Option<WifiCommand>>> = Mutex::new(RefCell::new(None));

#[derive(Clone)]
pub enum WifiCommand {
    Scan,
    Capture { channel: u8 },
    Observe { channel:u8,filter:CaptureFilter,record:bool },
    Stream { channel:u8,filter:CaptureFilter },
    Connect { ssid:String,password:String },
    Disconnect,
    Attack { mode: AttackMode, channel: u8 },
    /// Captive portal: open AP plus DHCP/DNS/HTTP on the portal address.
    Portal { ssid:String, channel:u8, template:PortalTemplate },
    Stop,
}


/// Rejected starts never clear a pending cancellation.
pub fn submit(command:WifiCommand)->bool {
    critical_section::with(|cs|{
        let mut gate=SESSION.borrow_ref_mut(cs);
        if matches!(command,WifiCommand::Stop){gate.cancel();WIFI_COMMAND.borrow_ref_mut(cs).take();return true}
        if gate.reserve().is_none(){return false}
        *WIFI_COMMAND.borrow_ref_mut(cs)=Some(command);WIFI_STATE.borrow_ref_mut(cs).busy=true;true
    })
}
pub fn busy()->bool {critical_section::with(|cs|SESSION.borrow_ref(cs).busy())}
fn take_command()->Option<WifiCommand>{
    critical_section::with(|cs|{
        let id=SESSION.borrow_ref_mut(cs).activate()?;
        ACTIVE_TOKEN.store(id,Ordering::Release);
        WIFI_COMMAND.borrow_ref_mut(cs).take()
    })
}
fn complete_command(){critical_section::with(|cs|{
    SESSION.borrow_ref_mut(cs).complete(ACTIVE_TOKEN.load(Ordering::Acquire));
    WIFI_STATE.borrow_ref_mut(cs).busy=false;
});}

fn set_status(status: &str) {
    critical_section::with(|cs| {
        let mut state = WIFI_STATE.borrow_ref_mut(cs);
        state.status.clear();
        state.status.push_str(status);
    });
}

/// Snapshot for rendering.
pub fn snapshot() -> (String, Vec<ApRow>, u32, u32) {
    critical_section::with(|cs| {
        let state = WIFI_STATE.borrow_ref(cs);
        (
            state.status.clone(),
            state.aps.clone(),
            state.frames,
            state.dropped,
        )
    })
}

/// Last successful scan only; monitor cache updates and failed scans never refresh it.
pub fn scan_observations()->(Vec<ApRow>,u64){
    critical_section::with(|cs|{let state=WIFI_STATE.borrow_ref(cs);(state.scan_aps.clone(),state.scan_ms)})
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
            Some(WifiCommand::Scan) => {scan_session(&mut controller).await;}
            Some(WifiCommand::Capture { channel }) => {
                capture_session(&mut controller, channel).await;
            }
            Some(WifiCommand::Attack { mode, channel }) => {
                attack_session(&mut controller, mode, channel).await;
            }

            Some(WifiCommand::Observe{channel,filter,record})=>monitor_session(&mut controller,channel,filter,record,false).await,
            Some(WifiCommand::Stream{channel,filter})=>monitor_session(&mut controller,channel,filter,false,true).await,
            Some(WifiCommand::Connect{ssid,password})=>connect_session(&mut controller,ACTIVE_TOKEN.load(Ordering::Acquire),ssid,password).await,
            Some(WifiCommand::Disconnect)=>{if disconnect(&mut controller).await{set_status("station disconnected");}},
            Some(WifiCommand::Portal{ssid,channel,template})=>portal_session(&mut controller,ACTIVE_TOKEN.load(Ordering::Acquire),ssid,channel,template).await,
            Some(WifiCommand::Stop) => {}
            None => {}
        }
        complete_command();
        embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
    }
}

fn stop_requested() -> bool {
    critical_section::with(|cs|SESSION.borrow_ref(cs).cancelled(ACTIVE_TOKEN.load(Ordering::Acquire)))
}

fn reset_counters(channel: u8) {
    critical_section::with(|cs| {
        let mut state = WIFI_STATE.borrow_ref_mut(cs);
        state.frames = 0;
        state.bytes = 0;
        state.dropped = 0;
        state.channel = channel;
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


fn monitor_hopper(channel:u8)->Result<ChannelHopper,&'static str>{
    if channel==0{return Ok(ChannelHopper::new(cyberdeck_core::net::hop_plan(1,false),300));}
    if channel>13{return Err("channel must be 0 (hop) or 1..13");}
    let channel=Channel::new(channel).map_err(|_|"channel must be 0 (hop) or 1..13")?;
    Ok(ChannelHopper::fixed(channel))
}

#[cfg(test)]
mod monitor_channel_tests {
    use super::*;

    #[test]
    fn hop_setting_visits_all_supported_channels_with_session_relative_dwell() {
        let mut hopper=monitor_hopper(0).expect("UI Hop setting must be accepted");
        assert_eq!(hopper.current().unwrap().get(),1);
        assert_eq!(hopper.poll(0),None);
        assert_eq!(hopper.poll(299),None);
        for (elapsed,channel) in [(300,2),(600,3),(900,4),(1200,5),(1500,6),(1800,7),(2100,8),(2400,9),(2700,10),(3000,11),(3300,12),(3600,13),(3900,1)] {
            assert_eq!(hopper.poll(elapsed).unwrap().get(),channel);
        }
    }

    #[test]
    fn fixed_channels_stay_fixed_and_unsupported_channels_are_rejected() {
        for channel in [1,6,13] {
            let mut hopper=monitor_hopper(channel).unwrap();
            assert_eq!(hopper.current().unwrap().get(),channel);
            assert_eq!(hopper.poll(300),None);
            assert_eq!(hopper.poll(3900),None);
        }
        for channel in [14,15,255] {assert!(monitor_hopper(channel).is_err());}
    }
}
async fn capture_session(controller:&mut WifiController<'static>,channel:u8){
    monitor_session(controller,channel,CaptureFilter::default(),true,false).await;
}
async fn monitor_session(controller:&mut WifiController<'static>,channel:u8,filter:CaptureFilter,record:bool,stream:bool){
    let Ok(mut hopper)=monitor_hopper(channel)else{set_status("channel must be 0 (hop) or 1..13");return};
    if !disconnect(controller).await{return}
    if stop_requested(){set_status("capture cancelled");return}
    let Some(initial_channel)=hopper.current()else{set_status("no capture channels configured");return};
    if let Err(e)=controller.set_channel(initial_channel.get(),SecondaryChannel::None){set_status(&alloc::format!("channel tune failed: {e:?}"));return}
    if stream&&!super::usb::pcap_start(){set_status("USB CDC host not connected or stream busy");return}
    if record&&!super::sd::ready(){set_status("capture requires mounted SD; use live observer");return}
    reset_counters(initial_channel.get());
    let name=if record{super::sd::next_name("CAPTURE","PCAP")}else{String::new()};
    let mut pcap=if record||stream{
        match PcapWriter::new(ChunkSink::new(name.clone(),stream),(SNAP_LEN+Radiotap::LEN)as u32,true,MAX_CAPTURE_BYTES){
            Ok(w)=>Some(w),Err(e)=>{if stream{super::usb::pcap_finish();}set_status(&alloc::format!("PCAP start failed: {e:?}"));return}
        }
    }else{None};
    let mut sniffer=controller.sniffer();sniffer.set_receive_cb(receive);
    if let Err(e)=sniffer.set_promiscuous_mode(true){if stream{super::usb::pcap_finish();}set_status(&alloc::format!("sniffer unavailable: {e:?}"));return}
    set_status(&if channel==0{alloc::format!("monitor hopping 1..13 (channel {}): {}",initial_channel.get(),filter.describe())}else{alloc::format!("monitor channel {channel}: {}",filter.describe())});
    let session_start=embassy_time::Instant::now();
    let mut error=None;let mut last_publish=session_start;
    'session:loop{
        if stop_requested(){break}
        // A bounded batch yields to the UI and storage even under a saturated channel.
        for _ in 0..RX_SLOTS{
            let Some(f)=critical_section::with(|cs|RX.borrow_ref_mut(cs).pop())else{break};
            critical_section::with(|cs|{
                OBSERVER.borrow_ref_mut(cs).on_frame(f.parser_bytes(),f.rssi,f.channel,f.timestamp_us,&filter,f.original_len);
                let mut s=WIFI_STATE.borrow_ref_mut(cs);s.frames=s.frames.saturating_add(1);s.bytes=s.bytes.saturating_add(u64::from(f.original_len));
            });
            if filter.matches(f.parser_bytes()){
                if let Some(writer)=pcap.as_mut(){
                    let freq=Channel::new(f.channel).map(|c|c.frequency_mhz()).unwrap_or(2412);
                    let mut rt=Radiotap::for_mgmt(freq,f.rssi);rt.tsft_us=f.timestamp_us;
                    if let Err(e)=writer.write_frame_with_original(Timestamp::from_micros(f.timestamp_us),f.bytes(),f.original_len,&rt){error=Some(alloc::format!("{e:?}"));break 'session}
                }
            }
            if stop_requested(){break 'session}
        }
        if channel==0{
            if let Some(next)=hopper.poll(session_start.elapsed().as_millis()){
                let primary=next.get();
                if let Err(e)=controller.set_channel(primary,SecondaryChannel::None){error=Some(alloc::format!("channel tune failed: {e:?}"));break 'session}
                critical_section::with(|cs|WIFI_STATE.borrow_ref_mut(cs).channel=primary);
                set_status(&alloc::format!("monitor hopping 1..13 (channel {primary}): {}",filter.describe()));
            }
        }
        critical_section::with(|cs|WIFI_STATE.borrow_ref_mut(cs).dropped=RX.borrow_ref(cs).dropped);
        if last_publish.elapsed()>=embassy_time::Duration::from_millis(250){
            let rows=passive_snapshot().aps;critical_section::with(|cs|WIFI_STATE.borrow_ref_mut(cs).aps=rows);last_publish=embassy_time::Instant::now();
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
    }
    let disabled=sniffer.set_promiscuous_mode(false);drop(sniffer);
    set_status("stopping; waiting for storage completion");
    let suffix=if let Some(writer)=pcap{
        match writer.finish(){
            Ok((sink,stats))=>match sink.finish().await{Ok(bytes)=>if stream{alloc::format!("{} records queued to USB; {} B sent",stats.records,super::usb::pcap_status().1)}else{alloc::format!("{name}: {bytes} B saved, {} records",stats.records)},Err(e)=>alloc::format!("storage failed: {e}")},
            Err(e)=>alloc::format!("PCAP finalize failed: {e:?}")
        }
    }else{String::from("live observations retained")};
    let frames=snapshot().2;
    set_status(&alloc::format!("stopped: {frames} frames; {suffix}{}{}",error.map(|e|alloc::format!("; capture error: {e}")).unwrap_or_default(),if disabled.is_err(){"; driver stop error"}else{""}));
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
            if sniffer
                .send_raw_frame(false, frame.as_slice(), true)
                .is_err()
            {
                finish_session("transmit rejected by driver");
                return;
            }
            critical_section::with(|cs| {
                let mut state = WIFI_STATE.borrow_ref_mut(cs);
                state.frames = runner.frames();
            });
        }
        if runner.should_stop(embassy_time::Instant::now().as_millis()) || stop_requested() {
            break;
        }
    }
    finish_session(&alloc::format!("{} frames sent", runner.frames()));
}

#[derive(Clone)]
pub struct ClientRow{pub mac:MacAddr,pub bssid:Option<MacAddr>,pub channel:u8,pub rssi:i8,pub frames:u32}
impl ClientRow{
    /// One display line for the "Nearby clients" screen.
    pub fn line(&self)->String{
        let ap=match self.bssid {Some(bssid)=>alloc::format!("{bssid}"),None=>String::from("unknown AP")};
        alloc::format!("{}  {}  ch {}  {} dBm  {} frames",self.mac,ap,self.channel,self.rssi,self.frames)
    }
}
#[derive(Clone)]
pub struct WpsRow{pub bssid:MacAddr,pub channel:u8,pub rssi:i8,pub configured:bool,pub selected_registrar:bool}
impl WpsRow{
    /// One display line for the "WPS information" screen.
    pub fn line(&self)->String{
        alloc::format!("{}  ch {}  {} dBm  {}{}",self.bssid,self.channel,self.rssi,
            if self.configured{"configured"}else{"unconfigured"},
            if self.selected_registrar{"  registrar selected"}else{""})
    }
}
pub use cyberdeck_core::packet::passive::InspectorRow;
#[derive(Clone)]
pub struct ProbeRow{pub client:MacAddr,pub ssid:String,pub channel:u8,pub rssi:i8}
impl ProbeRow{
    /// One line for the Karma screen: requested name first, then who asked.
    pub fn line(&self)->String{
        let name=if self.ssid.is_empty(){"WILDCARD"}else{self.ssid.as_str()};
        alloc::format!("{name}  {}  {}DBM",self.client,self.rssi)
    }
}
pub struct PassiveSnapshot{pub aps:Vec<ApRow>,pub clients:Vec<ClientRow>,pub wps:Vec<WpsRow>,pub probes:Vec<ProbeRow>,pub probe_ssids:u32,pub frames:Vec<InspectorRow>,pub eapol:u32,pub handshakes:u32,pub pmkids:u32,pub histogram:String}
type Observer=PassiveEngine<24,32,8,12>;
static OBSERVER:Mutex<RefCell<Observer>>=Mutex::new(RefCell::new(Observer::new()));

/// Portal address: the AP takes .1 and hands clients .100 and up on its own /24.
const PORTAL_IP:[u8;4]=[192,168,4,1];
fn portal_client_ip(mac:[u8;6])->[u8;4]{[PORTAL_IP[0],PORTAL_IP[1],PORTAL_IP[2],100+(mac[5]%100)]}
fn note_portal_client(){critical_section::with(|cs|{let mut s=WIFI_STATE.borrow_ref_mut(cs);s.portal_clients=s.portal_clients.saturating_add(1);});}
fn note_portal_request(){critical_section::with(|cs|{let mut s=WIFI_STATE.borrow_ref_mut(cs);s.portal_requests=s.portal_requests.saturating_add(1);});}
/// Captive-portal counters for the Evil Twin screen.
pub fn portal_snapshot()->(u32,u32){critical_section::with(|cs|{let s=WIFI_STATE.borrow_ref(cs);(s.portal_clients,s.portal_requests)})}

/// Answer DISCOVER/REQUEST so joining clients actually get an address.
async fn dhcp_service(stack:embassy_net::Stack<'static>)->!{
    use embassy_net::udp::{PacketMetadata,UdpSocket};
    let mut rx_meta=[PacketMetadata::EMPTY;2];let mut tx_meta=[PacketMetadata::EMPTY;2];
    let mut rx=[0u8;512];let mut tx=[0u8;512];
    let mut socket=UdpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
    if socket.bind(dhcp::SERVER_PORT).is_err(){
        set_status("DHCP port unavailable");
        loop{embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;}
    }
    loop{
        let mut request=[0u8;512];
        if let Ok(Ok((length,_)))=embassy_time::with_timeout(embassy_time::Duration::from_millis(500),socket.recv_from(&mut request)).await{
            let mac=dhcp::client_mac(&request[..length]).unwrap_or([0;6]);
            if let Some(reply)=dhcp::reply(&request[..length],&Lease::new(portal_client_ip(mac),PORTAL_IP)){
                let target=(embassy_net::IpAddress::Ipv4(embassy_net::Ipv4Address::BROADCAST),dhcp::CLIENT_PORT);
                let _=socket.send_to(&reply,target).await;
                note_portal_client();
            }
        }
    }
}

/// Answer every DNS question with the portal address so the OS opens it.
async fn dns_service(stack:embassy_net::Stack<'static>)->!{
    use embassy_net::udp::{PacketMetadata,UdpSocket};
    let mut rx_meta=[PacketMetadata::EMPTY;2];let mut tx_meta=[PacketMetadata::EMPTY;2];
    let mut rx=[0u8;512];let mut tx=[0u8;512];
    let mut socket=UdpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
    if socket.bind(53).is_err(){
        set_status("DNS port unavailable");
        loop{embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;}
    }
    loop{
        let mut query=[0u8;512];
        if let Ok(Ok((length,meta)))=embassy_time::with_timeout(embassy_time::Duration::from_millis(500),socket.recv_from(&mut query)).await{
            if let Some(answer)=portal::dns_response(&query[..length],PORTAL_IP){
                let _=socket.send_to(&answer,meta.endpoint).await;
                note_portal_request();
            }
        }
    }
}

/// Completes when the active session is cancelled.
async fn wait_for_stop(token:u32){
    while !critical_section::with(|cs|SESSION.borrow_ref(cs).cancelled(token)){
        embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
    }
}

/// Serve the portal page, the captive-probe paths and form posts.
async fn http_service(stack:embassy_net::Stack<'static>,portal_config:&PortalConfig)->!{
    use embedded_io_async::Write as _;
    use embassy_net::tcp::TcpSocket;
    loop{
        let mut rx=[0u8;1024];let mut tx=[0u8;1024];
        let mut socket=TcpSocket::new(stack,&mut rx,&mut tx);
        socket.set_timeout(Some(embassy_time::Duration::from_secs(3)));
        // `accept` performs the three-way handshake on this socket in embassy-net 0.9.
        if !matches!(embassy_time::with_timeout(embassy_time::Duration::from_secs(8),socket.accept(80)).await,Ok(Ok(()))){
            socket.abort();embassy_time::Timer::after(embassy_time::Duration::from_millis(20)).await;continue;
        }
        // One bounded request: headers plus a small form post.
        let mut buffer=[0u8;768];let mut used=0;
        while used<buffer.len(){
            match embassy_time::with_timeout(embassy_time::Duration::from_millis(300),socket.read(&mut buffer[used..])).await{
                Ok(Ok(0))=>break,
                Ok(Ok(read))=>{used+=read;if used>64&&buffer[..used].windows(4).any(|window|window==b"\r\n\r\n"){break}},
                _=>break,
            }
        }
        let response=match portal::parse_request(&buffer[..used]){
            Some(request)=>portal::response_for(&portal::route(&request),portal_config),
            None=>portal::http_response(400,"text/plain",b"bad request",&[]),
        };
        let _=embassy_time::with_timeout(embassy_time::Duration::from_secs(1),socket.write_all(&response)).await;
        let _=embassy_time::with_timeout(embassy_time::Duration::from_millis(300),socket.flush()).await;
        socket.close();
        note_portal_request();
        embassy_time::Timer::after(embassy_time::Duration::from_millis(20)).await;
    }
}

/// Evil Twin: open AP plus the three services a captive portal needs.
async fn portal_session(controller:&mut WifiController<'static>,token:u32,ssid:String,channel:u8,template:PortalTemplate){
    if !disconnect(controller).await{return}
    let Ok(name)=ssid.as_str().try_into()else{set_status("SSID exceeds 32 bytes");return};
    let config=AccessPointConfig::default()
        .with_ssid(name)
        .with_channel(channel)
        .with_authentication(AuthenticationMethodConfig::Open);
    if let Err(error)=controller.set_config(&Config::AccessPoint(config)){
        set_status(&alloc::format!("AP start failed: {error:?}"));return
    }
    if stop_requested(){set_status("portal cancelled");return}
    let Some(interface)=esp_radio::wifi::Interface::try_access_point()else{
        set_status("AP interface unavailable");return
    };
    static PORTAL_RESOURCES:StaticCell<embassy_net::StackResources<5>>=StaticCell::new();
    let seed=embassy_time::Instant::now().as_micros() as u64;
    let net_config=embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4{
        address:embassy_net::Ipv4Cidr::new(
            embassy_net::Ipv4Address::new(PORTAL_IP[0],PORTAL_IP[1],PORTAL_IP[2],PORTAL_IP[3]),24),
        gateway:None,
        dns_servers:Default::default(),
    });
    let(stack,mut runner)=embassy_net::new(interface,net_config,PORTAL_RESOURCES.init(embassy_net::StackResources::new()),seed);
    let portal_config=PortalConfig{template,ap_ip:PORTAL_IP,ssid,channel,capture_limit:16};
    set_status(&alloc::format!("portal up: {}",portal_config.ssid));
    let services=async{
        embassy_futures::join::join3(dhcp_service(stack),dns_service(stack),http_service(stack,&portal_config)).await
    };
    let running=async{embassy_futures::join::join(runner.run(),services).await};
    match select(running,wait_for_stop(token)).await{
        Either::First(_)=>{},
        Either::Second(_)=>set_status("portal stopped"),
    }
    // Leave the radio usable for the next session.
    let _=controller.set_config(&Config::Station(StationConfig::default()));
}

pub fn passive_snapshot()->PassiveSnapshot{critical_section::with(|cs|{
    let o=OBSERVER.borrow_ref(cs);
    PassiveSnapshot{aps:o.scan.aps.iter().map(|a|ApRow{ssid:a.ssid.display(),bssid:a.bssid,channel:a.channel,rssi:a.rssi,security:a.security.security.label()}).collect(),
        clients:o.scan.stations.iter().map(|s|ClientRow{mac:s.mac,bssid:s.bssid,channel:s.channel,rssi:s.rssi,frames:s.frames}).collect(),
        wps:o.wps.iter().map(|w|WpsRow{bssid:w.bssid,channel:w.channel,rssi:w.rssi,configured:w.info.configured,selected_registrar:w.info.selected_registrar}).collect(),
        probes:o.probes.iter().map(|p|ProbeRow{client:p.client,ssid:String::from_utf8_lossy(&p.ssid).into_owned(),channel:p.channel,rssi:p.rssi}).collect(),
        probe_ssids:o.probe_ssids() as u32,
        frames:o.frames.clone(),eapol:o.scan.eapol,handshakes:o.handshakes.complete_count()as u32,pmkids:o.handshakes.pmkid_count()as u32,histogram:o.histogram.report()}
})}
pub fn passive_hashes()->String{critical_section::with(|cs|OBSERVER.borrow_ref(cs).export_hashes())}
/// Dissection of the newest captured frame, for the Frame inspector screen.
pub fn dissect_latest()->Vec<String>{
    let mut buffer=[0u8;cyberdeck_core::packet::dissect::MAX_FRAME];
    let length=critical_section::with(|cs|{
        let observer=OBSERVER.borrow_ref(cs);
        let bytes=observer.latest.bytes();
        let length=bytes.len().min(buffer.len());
        buffer[..length].copy_from_slice(&bytes[..length]);
        length
    });
    cyberdeck_core::packet::dissect::lines(&buffer[..length])
}

async fn cancelled_or_timeout(_id:u32,seconds:u64){let deadline=embassy_time::Instant::now()+embassy_time::Duration::from_secs(seconds);loop{if stop_requested()||embassy_time::Instant::now()>=deadline{return}embassy_time::Timer::after(embassy_time::Duration::from_millis(20)).await;}}
async fn disconnect(controller:&mut WifiController<'static>)->bool{
    match embassy_time::with_timeout(embassy_time::Duration::from_secs(3),controller.disconnect_async()).await{
        Ok(Ok(_))=>true,Ok(Err(e))=>{set_status(&alloc::format!("disconnect failed: {e:?}"));false},Err(_)=>{set_status("disconnect timeout");false}
    }
}
async fn connect_session(controller:&mut WifiController<'static>,id:u32,ssid:String,password:String){
    if !disconnect(controller).await{return}
    let Ok(name)=ssid.as_str().try_into()else{set_status("SSID exceeds 32 bytes");return};
    let auth=if password.is_empty(){AuthenticationMethodConfig::Open}else{
        let Ok(pass)=password.as_str().try_into()else{set_status("password exceeds driver limit");return};AuthenticationMethodConfig::Wpa2Personal(pass)
    };
    if let Err(e)=controller.set_config(&Config::Station(StationConfig::default().with_ssid(name).with_authentication(auth))){set_status(&alloc::format!("station config failed: {e:?}"));return}
    set_status("connecting (30 second limit)");
    match select(controller.connect_async(),cancelled_or_timeout(id,30)).await{
        Either::First(Ok(info))=>set_status(&alloc::format!("connected {} on channel {}",info.ssid.as_str(),info.channel)),
        Either::First(Err(e))=>set_status(&alloc::format!("connection failed: {e:?}")),
        Either::Second(())=>{let cancelled=stop_requested();if disconnect(controller).await{set_status(if cancelled{"connection cancelled"}else{"connection timeout"});}}
    }
}

async fn scan_session(controller:&mut WifiController<'static>){
    set_status("scanning");
    let id=ACTIVE_TOKEN.load(Ordering::Acquire);
    match select(controller.scan_async(&ScanConfig::default()),cancelled_or_timeout(id,20)).await{
        Either::First(Ok(results))=>{
            let mut rows:Vec<ApRow>=results.iter().map(to_row).collect();
            rows.sort_by_key(|r|-i16::from(r.rssi));rows.truncate(MAX_APS);
            let count=rows.len();let queued=super::export::save_wifi_findings(&rows);
            let observed_ms=embassy_time::Instant::now().as_millis();
            critical_section::with(|cs|{let mut state=WIFI_STATE.borrow_ref_mut(cs);state.scan_aps=rows.clone();state.scan_ms=observed_ms;state.aps=rows;state.status=alloc::format!("{count} access points; {}",if queued{"inventory export queued"}else{"inventory retained"});});
        }
        Either::First(Err(e))=>set_status(&alloc::format!("scan failed: {e:?}")),
        Either::Second(())=>set_status(if stop_requested(){"scan cancelled"}else{"scan timeout"}),
    }
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

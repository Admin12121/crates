//! UI action to platform command mapping; every accepted tool has a real driver path.
use alloc::string::String;
use super::{RfRuntime,RfMode};
use cyberdeck_firmware::{app::{App,Tool,PacketFilter,KeyboardLayout},platform::{wifi::{self,WifiCommand},ble::{self,BleCommand},usb::{self,UsbCommand},sd,gps::{self,GpsCommand},network::{self,NetCommand}}};
use cyberdeck_core::{hid::Layout,packet::CaptureFilter,rf::nrf24::DataRate};
#[derive(Clone,Copy)]pub struct Flags{pub wifi:bool,pub ble:bool,pub usb:bool,pub gps:bool,pub network:bool}
fn queued(accepted:bool)->Result<(),&'static str>{if accepted{Ok(())}else{Err("Busy. Wait for the running tool to stop")}}
pub fn stop(rf:&mut RfRuntime<'_>){
 wifi::submit(WifiCommand::Stop);ble::submit(BleCommand::Stop);usb::submit(UsbCommand::Stop);
 gps::submit(GpsCommand::Stop);network::submit(NetCommand::Stop);
 rf.mode=RfMode::Off;if let Some(radio)=rf.radio.as_mut(){let _=radio.power_down();}
}
pub fn filter(value:PacketFilter)->CaptureFilter{let mut filter=CaptureFilter::default();match value{PacketFilter::All=>{},PacketFilter::Management=>filter.management_only=true,PacketFilter::Data=>filter.data_only=true,PacketFilter::Eapol=>filter.eapol_only=true};filter}
pub fn layout(value:KeyboardLayout)->Layout{match value{KeyboardLayout::Us=>Layout::Us,KeyboardLayout::Uk=>Layout::Uk,KeyboardLayout::De=>Layout::De}}
pub fn start(tool:Tool,app:&mut App,rf:&mut RfRuntime<'_>,flags:Flags)->Result<(),&'static str>{
 let s=app.settings();let filter=filter(s.filter);let layout=layout(s.layout);
 match tool{
  Tool::WifiScan=>{if !flags.wifi{return Err("Wi-Fi unavailable");}queued(wifi::submit(WifiCommand::Scan))},
  Tool::WifiCapture|Tool::PktCapture=>{if !flags.wifi{return Err("Wi-Fi unavailable");}queued(wifi::submit(if s.stream{WifiCommand::Stream{channel:s.channel,filter}}else{WifiCommand::Observe{channel:s.channel,filter,record:true,respond:false}}))},
  Tool::PktAnalyse|Tool::WifiWps|Tool::WifiClients=>queued(wifi::submit(WifiCommand::Observe{channel:s.channel,filter,record:false,respond:false})),
  Tool::WifiKarma=>queued(wifi::submit(WifiCommand::Observe{channel:s.channel,filter,record:false,respond:true})),
  Tool::WifiEvilTwin=>{
   if s.channel==0{return Err("Pick a channel from 1 to 13 (not All)");}
   let(ssid,_)=app.network_credentials();
   let ssid=if ssid.is_empty(){String::from("Free WiFi")}else{ssid};
   queued(wifi::submit(WifiCommand::Portal{ssid,channel:s.channel,template:cyberdeck_core::wifi::portal::PortalTemplate::NetworkSignIn}))
  },
  Tool::WifiHandshake=>{let mut filter=filter;filter.eapol_only=true;queued(wifi::submit(WifiCommand::Observe{channel:s.channel,filter,record:true,respond:false}))},
  Tool::PktStream=>{if !flags.usb{return Err("Plug the USB port into the PC");}queued(wifi::submit(WifiCommand::Stream{channel:s.channel,filter}))},
  Tool::WifiBeacon|Tool::WifiDeauth|Tool::WifiDisassoc|Tool::WifiAuthFlood|Tool::WifiProbeFlood=>{if s.channel==0{return Err("Pick a channel from 1 to 13 (not All)");}
   let mode=match tool{Tool::WifiBeacon=>cyberdeck_core::wifi::attack::AttackMode::BeaconSpam,Tool::WifiDisassoc=>cyberdeck_core::wifi::attack::AttackMode::Disassoc,Tool::WifiAuthFlood=>cyberdeck_core::wifi::attack::AttackMode::AuthFlood,Tool::WifiProbeFlood=>cyberdeck_core::wifi::attack::AttackMode::ProbeFlood,_=>cyberdeck_core::wifi::attack::AttackMode::Deauth};
   // Disconnect tests and the join flood aim at the selected network; beacon
   // spam and the name flood rotate their own identities.
   let target=if matches!(tool,Tool::WifiDeauth|Tool::WifiDisassoc|Tool::WifiAuthFlood){let(_,aps,_,_)=wifi::snapshot();Some(aps.get(usize::from(s.target)).ok_or("Scan Wi-Fi first and pick a network")?.bssid)}else{None};
   queued(wifi::submit(WifiCommand::Attack{mode,channel:s.channel,target}))},
  Tool::PktFiles=>{if !sd::ready(){return Err("Insert a card first");}queued(sd::request_list())},
  Tool::BleScan=>{if !flags.ble{return Err("Bluetooth unavailable");}queued(ble::submit(BleCommand::Scan))},
  Tool::BleSpam=>{let campaign=cyberdeck_core::ble::spam::SpamCampaign::from_index(s.campaign as usize).unwrap_or(cyberdeck_core::ble::spam::SpamCampaign::IBeacon);queued(ble::submit(BleCommand::Advertise(campaign)))},
  Tool::BleGatt=>queued(ble::submit(BleCommand::Inspect{index:s.target})),
  Tool::BleHid=>queued(ble::submit(BleCommand::HidListen{payload:s.payload,layout})),
  Tool::HidIntro|Tool::HidDucky=>{if !flags.usb{return Err("Native USB HID unavailable");}queued(usb::submit(UsbCommand::RunPayload{index:s.payload,layout}))},
  Tool::RfSpectrum|Tool::RfCapture=>{
   if wifi::busy()||ble::busy(){return Err("Stop Wi-Fi and Bluetooth first");}
   let Some(radio)=rf.radio.as_mut()else{return Err("Attach an nRF24 radio module");};
   let rate=match s.rf_rate{0=>DataRate::Kbps250,2=>DataRate::Mbps2,_=>DataRate::Mbps1};
   // Channel 0 on Radio capture sweeps the research channel plan; 1..125 is fixed.
   let sweep=if tool==Tool::RfCapture&&s.channel==0{Some(cyberdeck_core::rf::capture::sniff_channels())}else{None};
   if tool==Tool::RfCapture{
    // Promiscuous: the MouseJack research sync addresses with CRC off, so
    // packets from unknown senders reach the FIFO (alignment is best-effort).
    radio.promiscuous_rx(rate,s.rf_payload_len).map_err(|_|"Radio module problem")?;
   }else{
    radio.configure(rate,s.rf_payload_len,[0xE7;5]).map_err(|_|"Radio module problem")?;
    radio.set_channel(s.channel.min(125)).map_err(|_|"Radio channel problem")?;
    radio.power_up_rx().map_err(|_|"Radio module did not start")?;
   }
   rf.delay.delay_micros(1600);
   rf.spectrum.clear();rf.log=cyberdeck_core::rf::capture::NrfLog::new();rf.stats=cyberdeck_core::rf::session::SessionStats::new(embassy_time::Instant::now().as_millis());rf.packets=0;rf.channel_cursor=0;rf.sweep=sweep;
   rf.mode=if tool==Tool::RfSpectrum{RfMode::Spectrum}else{RfMode::Capture};Ok(())
  },
  Tool::GpsStatus=>if flags.gps{Ok(())}else{Err("No GPS on this board")},
  Tool::GpsRecord|Tool::GpsWardrive=>{
   if !flags.gps{return Err("Connect a GPS receiver");}
   if gps::fix().is_none(){return Err("No location yet. Wait for a fix");}
   if !sd::ready(){return Err("Insert a card first");}
   if tool==Tool::GpsWardrive{
   if flags.wifi{wifi::submit(WifiCommand::Scan);}
   if flags.ble{ble::submit(BleCommand::Scan);}
  }
   queued(gps::submit(if tool==Tool::GpsWardrive{GpsCommand::Wardrive}else{GpsCommand::Record}))
  },
  Tool::NetInfo|Tool::NetDiscover|Tool::NetProbe|Tool::NetServices=>{
   if !flags.network{return Err("Network unavailable");}
   if !network::ready(){
    let(ssid,password)=app.network_credentials();
    let credentials=cyberdeck_core::network::Credentials::new(&ssid,&password)?;
    if !wifi::submit(WifiCommand::Connect{ssid:credentials.ssid,password:credentials.password}){return Err("Wi-Fi busy. Stop the running tool first");}
   }
   queued(network::submit(match tool{Tool::NetDiscover=>NetCommand::Discover{start:s.target},Tool::NetProbe=>NetCommand::Probe{host:s.target},Tool::NetServices=>NetCommand::Services{host:s.target},_=>NetCommand::Info}))
  },
 }
}
pub fn enable(app:&mut App,flags:Flags){
 if flags.wifi{for tool in [Tool::WifiHandshake,Tool::WifiWps,Tool::WifiClients]{app.set_tool_available(tool);}}
 app.set_tool_available(Tool::PktFiles);
 if flags.usb&&flags.wifi{app.set_tool_available(Tool::PktStream);}
 if flags.ble{app.set_tool_available(Tool::BleGatt);app.set_tool_available(Tool::BleHid);}
 if flags.gps{for tool in [Tool::GpsStatus,Tool::GpsRecord,Tool::GpsWardrive]{app.set_tool_available(tool);}}
 if flags.network{for tool in [Tool::NetInfo,Tool::NetDiscover,Tool::NetProbe,Tool::NetServices]{app.set_tool_available(tool);}}
}

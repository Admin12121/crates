//! FIELD GPS receiver: asynchronous UART, bounded NMEA state and append-only CSV.
use alloc::{format,string::{String,ToString},vec::Vec};
use core::cell::RefCell;
use critical_section::Mutex;
use cyberdeck_core::gps::{Fix,Nmea,FixHistory,ObservationCursor,TrackLog,wigle_header,wigle_row,WardriveObservation};
use esp_hal::{Async,uart::UartRx};
use embassy_time::{Duration,Instant,Timer,with_timeout};
use super::sd;
#[derive(Clone,Copy)]pub enum GpsCommand{Record,Wardrive,Stop}
struct State{fix:Option<Fix>,valid:bool,seen:bool,lines:Vec<String>,points:u32,recording:bool,wardrive:bool,file:Option<String>,ticket:Option<u32>,error:Option<String>}
static STATE:Mutex<RefCell<State>>=Mutex::new(RefCell::new(State{fix:None,valid:false,seen:false,lines:Vec::new(),points:0,recording:false,wardrive:false,file:None,ticket:None,error:None}));
static COMMAND:Mutex<RefCell<Option<GpsCommand>>>=Mutex::new(RefCell::new(None));
pub fn submit(command:GpsCommand)->bool{critical_section::with(|cs|{let mut q=COMMAND.borrow_ref_mut(cs);if matches!(command,GpsCommand::Stop){*q=Some(command);true}else if q.is_some(){false}else{*q=Some(command);true}})}
pub fn detected()->bool{critical_section::with(|cs|STATE.borrow_ref(cs).seen)}
pub fn recording()->bool{critical_section::with(|cs|STATE.borrow_ref(cs).recording)}
pub fn snapshot()->Vec<String>{critical_section::with(|cs|STATE.borrow_ref(cs).lines.clone())}
pub fn fix()->Option<Fix>{let now=Instant::now().as_millis();critical_section::with(|cs|{let state=STATE.borrow_ref(cs);state.fix.as_ref().filter(|f|state.valid&&now.saturating_sub(f.received_ms)<cyberdeck_core::gps::FIX_TTL_MS).cloned()})}
fn message(text:&str){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.error=Some(String::from(text));s.lines=alloc::vec![String::from(text)];});}
fn begin(wardrive:bool){
 if fix().is_none(){message("No location yet. Wait for a fix");return;}
 if !sd::ready(){message("Insert a card first");return;}
 let name=sd::next_name(if wardrive{"DRIVE"}else{"TRACK"},"CSV");
 let header=if wardrive{wigle_header()}else{"uptime_ms,utc_date,utc_time,latitude,longitude,altitude_dm,satellites,hdop_centi\n"};
 let ticket=sd::enqueue_tracked(&name,header.as_bytes().to_vec(),false);
 critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.recording=ticket.is_some();s.wardrive=wardrive;s.points=0;s.file=Some(name);s.ticket=ticket;if ticket.is_some(){s.error=None;}});
 if ticket.is_none(){message("Card busy. Recording not started");}
}
fn save_fix(f:&Fix,now:u64,history:&FixHistory<8>,cursor:&mut ObservationCursor<64>){
 let session=critical_section::with(|cs|{let s=STATE.borrow_ref(cs);if !s.recording{return None;}Some((s.file.clone()?,s.wardrive,s.ticket))});
 let Some((name,wardrive,ticket))=session else{return;};
 if let Some(t)=ticket{match sd::completion(t){Some(result)=>{if !result.success{critical_section::with(|cs|STATE.borrow_ref_mut(cs).recording=false);message("Recording stopped: card problem");return;}},None=>return}}
 let mut bytes=String::new();
 if wardrive{
  let (aps,seen)=super::wifi::scan_observations();
  if let Some(matched)=history.closest(seen,1500){
   for ap in aps.iter().take(24){let address=ap.bssid.to_string();if cursor.accept(&format!("WIFI:{address}"),seen,now,2500){if let Some(row)=wigle_row(matched,&WardriveObservation{address:&address,name:&ap.ssid,auth:ap.security,channel:ap.channel,rssi:ap.rssi,kind:"WIFI"}){bytes.push_str(&row);}}}
  }
  for (device,seen) in super::ble::timed_devices().iter().take(24){
   if let Some(matched)=history.closest(*seen,1500){if cursor.accept(&format!("BLE:{}",device.address),*seen,now,2500){if let Some(row)=wigle_row(matched,&WardriveObservation{address:&device.address,name:&device.name,auth:"[BLE]",channel:0,rssi:device.rssi,kind:"BLE"}){bytes.push_str(&row);}}}
  }
 }else if cursor.accept("TRACK",f.received_ms,now,cyberdeck_core::gps::FIX_TTL_MS){bytes=f.csv_row(now);}
 if bytes.is_empty(){return;}
 if let Some(ticket)=sd::enqueue_tracked(&name,bytes.into_bytes(),true){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.points=s.points.saturating_add(1);s.ticket=Some(ticket);});}else{critical_section::with(|cs|STATE.borrow_ref_mut(cs).recording=false);message("Recording stopped: card unavailable");}
}
pub async fn run(mut uart:UartRx<'static,Async>)->!{
 let mut parser=Nmea::new();let mut buffer=[0;96];let mut last_record=0;let mut last_publish=0;let mut history=FixHistory::<8>::new();let mut cursor=ObservationCursor::<64>::new();let mut track=TrackLog::<256>::new();
 loop{
  if let Some(command)=critical_section::with(|cs|COMMAND.borrow_ref_mut(cs).take()){match command{
   GpsCommand::Record=>{cursor=ObservationCursor::new();track=TrackLog::new();begin(false)},
   GpsCommand::Wardrive=>{cursor=ObservationCursor::new();track=TrackLog::new();begin(true)},
   GpsCommand::Stop=>{
    critical_section::with(|cs|STATE.borrow_ref_mut(cs).recording=false);
    // Route recording keeps an in-memory copy; stopping exports it as GPX.
    if !track.is_empty(){
     let name=sd::next_name("TRK","GPX");
     let exported=sd::enqueue(&name,track.gpx().into_bytes(),false);
     message(if exported{"Track exported"}else{"Track export failed: card unavailable"});
    }
    track=TrackLog::new();
   }}}
  let now=Instant::now().as_millis();
  match with_timeout(Duration::from_millis(100),uart.read_async(&mut buffer)).await{Ok(Ok(len))=>{for b in &buffer[..len]{parser.push(*b,now);}},Ok(Err(_))=>{message("GPS read error");Timer::after(Duration::from_millis(100)).await;},Err(_)=>{}}
  let now=Instant::now().as_millis();
  let fresh=parser.fresh_fix(now).cloned();
  critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.seen=parser.sentences()>0;s.valid=fresh.is_some();s.fix=parser.fix().cloned();});
  if let Some(f)=fresh.as_ref(){history.push(f);
   if now.saturating_sub(last_record)>=1000{save_fix(f,now,&history,&mut cursor);last_record=now;}
   let route=critical_section::with(|cs|{let s=STATE.borrow_ref(cs);s.recording&&!s.wardrive});
   if route{track.record(f,now);}
  }
  if now.saturating_sub(last_publish)>=500{
   critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);let mut lines=Vec::new();
    if let Some(error)=&s.error{lines.push(error.clone());}
    if let Some(f)=fresh.as_ref(){lines.push(format!("Lat {}",f.latitude()));lines.push(format!("Lon {}",f.longitude()));lines.push(format!("{} satellites  HDOP {}.{:02}",f.satellites,f.hdop_centi/100,f.hdop_centi%100));lines.push(format!("Altitude {}.{} m",f.altitude_dm/10,f.altitude_dm.unsigned_abs()%10));lines.push(format!("UTC {} {}",f.utc_date,f.utc_time));}
    else{lines.push(String::from(if s.seen{"Waiting for location"}else{"No GPS receiver data"}));}
    lines.push(format!("{} updates, {} bad",parser.sentences(),parser.checksum_errors()));
    if let Some(file)=&s.file{lines.push(format!("{} {} points",if s.recording{"REC"}else{"Stopped"},s.points));lines.push(file.clone());}
    s.lines=lines;
   });last_publish=now;
  }
 }
}

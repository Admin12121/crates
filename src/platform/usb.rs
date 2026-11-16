use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
use critical_section::Mutex;
use cyberdeck_core::hid::{Layout, ConsumerReport, KeyboardReport, MouseReport};
use cyberdeck_core::hid::ducky;
use cyberdeck_core::hid::engine::{HidEngine, Output};
use cyberdeck_core::hid::session::SessionQueue;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState, Sender, Receiver};
use embassy_usb::class::hid::{Config as HidConfig, HidWriter, State as HidState};
use embassy_usb::driver::Driver;
use embassy_usb::{Builder, Config as UsbConfig, Handler};

const POLL_MS: u64 = 10;
const REPORT_KEYBOARD: u8 = 1;
const REPORT_CONSUMER: u8 = 2;
const REPORT_MOUSE: u8 = 3;
pub(super) const REPORT_DESCRIPTOR: &[u8] = &[
    0x05,
    0x01, // Usage Page (Generic Desktop)
    0x09,
    0x06, // Usage (Keyboard)
    0xA1,
    0x01, // Collection (Application)
    0x85,
    REPORT_KEYBOARD, //   Report ID
    0x05,
    0x07, //   Usage Page (Keyboard)
    0x19,
    0xE0,
    0x29,
    0xE7,
    0x15,
    0x00,
    0x25,
    0x01,
    0x75,
    0x01,
    0x95,
    0x08,
    0x81,
    0x02, //   modifiers
    0x95,
    0x01,
    0x75,
    0x08,
    0x81,
    0x01, //   reserved byte
    0x95,
    0x06,
    0x75,
    0x08,
    0x15,
    0x00,
    0x25,
    0x65,
    0x05,
    0x07,
    0x19,
    0x00,
    0x29,
    0x65,
    0x81,
    0x00, //   six keycodes
    0xC0, // End Collection
    0x05,
    0x0C, // Usage Page (Consumer)
    0x09,
    0x01, // Usage (Consumer Control)
    0xA1,
    0x01, // Collection (Application)
    0x85,
    REPORT_CONSUMER, //   Report ID
    0x15,
    0x00,
    0x26,
    0xFF,
    0x03,
    0x19,
    0x00,
    0x2A,
    0xFF,
    0x03,
    0x75,
    0x10,
    0x95,
    0x01,
    0x81,
    0x00, //   one 16-bit usage
    0xC0, // End Collection
    0x05,
    0x01, // Usage Page (Generic Desktop)
    0x09,
    0x02, // Usage (Mouse)
    0xA1,
    0x01, // Collection (Application)
    0x85,
    REPORT_MOUSE, //   Report ID
    0x09,
    0x01, //   Usage (Pointer)
    0xA1,
    0x00, //   Collection (Physical)
    0x05,
    0x09,
    0x19,
    0x01,
    0x29,
    0x03,
    0x15,
    0x00,
    0x25,
    0x01,
    0x95,
    0x03,
    0x75,
    0x01,
    0x81,
    0x02, //     three buttons
    0x95,
    0x01,
    0x75,
    0x05,
    0x81,
    0x01, //     padding
    0x05,
    0x01,
    0x09,
    0x30,
    0x09,
    0x31,
    0x09,
    0x38,
    0x15,
    0x81,
    0x25,
    0x7F,
    0x75,
    0x08,
    0x95,
    0x03,
    0x81,
    0x06, //     X, Y, wheel
    0xC0, //   End Collection
    0xC0, // End Collection
];


pub struct UsbStatus {
    pub installed: bool,
    pub status: String,
    pub percent: u8,
    pub keystrokes: u32,
    pub unsupported: u32,
}
impl UsbStatus {
    const fn new() -> Self { Self { installed: false, status: String::new(), percent: 0, keystrokes: 0, unsupported: 0 } }
}
static STATE: Mutex<RefCell<UsbStatus>> = Mutex::new(RefCell::new(UsbStatus::new()));
static COMMAND: Mutex<RefCell<SessionQueue<UsbCommand>>> = Mutex::new(RefCell::new(SessionQueue::new()));
static PAUSED: AtomicBool = AtomicBool::new(false);
static CONFIGURED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub enum UsbCommand {
    RunDemo,
    RunText { name: String, source: String, layout: Layout },
    RunPayload { index: u8, layout: Layout },
    Pause,
    Resume,
    Stop,
}
pub fn is_installed() -> bool { critical_section::with(|cs| STATE.borrow_ref(cs).installed) }
pub fn submit(command: UsbCommand) -> bool {
    critical_section::with(|cs| {
        match command {
            UsbCommand::Stop => { COMMAND.borrow_ref_mut(cs).stop(); true }
            UsbCommand::Pause => { PAUSED.store(true, Ordering::Release); true }
            UsbCommand::Resume => { PAUSED.store(false, Ordering::Release); true }
            _ => COMMAND.borrow_ref_mut(cs).submit(command),
        }
    })
}
fn current(token: u32) -> bool { critical_section::with(|cs| COMMAND.borrow_ref(cs).is_current(token)) }
pub fn preview(index: u8) -> Option<String> {
    super::payload::preview(index)
}
fn publish(status: &str, percent: u8, keystrokes: u32, unsupported: u32) {
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.status.clear(); state.status.push_str(status);
        state.percent = percent; state.keystrokes = keystrokes; state.unsupported = unsupported;
    });
}
pub fn snapshot() -> (String, u8, u32, u32) {
    critical_section::with(|cs| { let s=STATE.borrow_ref(cs); (s.status.clone(),s.percent,s.keystrokes,s.unsupported) })
}
struct UsbEvents;
impl Handler for UsbEvents {
    fn configured(&mut self, configured: bool) { CONFIGURED.store(configured, Ordering::Release); }
    fn reset(&mut self) { CONFIGURED.store(false, Ordering::Release); }
    fn enabled(&mut self, enabled: bool) { if !enabled { CONFIGURED.store(false, Ordering::Release); } }
}
fn encode(output: Output) -> ([u8;9],usize) {
    let mut frame=[0;9];
    let len=match output {
        Output::Keyboard(r)=>{frame[0]=REPORT_KEYBOARD;frame[1..9].copy_from_slice(&r.to_bytes());9}
        Output::Consumer(r)=>{frame[0]=REPORT_CONSUMER;frame[1..3].copy_from_slice(&r.to_bytes());3}
        Output::Mouse(r)=>{frame[0]=REPORT_MOUSE;frame[1..5].copy_from_slice(&r.to_bytes());5}
        Output::ReleaseAll=>{frame[0]=REPORT_KEYBOARD;9}
    };(frame,len)
}
async fn release_all<'d,D:Driver<'d>>(writer:&mut HidWriter<'d,D,9>)->bool {
    let reports=[
        Output::Keyboard(KeyboardReport { modifiers:0,keycodes:[0;6] }),
        Output::Consumer(ConsumerReport { usage:0 }),
        Output::Mouse(MouseReport { buttons:0,dx:0,dy:0,wheel:0 }),
    ];
    let mut ok=true;
    for output in reports {
        let(frame,len)=encode(output);
        ok &= matches!(with_timeout(Duration::from_millis(150),writer.write(&frame[..len])).await,Ok(Ok(())));
    } ok
}
async fn hid_loop<'d,D:Driver<'d>>(mut writer:HidWriter<'d,D,9>)->! {
    loop {
        let command=critical_section::with(|cs| COMMAND.borrow_ref_mut(cs).take());
        if let Some((token,command))=command {
            if !CONFIGURED.load(Ordering::Acquire) {
                publish("Plug into a PC, then press Start",0,0,0);
            } else if current(token) {
                let (name,body,layout)=match command {
                    UsbCommand::RunText{name,source,layout} => {
                        if name.len()>64 || source.len()>8192 || cyberdeck_core::hid::engine::validate_payload_name(&name).is_err() {publish("Script too big or wrongly named",0,0,0);continue;}
                        (name,source,layout)
                    }
                    other => {
                        let(index,layout)=match other {UsbCommand::RunPayload{index,layout}=>(index,layout),_=>(0,Layout::Us)};
                        let Some((name,body))=super::payload::resolve(index) else {publish("Unknown script",0,0,0);continue;};
                        (name,body,layout)
                    }
                };
                match ducky::parse(&name,&body) {
                    Err(error)=>publish(&error.describe(),0,0,0),
                    Ok(script)=>{
                        PAUSED.store(false,Ordering::Release);
                        let mut engine=HidEngine::new(&script,layout);
                        let mut failed=false; let mut was_paused=false;
                        loop {
                            if !current(token) || !CONFIGURED.load(Ordering::Acquire) { engine.stop(); }
                            let paused=PAUSED.load(Ordering::Acquire);
                            if paused && !was_paused && !release_all(&mut writer).await { failed=true;break; }
                            was_paused=paused; engine.set_paused(paused);
                            let now=Instant::now().as_millis();
                            if let Some(output)=engine.next_report(now) {
                                // One short report per poll keeps Stop responsive even in long scripts.
                                if matches!(output,Output::ReleaseAll) {
                                    if !release_all(&mut writer).await { failed=true; }
                                } else {
                                    if !current(token) { engine.stop();continue; }
                                    let(frame,len)=encode(output);
                                    if !matches!(with_timeout(Duration::from_millis(250),writer.write(&frame[..len])).await,Ok(Ok(()))) { failed=true;break; }
                                }
                            }
                            let p=engine.progress();
                            publish(if paused {"paused"} else {name.as_str()},p.percent,engine.keystrokes(),engine.unsupported_chars());
                            if engine.is_finished() {break;}
                            Timer::after(Duration::from_millis(POLL_MS)).await;
                        }
                        let released=release_all(&mut writer).await;
                        let p=engine.progress();
                        publish(if failed || !released {"Sending failed. Replug the USB cable"} else if !current(token) {"Stopped. Keys released"} else {"Script sent"},p.percent,engine.keystrokes(),engine.unsupported_chars());
                    }
                }
            }
        }
        Timer::after(Duration::from_millis(POLL_MS)).await;
    }
}

// CDC packets are queued as whole PCAP records. Full queues reject the complete record.
const MAX_STREAM_RECORD:usize=1664;
const STREAM_RECORDS:usize=8;
struct Stream {
    connected:bool, accepting:bool, active:bool, generation:u32,
    queue:VecDeque<Vec<u8>>, bytes:u32, rejected:u32,
}
impl Stream {
    const fn new()->Self {Self{connected:false,accepting:false,active:false,generation:0,queue:VecDeque::new(),bytes:0,rejected:0}}
    fn disconnect(&mut self) { self.connected=false;self.accepting=false;self.active=false;self.generation=self.generation.wrapping_add(1);self.queue.clear(); }
}
static STREAM:Mutex<RefCell<Stream>>=Mutex::new(RefCell::new(Stream::new()));
static CONSOLE:Mutex<RefCell<VecDeque<String>>>=Mutex::new(RefCell::new(VecDeque::new()));
pub fn take_console_line()->Option<String> {critical_section::with(|cs|CONSOLE.borrow_ref_mut(cs).pop_front())}
pub fn pcap_start()->bool { critical_section::with(|cs| {
    let mut s=STREAM.borrow_ref_mut(cs);
    if !s.connected || s.active || !s.queue.is_empty(){return false;}
    s.generation=s.generation.wrapping_add(1);s.accepting=true;s.active=true;s.bytes=0;s.rejected=0;true
})}
pub fn pcap_write(record:&[u8])->bool {critical_section::with(|cs|{
    let mut s=STREAM.borrow_ref_mut(cs);
    if !s.connected || !s.accepting || record.is_empty() || record.len()>MAX_STREAM_RECORD || s.queue.len()>=STREAM_RECORDS {
        s.rejected=s.rejected.saturating_add(1);return false;
    }
    s.queue.push_back(record.to_vec());true
})}
pub fn pcap_finish(){critical_section::with(|cs|STREAM.borrow_ref_mut(cs).accepting=false)}
pub fn pcap_status()->(bool,u32,u32){critical_section::with(|cs|{let s=STREAM.borrow_ref(cs);(s.connected,s.bytes,s.rejected)})}
async fn cdc_send<'d,D:Driver<'d>>(mut sender:Sender<'d,D>)->! {
    loop {
        let connected=sender.dtr() && CONFIGURED.load(Ordering::Acquire);
        let item=critical_section::with(|cs|{
            let mut s=STREAM.borrow_ref_mut(cs);
            if !connected {if s.connected || s.active{s.disconnect();}return None;}
            s.connected=true;
            match s.queue.pop_front() {
                Some(record)=>Some((s.generation,record)),
                None=>{if !s.accepting{s.active=false;}None}
            }
        });
        if let Some((generation,record))=item {
            let mut success=true;
            for chunk in record.chunks(64) {
                if !sender.dtr() || !matches!(with_timeout(Duration::from_millis(500),sender.write_packet(chunk)).await,Ok(Ok(()))) {success=false;break;}
            }
            // A short final USB packet terminates exact-multiple bulk transfers.
            if success && record.len()%64==0 {
                success=matches!(with_timeout(Duration::from_millis(500),sender.write_packet(&[])).await,Ok(Ok(())));
            }
            critical_section::with(|cs|{
                let mut s=STREAM.borrow_ref_mut(cs);
                if s.generation==generation {
                    if success{s.bytes=s.bytes.saturating_add(record.len() as u32);}else{s.disconnect();}
                }
            });
        } else {Timer::after(Duration::from_millis(POLL_MS)).await;}
    }
}
async fn cdc_receive<'d,D:Driver<'d>>(mut receiver:Receiver<'d,D>)->! {
    let mut packet=[0;64]; let mut line=String::new();let mut overflow=false;
    loop {
        receiver.wait_connection().await;
        match receiver.read_packet(&mut packet).await {
            Ok(len)=>for &byte in &packet[..len] {
                if byte==b'\n' {
                    if !overflow && !line.is_empty() {critical_section::with(|cs|{
                        let mut q=CONSOLE.borrow_ref_mut(cs);
                        if q.len()<4 {q.push_back(core::mem::take(&mut line));}
                    });}
                    line.clear();overflow=false;
                } else if byte==b'\r' {} else if byte.is_ascii_graphic() || byte==b' ' {
                    if line.len()<192 {line.push(byte as char);}else{overflow=true;}
                }
            },
            Err(_)=>{line.clear();overflow=false;Timer::after(Duration::from_millis(10)).await;}
        }
    }
}
pub async fn run(usb:esp_hal::usb::otg::Usb<'static>)->! {
    let mut ep_out_buffer=[0;256];
    let driver=esp_hal::usb::otg::embassy_usb_device::Driver::new(usb,&mut ep_out_buffer,esp_hal::usb::otg::embassy_usb_device::Config::default());
    // The HID_CDC profile is what this build enumerates. Identity switching
    // needs re-enumeration, which embassy-usb cannot do after build().
    let profile=cyberdeck_core::hid::UsbProfile::HID_CDC;
    let mut config=UsbConfig::new(profile.vendor_id,profile.product_id);
    config.manufacturer=Some(profile.manufacturer);config.product=Some(profile.product);config.serial_number=Some(profile.serial);
    config.max_power=100;config.max_packet_size_0=64;
    // Composite IAD class values required by Windows for CDC alongside HID.
    config.device_class=0xEF;config.device_sub_class=0x02;config.device_protocol=0x01;config.composite_with_iads=true;
    let mut config_descriptor=[0;384];let mut bos_descriptor=[0;256];let mut msos_descriptor=[0;256];let mut control_buffer=[0;64];
    let mut hid_state=HidState::new();let mut cdc_state=CdcState::new();let mut events=UsbEvents;
    let mut builder=Builder::new(driver,config,&mut config_descriptor,&mut bos_descriptor,&mut msos_descriptor,&mut control_buffer);
    builder.handler(&mut events);
    let writer=HidWriter::<_,9>::new(&mut builder,&mut hid_state,HidConfig{report_descriptor:REPORT_DESCRIPTOR,request_handler:None,poll_ms:10,max_packet_size:9});
    let cdc=CdcAcmClass::new(&mut builder,&mut cdc_state,64);
    let(sender,receiver)=cdc.split();
    let mut device=builder.build();
    critical_section::with(|cs|STATE.borrow_ref_mut(cs).installed=true);
    publish("Pick a script, then press Start",0,0,0);
    // device.run is created once and never dropped during polls or HID writes.
    embassy_futures::join::join(device.run(),embassy_futures::join::join3(hid_loop(writer),cdc_send(sender),cdc_receive(receiver))).await;
    unreachable!()
}

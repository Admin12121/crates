use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bt_hci::cmd::SyncCmd;
use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams, LeSetScanEnable, LeSetScanParams};
use bt_hci::controller::{ControllerCmdSync, ExternalController};
use bt_hci::param::{AddrKind, AdvChannelMap, AdvKind, BdAddr, Duration as HciDuration, LeScanKind, ScanningFilterPolicy};
use critical_section::Mutex;
use cyberdeck_core::ble::ad::{AdvReport, BleAddress};
use cyberdeck_core::ble::spam::{SpamCampaign, SpamRotator};
use cyberdeck_core::ble::vendor::classify;
use cyberdeck_core::hid::{ConsumerReport, KeyboardReport, Layout, MouseReport};
use cyberdeck_core::hid::engine::{BUILTIN_SCRIPTS, HidEngine, Output};
use cyberdeck_core::hid::session::SessionQueue;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

const MAX_DEVICES: usize = 24;
type BleController = ExternalController<BleConnector<'static>, 1>;
type BleStack<'a> = Stack<'a, BleController, DefaultPacketPool>;

#[derive(Clone)]
pub struct BleDevice {
    pub address: String,
    pub name: String,
    pub rssi: i8,
    pub kind: &'static str,
    pub detail: String,
    /// Uptime of the most recent advertisement from this device, used by
    /// wardriving to correlate a sighting with the nearest GPS fix.
    pub seen: u64,
    raw: trouble_host::Address,
}
pub struct BleState {
    pub online: bool,
    pub status: String,
    pub devices: Vec<BleDevice>,
    pub frames: u32,
    gatt: Vec<String>,
}
impl BleState {
    const fn new() -> Self { Self { online:false, status:String::new(), devices:Vec::new(), frames:0, gatt:Vec::new() } }
}
static STATE: Mutex<RefCell<BleState>> = Mutex::new(RefCell::new(BleState::new()));
static COMMAND: Mutex<RefCell<SessionQueue<BleCommand>>> = Mutex::new(RefCell::new(SessionQueue::new()));
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SCANNING: AtomicBool = AtomicBool::new(false);
static SCAN_TOKEN: AtomicU32 = AtomicU32::new(0);
static HID_PROGRESS: Mutex<RefCell<(u8,u32,u32)>> = Mutex::new(RefCell::new((0,0,0)));
static HID_CONNECTED: AtomicBool = AtomicBool::new(false);
static HID_PAUSED: AtomicBool = AtomicBool::new(false);
static HID_PAYLOAD: Mutex<RefCell<Option<(u8, Layout)>>> = Mutex::new(RefCell::new(None));

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BleCommand {
    Scan,
    ScanConfigured { active:bool, interval_ms:u16, window_ms:u16 },
    Advertise(SpamCampaign),
    Inspect { index:u8 },
    /// Advertise as a HID peripheral and deliver this payload once paired.
    HidListen { payload:u8, layout:Layout },
    RunHidPayload { index:u8, layout:Layout },
    HidPause,
    HidResume,
    Stop,
}
pub fn submit(command:BleCommand)->bool {
    critical_section::with(|cs| match command {
        BleCommand::Stop => {
            COMMAND.borrow_ref_mut(cs).stop();
            HID_PAYLOAD.borrow_ref_mut(cs).take();
            true
        }
        BleCommand::RunHidPayload {index,layout} => {
            if !HID_CONNECTED.load(Ordering::Acquire) { return false; }
            let mut slot=HID_PAYLOAD.borrow_ref_mut(cs);
            if slot.is_some() {return false;}
            *slot=Some((index,layout));true
        }
        BleCommand::HidPause => {HID_PAUSED.store(true,Ordering::Release);true}
        BleCommand::HidResume => {HID_PAUSED.store(false,Ordering::Release);true}
        _=> COMMAND.borrow_ref_mut(cs).submit(command),
    })
}
pub fn busy()->bool { critical_section::with(|cs| ACTIVE.load(Ordering::Acquire) || COMMAND.borrow_ref(cs).has_pending()) }
pub fn online() { critical_section::with(|cs| STATE.borrow_ref_mut(cs).online=true); }
fn current(token:u32)->bool {critical_section::with(|cs|COMMAND.borrow_ref(cs).is_current(token))}
fn set_status(text:&str) {critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.status.clear();s.status.push_str(text);});}
pub fn snapshot()->(String,Vec<BleDevice>,u32) {critical_section::with(|cs|{let s=STATE.borrow_ref(cs);(s.status.clone(),s.devices.clone(),s.frames)})}
pub fn gatt_snapshot()->Vec<String> {critical_section::with(|cs|STATE.borrow_ref(cs).gatt.clone())}
pub fn hid_snapshot()->(String,u8,u32,u32) { let status=critical_section::with(|cs|STATE.borrow_ref(cs).status.clone());let(p,k,u)=critical_section::with(|cs|*HID_PROGRESS.borrow_ref(cs));(status,p,k,u) }
pub fn hid_connected()->bool {HID_CONNECTED.load(Ordering::Acquire)}
async fn cancelled(token:u32) {while current(token) {Timer::after(Duration::from_millis(20)).await;}}
async fn bounded<F:Future>(token:u32, timeout_ms:u64, future:F)->Result<F::Output,&'static str> {
    if !current(token) {return Err("cancelled");}
    match select(with_timeout(Duration::from_millis(timeout_ms),future),cancelled(token)).await {
        Either::First(Ok(result)) if current(token)=>Ok(result),
        Either::First(Err(_))=>Err("operation timed out"),
        _=>Err("cancelled"),
    }
}
async fn command<T:SyncCmd>(stack:&BleStack<'_>,token:u32,cmd:T)->Result<T::Return,&'static str>
where BleController:ControllerCmdSync<T> {
    bounded(token,3000,stack.command(cmd)).await?.map_err(|_|"controller rejected command")
}
fn record(raw:trouble_host::Address,rssi:i8,data:&[u8],connectable:bool) {
    if !SCANNING.load(Ordering::Acquire) || !current(SCAN_TOKEN.load(Ordering::Acquire)) {return;}
    let now=Instant::now().as_millis();
    let report=AdvReport::parse(BleAddress::new(raw.addr.into_inner()),rssi,data,connectable,now);
    let matched=classify(&report);
    let detail=alloc::format!("{}; {} AD bytes; {} address",matched.vendor,data.len(),if raw.kind.as_raw()&1!=0{"random"}else{"public"});
    critical_section::with(|cs| {
        let mut s=STATE.borrow_ref_mut(cs);s.frames=s.frames.saturating_add(1);
        if let Some(slot)=s.devices.iter_mut().find(|d|d.raw==raw) {
            slot.rssi=rssi;slot.seen=now;if let Some(name)=report.name {slot.name=name;}
            slot.kind=matched.kind.label();slot.detail=detail;return;
        }
        if s.devices.len()>=MAX_DEVICES {s.devices.remove(0);}
        s.devices.push(BleDevice{address:alloc::format!("{raw}"),name:report.name.unwrap_or_default(),rssi,kind:matched.kind.label(),detail,seen:now,raw});
    });
}

/// Devices paired with their last-seen uptime, freshest first, so wardriving
/// can correlate a BLE sighting with the GPS fix nearest to that sighting.
pub fn timed_devices()->Vec<(BleDevice,u64)>{
    critical_section::with(|cs|{
        let s=STATE.borrow_ref(cs);
        let mut rows:Vec<(BleDevice,u64)>=s.devices.iter().map(|d|(d.clone(),d.seen)).collect();
        rows.sort_by_key(|(_,seen)|core::cmp::Reverse(*seen));
        rows
    })
}
struct Observer;
impl EventHandler for Observer {
    fn on_adv_reports(&self,reports:bt_hci::param::LeAdvReportsIter) {
        for report in reports {
            let Ok(report)=report else {continue;};
            // `LeAdvEventKind` is a plain enum in bt-hci 0.9: no raw accessor exists.
            // Kinds 0/1 (AdvInd, AdvDirectInd) are the connectable advertisements.
            let connectable=matches!(&report.event_kind,
                bt_hci::param::LeAdvEventKind::AdvInd|bt_hci::param::LeAdvEventKind::AdvDirectInd);
            record(trouble_host::Address::new(report.addr_kind,report.addr),report.rssi,report.data,connectable);
        }
    }
}

pub async fn run(controller:BleController)->! {
    let mut resources:HostResources<_,DefaultPacketPool,1,3>=HostResources::new();
    let mut address=[0;6];esp_hal::rng::Rng::new().read(&mut address);address[5]|=0xC0;
    let stack=trouble_host::new(controller,&mut resources).set_random_address(trouble_host::Address::random(address)).build();
    stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
    let mut runner=stack.runner();
    // The host owns one permanent HCI reader, initialized together with its
    // reset/event-mask control task. Commands never wait without a reader.
    let host=async {
        loop {
            if runner.run_with_handler(&Observer).await.is_err() {
                set_status("BLE transport failed; restart device");
                critical_section::with(|cs|STATE.borrow_ref_mut(cs).online=false);
                COMMAND_STOP();
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    };
    embassy_futures::join::join(host,actor(&stack)).await;
    unreachable!()
}
#[allow(non_snake_case)]
fn COMMAND_STOP(){critical_section::with(|cs|COMMAND.borrow_ref_mut(cs).stop());}
async fn actor(stack:&BleStack<'_>)->! {
    loop {
        let next=critical_section::with(|cs| {
            let next=COMMAND.borrow_ref_mut(cs).take();
            if next.is_some(){ACTIVE.store(true,Ordering::Release);} next
        });
        if let Some((token,cmd))=next {
            let result=match cmd {
                BleCommand::Scan=>scan(stack,token,false,100,50).await,
                BleCommand::ScanConfigured{active,interval_ms,window_ms}=>scan(stack,token,active,interval_ms,window_ms).await,
                BleCommand::Advertise(campaign)=>advertise(stack,token,campaign).await,
                BleCommand::Inspect{index}=>inspect(stack,token,index).await,
                BleCommand::HidListen{payload,layout}=>hid_listen(stack,token,payload,layout).await,
                _=>Ok(()),
            };
            // Cleanup is awaited before busy becomes false, including a rapid
            // Stop/restart with another generation already in the command slot.
            SCANNING.store(false,Ordering::Release);
            let scan_off=with_timeout(Duration::from_millis(1000),stack.command(LeSetScanEnable::new(false,false))).await;
            let adv_off=with_timeout(Duration::from_millis(1000),stack.command(LeSetAdvEnable::new(false))).await;
            if !matches!(scan_off,Ok(Ok(()))) || !matches!(adv_off,Ok(Ok(()))) {set_status("BLE cleanup failed; restart device");}
            else if let Err(message)=result {set_status(message);}
            ACTIVE.store(false,Ordering::Release);
        }
        Timer::after(Duration::from_millis(20)).await;
    }
}
async fn scan(stack:&BleStack<'_>,token:u32,active:bool,interval_ms:u16,window_ms:u16)->Result<(),&'static str> {
    let interval=u32::from(interval_ms.clamp(10,10240));let window=u32::from(window_ms).clamp(3,interval);
    critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.devices.clear();s.frames=0;s.gatt.clear();});
    set_status(if active{"active scan"}else{"passive scan"});
    command(stack,token,LeSetScanParams::new(if active{LeScanKind::Active}else{LeScanKind::Passive},HciDuration::from_millis(interval),HciDuration::from_millis(window),AddrKind::RANDOM,ScanningFilterPolicy::BasicUnfiltered)).await?;
    SCAN_TOKEN.store(token,Ordering::Release);SCANNING.store(true,Ordering::Release);
    // Keep duplicates: RSSI/name changes must update a stable-size device table.
    command(stack,token,LeSetScanEnable::new(true,false)).await?;
    cancelled(token).await;
    let count=critical_section::with(|cs|STATE.borrow_ref(cs).devices.len());
    set_status(&alloc::format!("scan stopped: {count} devices"));Ok(())
}
async fn advertise(stack:&BleStack<'_>,token:u32,campaign:SpamCampaign)->Result<(),&'static str> {
    set_status(campaign.label());critical_section::with(|cs|STATE.borrow_ref_mut(cs).frames=0);
    command(stack,token,LeSetAdvParams::new(HciDuration::from_millis(100),HciDuration::from_millis(100),AdvKind::AdvNonconnInd,AddrKind::RANDOM,AddrKind::PUBLIC,BdAddr::new([0;6]),AdvChannelMap::ALL,bt_hci::param::AdvFilterPolicy::Unfiltered)).await?;
    // The rotator takes a 64-bit seed; one `random()` call only yields 32 bits.
    let seed=(u64::from(esp_hal::rng::Rng::new().random())<<32)|u64::from(esp_hal::rng::Rng::new().random());
    let mut rotator=SpamRotator::new(campaign,seed);
    let mut builder=cyberdeck_core::ble::ad::AdvBuilder::new();
    while current(token) {
        if !rotator.next_payload(&mut builder){break;}
        // Disable before replacing data so both controller state and failures are explicit.
        command(stack,token,LeSetAdvEnable::new(false)).await?;
        let mut data=[0;31];let len=builder.as_slice().len();data[..len].copy_from_slice(builder.as_slice());
        command(stack,token,LeSetAdvData::new(len as u8,data)).await?;
        command(stack,token,LeSetAdvEnable::new(true)).await?;
        critical_section::with(|cs|STATE.borrow_ref_mut(cs).frames=rotator.frames());
        let _=bounded(token,200,Timer::after(Duration::from_millis(100))).await;
    }
    let frames=critical_section::with(|cs|STATE.borrow_ref(cs).frames);
    set_status(&alloc::format!("{frames} frames advertised"));Ok(())
}
fn gatt_line(line:String){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);if s.gatt.len()<72{s.gatt.push(line);}});}
async fn inspect(stack:&BleStack<'_>,token:u32,index:u8)->Result<(),&'static str> {
    let target=critical_section::with(|cs|STATE.borrow_ref(cs).devices.get(usize::from(index)).map(|d|d.raw)).ok_or("select a scanned device")?;
    critical_section::with(|cs|STATE.borrow_ref_mut(cs).gatt.clear());
    set_status("GATT connecting (read-only)");
    let mut central=stack.central();let filter=[target];
    let config=ConnectConfig{scan_config:ScanConfig{filter_accept_list:&filter,active:false,..Default::default()},connect_params:Default::default()};
    let conn=bounded(token,12000,central.connect(&config)).await?.map_err(|_|"GATT connection failed")?;
    let result=async {
        let client=bounded(token,5000,GattClient::<_,DefaultPacketPool,16>::new(stack,&conn)).await?.map_err(|_|"GATT MTU negotiation failed")?;
        let discover=async {
            let services=bounded(token,15000,client.services()).await?.map_err(|_|"service discovery failed or table full")?;
            for service in &services {
                if !current(token){return Err("cancelled");}
                gatt_line(alloc::format!("Service {:?} {:?}",service.uuid(),service.handle_range()));
                let chars=bounded(token,12000,client.characteristics::<24>(service)).await?.map_err(|_|"characteristic discovery failed or table full")?;
                for characteristic in &chars {
                    let mut row=alloc::format!("  {:04X} {:?} {:?}",characteristic.handle,characteristic.uuid,characteristic.props);
                    // Discovery itself never writes remote values. Read at most
                    // 32 bytes from explicitly readable characteristics.
                    if characteristic.props.any(&[CharacteristicProp::Read]) {
                        let mut value=[0;32];
                        match bounded(token,3000,client.read_characteristic(characteristic,&mut value)).await {
                            Ok(Ok(len))=>{use core::fmt::Write;let _=write!(row," = {:02X?}",&value[..len.min(32)]);}
                            Ok(Err(_))=>row.push_str(" (read denied)"),
                            Err("cancelled")=>return Err("cancelled"),
                            Err(_)=>row.push_str(" (read timeout)"),
                        }
                    }
                    gatt_line(row);
                }
            }
            set_status(&alloc::format!("GATT: {} services; read-only",services.len()));Ok(())
        };
        match select(client.task(),discover).await {
            Either::First(_)=>Err("GATT peer disconnected"),Either::Second(result)=>result,
        }
    }.await;
    conn.disconnect();result
}

type HidServer<'a> = AttributeServer<'a,NoopRawMutex,DefaultPacketPool,48,1>;
struct HidReports {keyboard:Characteristic<[u8;8]>,consumer:Characteristic<[u8;2]>,mouse:Characteristic<[u8;4]>}
fn hid_server<'a>(keyboard:&'a mut [u8;8],consumer:&'a mut [u8;2],mouse:&'a mut [u8;4])->(HidServer<'a>,HidReports) {
    let mut table:AttributeTable<'a,NoopRawMutex,48>=AttributeTable::new();
    {
        let mut gap=table.add_service(Service::new(0x1800u16));
        gap.add_characteristic_ro(0x2A00u16,b"Admin12121 HID" as &[u8]).build();
        gap.add_characteristic_ro(0x2A01u16,&[0xC1u8,0x03]).build();gap.build();
    }
    let reports;
    {
        let mut hid=table.add_service(Service::new(0x1812u16));
        hid.add_characteristic_ro(0x2A4Au16,&[0x11u8,0x01,0x00,0x02]).build();
        hid.add_characteristic_ro(0x2A4Bu16,super::usb::REPORT_DESCRIPTOR).build();
        hid.add_characteristic_small(0x2A4Cu16,[CharacteristicProp::WriteWithoutResponse],0u8).build();
        let mut key=hid.add_characteristic(0x2A4Du16,[CharacteristicProp::Read,CharacteristicProp::Notify],[0u8;8],keyboard);
        key.add_descriptor_ro(0x2908u16,PermissionLevel::Allowed,&[1u8,1]);let keyboard=key.build();
        let mut media=hid.add_characteristic(0x2A4Du16,[CharacteristicProp::Read,CharacteristicProp::Notify],[0u8;2],consumer);
        media.add_descriptor_ro(0x2908u16,PermissionLevel::Allowed,&[2u8,1]);let consumer=media.build();
        let mut pointer=hid.add_characteristic(0x2A4Du16,[CharacteristicProp::Read,CharacteristicProp::Notify],[0u8;4],mouse);
        pointer.add_descriptor_ro(0x2908u16,PermissionLevel::Allowed,&[3u8,1]);let mouse=pointer.build();
        reports=HidReports{keyboard,consumer,mouse};hid.build();
    }
    (AttributeServer::new(table),reports)
}
async fn hid_output(reports:&HidReports,conn:&GattConnection<'_,'_,DefaultPacketPool>,output:Output)->Result<(),&'static str> {
    match output {
        Output::Keyboard(report)=>reports.keyboard.notify(conn,&report.to_bytes(),true).await,
        Output::Consumer(report)=>reports.consumer.notify(conn,&report.to_bytes(),true).await,
        Output::Mouse(report)=>reports.mouse.notify(conn,&report.to_bytes(),true).await,
        Output::ReleaseAll=>{
            reports.keyboard.notify(conn,&KeyboardReport{modifiers:0,keycodes:[0;6]}.to_bytes(),true).await.map_err(|_|"BLE keyboard release failed")?;
            reports.consumer.notify(conn,&ConsumerReport{usage:0}.to_bytes(),true).await.map_err(|_|"BLE consumer release failed")?;
            reports.mouse.notify(conn,&MouseReport{buttons:0,dx:0,dy:0,wheel:0}.to_bytes(),true).await
        }
    }.map_err(|_|"BLE HID report failed")
}
async fn hid_listen(stack:&BleStack<'_>,token:u32,payload:u8,layout:Layout)->Result<(),&'static str> {
    let mut keyboard=[0;8];let mut consumer=[0;2];let mut mouse=[0;4];
    let(server,reports)=hid_server(&mut keyboard,&mut consumer,&mut mouse);
    let mut peripheral=stack.peripheral();
    // Ordinary discoverable HOGP, enabled only by the local Pair action.
    let adv=[2,1,6,3,3,0x12,0x18,3,0x19,0xC1,0x03];
    let scan=[16,9,b'A',b'd',b'm',b'i',b'n',b'1',b'2',b'1',b'2',b'1',b' ',b'H',b'I',b'D'];
    set_status("Pair Admin12121 HID from host");
    let advertiser=bounded(token,5000,peripheral.advertise(&AdvertisementParameters::default(),Advertisement::ConnectableScannableUndirected{adv_data:&adv,scan_data:&scan})).await?.map_err(|_|"HID advertising failed")?;
    let raw=bounded(token,60000,advertiser.accept()).await?.map_err(|_|"HID connection failed")?;
    let conn=raw.with_attribute_server(&server).map_err(|_|"HID attribute server unavailable")?;
    let _=conn.raw().request_security();
    HID_CONNECTED.store(true,Ordering::Release);
    HID_PAUSED.store(false,Ordering::Release);
    // Queue the chosen script now; it runs as soon as the host has paired and
    // subscribed, so pairing on the phone is the only user step.
    critical_section::with(|cs|*HID_PAYLOAD.borrow_ref_mut(cs)=Some((payload,layout)));
    set_status("HID connected; pair, then select Run");
    let events=async {
        loop {match conn.next().await {
            GattConnectionEvent::Disconnected{..}=>return Err("HID host disconnected"),
            GattConnectionEvent::Gatt{event}=>if let Ok(reply)=event.accept(){reply.send().await;},
            GattConnectionEvent::PairingComplete{bond,..}|GattConnectionEvent::Encrypted{bond,..}=>{if let Some(bond)=bond {let _=stack.add_bond_information(bond);}set_status("HID paired; select payload and Run");},
            GattConnectionEvent::PairingFailed(_)=>set_status("HID pairing failed; retry from host"),
            _=>{}
        }}
    };
    let payloads=async {
        while current(token) {
            let next=critical_section::with(|cs|HID_PAYLOAD.borrow_ref_mut(cs).take());
            if let Some((index,layout))=next {
                if !conn.raw().security_level().map(|level|level.encrypted()).unwrap_or(false) {set_status("Pair from host before Run");continue;}
                if !reports.keyboard.should_notify(&conn) {set_status("Host has not subscribed to HID reports");continue;}
                let Some((name,source))=BUILTIN_SCRIPTS.get(usize::from(index)) else {set_status("Unknown HID payload");continue;};
                let script=cyberdeck_core::hid::ducky::parse(name,source).map_err(|_|"HID payload parse failed")?;
                let mut engine=HidEngine::new(&script,layout);let mut paused_before=false;
                while !engine.is_finished() {
                    if !current(token){engine.stop();}
                    let paused=HID_PAUSED.load(Ordering::Acquire);
                    if paused && !paused_before {with_timeout(Duration::from_millis(500),hid_output(&reports,&conn,Output::ReleaseAll)).await.map_err(|_|"HID pause release timed out")??;}
                    paused_before=paused;engine.set_paused(paused);
                    if let Some(output)=engine.next_report(Instant::now().as_millis()) {
                        let subscribed=match output {Output::Consumer(_)=>reports.consumer.should_notify(&conn),Output::Mouse(_)=>reports.mouse.should_notify(&conn),_=>reports.keyboard.should_notify(&conn)};
                        if !subscribed {return Err("Host has not subscribed to this HID report");}
                        with_timeout(Duration::from_millis(500),hid_output(&reports,&conn,output)).await.map_err(|_|"HID report timed out")??;
                    }
                    let progress=engine.progress();
                    critical_section::with(|cs|*HID_PROGRESS.borrow_ref_mut(cs)=(progress.percent,engine.keystrokes(),engine.unsupported_chars()));
                    set_status(&alloc::format!("{} {}% / {} keys",if paused{"paused"}else{name},progress.percent,engine.keystrokes()));
                    Timer::after(Duration::from_millis(10)).await;
                }
                with_timeout(Duration::from_millis(500),hid_output(&reports,&conn,Output::ReleaseAll)).await.map_err(|_|"HID release timed out")??;
                set_status(if current(token){"HID payload sent; select Run to repeat"}else{"HID stopped; reports released"});
            }
            Timer::after(Duration::from_millis(10)).await;
        }
        with_timeout(Duration::from_millis(500),hid_output(&reports,&conn,Output::ReleaseAll)).await.map_err(|_|"HID release timed out")??;
        Ok(())
    };
    let result=match select(events,payloads).await {Either::First(result)|Either::Second(result)=>result};
    HID_CONNECTED.store(false,Ordering::Release);critical_section::with(|cs|HID_PAYLOAD.borrow_ref_mut(cs).take());
    conn.raw().disconnect();result
}
//! Bounded microSD actor. Accepted writes are queued; only completion confirms durability.
use alloc::{collections::VecDeque,rc::Rc,string::String,vec::Vec};
use core::cell::RefCell;
use critical_section::Mutex;
use embedded_hal::spi::{ErrorType,Operation,SpiBus,SpiDevice};
use embedded_sdmmc::{Mode,SdCard,TimeSource,Timestamp,VolumeIdx,VolumeManager};
use esp_hal::{Blocking,delay::Delay,gpio::Output,spi::{Error as SpiError,master::Spi}};
use cyberdeck_core::hid::engine::{MAX_EXTERNAL_PAYLOAD_BYTES,MAX_EXTERNAL_PAYLOADS};
use cyberdeck_core::packet::storage::{file_name,valid_file_name,pcap_snaplen,pcap_record_size};

const QUEUE_DEPTH:usize=8;
const QUEUE_BYTES:usize=24*1024;
const MAX_JOB_BYTES:usize=8192;
const MAX_FILES:usize=32;
pub struct SdBus<'d>{spi:Rc<RefCell<Spi<'d,Blocking>>>,cs:Output<'d>}
impl<'d>SdBus<'d>{
    pub fn new(spi:Spi<'d,Blocking>,cs:Output<'d>)->Self{Self::from_shared(Rc::new(RefCell::new(spi)),cs)}
    pub fn from_shared(spi:Rc<RefCell<Spi<'d,Blocking>>>,cs:Output<'d>)->Self{Self{spi,cs}}
}
impl ErrorType for SdBus<'_>{type Error=SpiError;}
/// Full-duplex transfer for [`Operation::Transfer`].
///
/// esp-hal only offers an in-place transfer, so the outgoing bytes are staged in a
/// small bounded buffer: send a chunk, capture what the card returned, repeat. Any
/// trailing read-only bytes are clocked separately, which is what an SD data-in
/// phase expects.
fn full_duplex(spi:&mut Spi<'_,Blocking>,read:&mut[u8],write:&[u8])->Result<(),SpiError>{
    const CHUNK:usize=32;
    let mut staged=[0u8;CHUNK];
    let shared=read.len().min(write.len());
    let mut index=0;
    while index<shared {
        let len=(shared-index).min(CHUNK);
        staged[..len].copy_from_slice(&write[index..index+len]);
        spi.transfer(&mut staged[..len])?;
        read[index..index+len].copy_from_slice(&staged[..len]);
        index+=len;
    }
    if read.len()>shared {spi.read(&mut read[shared..])?;}
    Ok(())
}
impl SpiDevice<u8> for SdBus<'_>{
    fn transaction(&mut self,operations:&mut[Operation<'_,u8>])->Result<(),SpiError>{
        let mut spi=self.spi.borrow_mut();self.cs.set_low();
        let result=operations.iter_mut().try_for_each(|op|match op{
            Operation::Read(data)=>spi.read(data),Operation::Write(data)=>spi.write(data),
            Operation::Transfer(read,write)=>full_duplex(&mut spi,read,write),
            Operation::TransferInPlace(data)=>spi.transfer_in_place(data),
            Operation::DelayNs(ns)=>{Delay::new().delay_nanos(*ns);Ok(())}
        });
        let flushed=spi.flush();self.cs.set_high();result.and(flushed)
    }
}
struct FixedClock;
impl TimeSource for FixedClock{fn get_timestamp(&self)->Timestamp{Timestamp{year_since_1970:56,zero_indexed_month:10,zero_indexed_day:15,hours:0,minutes:0,seconds:0}}}
#[derive(Clone)]
pub struct FileRow{pub name:String,pub bytes:u32}
#[derive(Clone)]
pub struct WriteResult{pub ticket:u32,pub name:String,pub bytes:u64,pub success:bool,pub error:String}
struct StorageState{mounted:bool,status:String,files:u32,bytes:u64,library:Vec<FileRow>,preview:String,completed:VecDeque<WriteResult>,failed:Vec<String>}
impl StorageState{const fn new()->Self{Self{mounted:false,status:String::new(),files:0,bytes:0,library:Vec::new(),preview:String::new(),completed:VecDeque::new(),failed:Vec::new()}}}
pub struct Job{pub ticket:u32,pub name:String,pub append:bool,pub bytes:Vec<u8>}
enum Request{Write(Job),List,Preview(String),Recover(String),Payloads}
static STATE:Mutex<RefCell<StorageState>>=Mutex::new(RefCell::new(StorageState::new()));
static JOBS:Mutex<RefCell<VecDeque<Request>>>=Mutex::new(RefCell::new(VecDeque::new()));
/// Scanned HID payload scripts, handed to `platform::payload` exactly once.
static SCANNED:Mutex<RefCell<Option<Vec<(String,String)>>>>=Mutex::new(RefCell::new(None));
static NEXT:Mutex<RefCell<u32>>=Mutex::new(RefCell::new(0));
static TICKET:Mutex<RefCell<u32>>=Mutex::new(RefCell::new(0));
fn publish(status:&str,mounted:bool){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.mounted=mounted;s.status=String::from(status);});}
pub fn ready()->bool{critical_section::with(|cs|STATE.borrow_ref(cs).mounted)}
pub fn status_line()->String{critical_section::with(|cs|{let s=STATE.borrow_ref(cs);alloc::format!("SD: {} ({} files, {} B)",if s.status.is_empty(){"not mounted"}else{&s.status},s.files,s.bytes)})}
pub fn completion(ticket:u32)->Option<WriteResult>{critical_section::with(|cs|STATE.borrow_ref(cs).completed.iter().find(|r|r.ticket==ticket).cloned())}
pub fn library_snapshot()->(String,Vec<FileRow>){critical_section::with(|cs|{let s=STATE.borrow_ref(cs);(s.status.clone(),s.library.clone())})}
pub fn preview()->String{critical_section::with(|cs|STATE.borrow_ref(cs).preview.clone())}
pub fn enqueue(name:&str,bytes:Vec<u8>,append:bool)->bool{enqueue_tracked(name,bytes,append).is_some()}
pub fn enqueue_tracked(name:&str,bytes:Vec<u8>,append:bool)->Option<u32>{enqueue_owned(name,bytes,append).ok()}
/// Rejected owned data is returned intact so a capture can drain its valid prefix.
pub fn enqueue_owned(name:&str,bytes:Vec<u8>,append:bool)->Result<u32,Vec<u8>>{
    if bytes.is_empty()||bytes.len()>MAX_JOB_BYTES||!valid_file_name(name){return Err(bytes)}
    critical_section::with(|cs|{
        if !STATE.borrow_ref(cs).mounted{return Err(bytes)}
        let mut jobs=JOBS.borrow_ref_mut(cs);
        let queued:usize=jobs.iter().map(|r|if let Request::Write(j)=r{j.bytes.len()}else{0}).sum();
        if jobs.len()>=QUEUE_DEPTH||queued+bytes.len()>QUEUE_BYTES{return Err(bytes)}
        let mut next=TICKET.borrow_ref_mut(cs);*next=next.wrapping_add(1);let ticket=*next;
        jobs.push_back(Request::Write(Job{ticket,name:String::from(name),append,bytes}));
        STATE.borrow_ref_mut(cs).status=alloc::format!("queued {name}");Ok(ticket)
    })
}
fn request(request:Request)->bool{critical_section::with(|cs|{
    if !STATE.borrow_ref(cs).mounted{return false}
    let mut q=JOBS.borrow_ref_mut(cs);if q.len()>=QUEUE_DEPTH{return false}q.push_back(request);true
})}
pub fn request_list()->bool{request(Request::List)}
pub fn request_preview(name:&str)->bool{valid_file_name(name)&&request(Request::Preview(String::from(name)))}
pub fn request_recover(name:&str)->bool{valid_file_name(name)&&request(Request::Recover(String::from(name)))}
/// Queue a scan for `*.TXT` HID payload scripts in the card root.
pub fn request_payload_scan()->bool{request(Request::Payloads)}
/// Take the most recent scan result, if the storage actor produced one.
pub fn take_payloads()->Option<Vec<(String,String)>>{critical_section::with(|cs|SCANNED.borrow_ref_mut(cs).take())}
pub fn next_name(stem:&str,extension:&str)->String{
    let index=critical_section::with(|cs|{let mut n=NEXT.borrow_ref_mut(cs);*n=n.saturating_add(1);*n});
    file_name(stem,extension,index).unwrap_or_default()
}
type Manager<D>=VolumeManager<D,FixedClock,4,4,1>;
fn list_files<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume)->Result<Vec<FileRow>,&'static str>{
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    let mut files=Vec::new();let mut highest=0u32;
    let result=m.iterate_dir(root,|e|{
        if e.attributes.is_directory(){return}
        let name=alloc::format!("{}",e.name);
        let base=e.name.base_name();let digits=base.iter().rev().take_while(|b|b.is_ascii_digit()).count();
        if digits>0{let value=base[base.len()-digits..].iter().fold(0u32,|n,b|n.saturating_mul(10).saturating_add(u32::from(*b-b'0')));highest=highest.max(value);}
        if files.len()<MAX_FILES{files.push(FileRow{name,bytes:e.size});}
    }).map_err(|_|"directory read failed");
    let closed=m.close_dir(root).map_err(|_|"directory close failed");
    result.and(closed)?;
    critical_section::with(|cs|{let mut n=NEXT.borrow_ref_mut(cs);*n=(*n).max(highest);});
    files.sort_by(|a,b|a.name.cmp(&b.name));Ok(files)
}
async fn write_job<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume,j:&Job)->Result<u64,&'static str>{
    let blocked=critical_section::with(|cs|STATE.borrow_ref(cs).failed.contains(&j.name));
    if blocked{return Err("earlier write failed; recover capture")}
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    // New exports must not overwrite an existing capture.
    let mode=if j.append{Mode::ReadWriteCreateOrAppend}else{Mode::ReadWriteCreate};
    let file=match m.open_file_in_dir(root,j.name.as_str(),mode){Ok(f)=>f,Err(_)=>{let _=m.close_dir(root);return Err("file open failed")}};
    let mut result=Ok(j.bytes.len()as u64);
    for chunk in j.bytes.chunks(512){
        if m.write(file,chunk).is_err(){result=Err("data write failed");break}
        embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;
    }
    let closed=m.close_file(file).map_err(|_|"file close failed");
    let dir_closed=m.close_dir(root).map_err(|_|"directory close failed");
    result=result.and(closed.map(|_|j.bytes.len()as u64)).and(dir_closed.map(|_|j.bytes.len()as u64));
    result
}
fn read_exact<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,f:embedded_sdmmc::RawFile,data:&mut[u8])->Result<bool,&'static str>{
    let mut at=0;while at<data.len(){let n=m.read(f,&mut data[at..]).map_err(|_|"file read failed")?;if n==0{return Ok(false)}at+=n;}Ok(true)
}
fn file_preview<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume,name:&str)->Result<String,&'static str>{
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    let file=match m.open_file_in_dir(root,name,Mode::ReadOnly){Ok(f)=>f,Err(_)=>{let _=m.close_dir(root);return Err("file open failed")}};
    let mut bytes=[0u8;512];let read=m.read(file,&mut bytes).map_err(|_|"file read failed");
    let closed=m.close_file(file).map_err(|_|"file close failed");let dir=m.close_dir(root).map_err(|_|"directory close failed");
    let n=read?;closed?;dir?;
    if let Some(snap)=pcap_snaplen(&bytes[..n]){
        Ok(alloc::format!("{name}\nPCAP radiotap | snapshot {snap} B\n{}",cyberdeck_core::packet::hexdump(&bytes[..n],6)))
    }else{Ok(alloc::format!("{name}\n{}",bytes[..n].iter().map(|b|if b.is_ascii_graphic()||matches!(*b,b' '|b'\n'|b'\r'|b'\t'){char::from(*b)}else{'.'}).collect::<String>()))}
}
async fn recover<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume,name:&str)->Result<String,&'static str>{
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    let source=match m.open_file_in_dir(root,name,Mode::ReadOnly){Ok(f)=>f,Err(_)=>{let _=m.close_dir(root);return Err("source open failed")}};
    let output=next_name("REC","CAP");
    let destination=match m.open_file_in_dir(root,output.as_str(),Mode::ReadWriteCreate){Ok(f)=>f,Err(_)=>{let _=m.close_file(source);let _=m.close_dir(root);return Err("recovery file open failed")}};
    let mut records=0u32;let mut bytes=24u64;
    let result=async{
        let mut header=[0u8;24];if !read_exact(m,source,&mut header)?{return Err("short PCAP header")}
        let snap=pcap_snaplen(&header).ok_or("unsupported PCAP header")?;
        if snap>2048{return Err("snapshot exceeds recovery buffer")}
        m.write(destination,&header).map_err(|_|"recovery write failed")?;
        loop{
            let mut h=[0u8;16];if !read_exact(m,source,&mut h)?{break}
            let Some(size)=pcap_record_size(&h,snap)else{break};
            let mut payload=[0u8;2048];let n=size-16;
            if !read_exact(m,source,&mut payload[..n])?{break}
            m.write(destination,&h).map_err(|_|"recovery write failed")?;
            for part in payload[..n].chunks(512){m.write(destination,part).map_err(|_|"recovery write failed")?;embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;}
            records=records.saturating_add(1);bytes+=size as u64;
        }
        Ok(())
    }.await;
    let closed_source=m.close_file(source).map_err(|_|"source close failed");
    let closed=m.close_file(destination).map_err(|_|"recovery close failed");
    let dir=m.close_dir(root).map_err(|_|"directory close failed");
    result?;closed_source?;closed?;dir?;
    Ok(alloc::format!("Recovered {output}: {records} records, {bytes} B; original kept"))
}
/// Payload scripts are plain text in the card root; captures use their own extensions.
fn is_payload_file(name:&str)->bool{
    name.get(name.len().saturating_sub(4)..).is_some_and(|extension|extension.eq_ignore_ascii_case(".TXT"))
}
/// Read one script, bounded by [`MAX_EXTERNAL_PAYLOAD_BYTES`]; invalid UTF-8 becomes
/// replacement characters so the engine reports them as unsupported instead of failing.
fn read_payload<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume,name:&str)->Result<String,&'static str>{
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    let file=match m.open_file_in_dir(root,name,Mode::ReadOnly){Ok(f)=>f,Err(_)=>{let _=m.close_dir(root);return Err("payload open failed")}};
    let mut bytes=Vec::new();let mut buffer=[0u8;256];
    let mut result=Ok(());
    loop{
        if bytes.len()>=MAX_EXTERNAL_PAYLOAD_BYTES{break}
        match m.read(file,&mut buffer){
            Ok(0)=>break,
            Ok(n)=>{let room=MAX_EXTERNAL_PAYLOAD_BYTES-bytes.len();bytes.extend_from_slice(&buffer[..n.min(room)]);}
            Err(_)=>{result=Err("payload read failed");break}
        }
    }
    let closed=m.close_file(file).map_err(|_|"payload close failed");
    let directory=m.close_dir(root).map_err(|_|"directory close failed");
    result?;closed?;directory?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
fn scan_payloads<D:embedded_sdmmc::BlockDevice>(m:&Manager<D>,v:embedded_sdmmc::RawVolume)->Result<Vec<(String,String)>,&'static str>{
    let root=m.open_root_dir(v).map_err(|_|"directory open failed")?;
    let mut names:Vec<String>=Vec::new();
    let scanned=m.iterate_dir(root,|entry|{
        if entry.attributes.is_directory(){return}
        let name=alloc::format!("{}",entry.name);
        if !is_payload_file(&name){return}
        // Bounded: a card cannot make the firmware allocate an unbounded list.
        if names.len()<MAX_EXTERNAL_PAYLOADS{names.push(name);}
    }).map_err(|_|"directory read failed");
    let closed=m.close_dir(root).map_err(|_|"directory close failed");
    scanned.and(closed)?;
    names.sort();
    let mut scripts=Vec::new();
    for name in names{
        if let Ok(text)=read_payload(m,v,&name){if !text.is_empty(){scripts.push((name,text));}}
    }
    Ok(scripts)
}
pub async fn run(bus:SdBus<'static>)->!{
    let card=SdCard::new(bus,Delay::new());let manager=VolumeManager::new(card,FixedClock);
    let volume=match manager.open_volume(VolumeIdx(0)){
        Ok(v)=>{let raw=v.to_raw_volume();match list_files(&manager,raw){Ok(files)=>{critical_section::with(|cs|STATE.borrow_ref_mut(cs).library=files);publish("mounted",true)},Err(e)=>publish(e,false)}Some(raw)}
        Err(_)=>{publish("no FAT volume",false);None}
    };
    loop{
        let request=critical_section::with(|cs|JOBS.borrow_ref_mut(cs).pop_front());
        if let Some(request)=request{
            if let Some(v)=volume{match request{
                Request::Write(job)=>{
                    let result=write_job(&manager,v,&job).await;
                    critical_section::with(|cs|{
                        let mut s=STATE.borrow_ref_mut(cs);let success=result.is_ok();let bytes=result.as_ref().copied().unwrap_or(0);
                        let error=result.err().unwrap_or("");
                        if success{s.files=s.files.saturating_add(u32::from(!job.append));s.bytes=s.bytes.saturating_add(bytes);s.status=alloc::format!("saved {} ({} B)",job.name,bytes);}
                        else{s.status=alloc::format!("{}: {error}",job.name);if s.failed.len()<8&&!s.failed.contains(&job.name){s.failed.push(job.name.clone());}}
                        if s.completed.len()>=24{s.completed.pop_front();}
                        s.completed.push_back(WriteResult{ticket:job.ticket,name:job.name,bytes,success,error:String::from(error)});
                    });
                }
                Request::List=>match list_files(&manager,v){Ok(files)=>{let count=files.len();critical_section::with(|cs|STATE.borrow_ref_mut(cs).library=files);publish(&alloc::format!("{count} files (max {MAX_FILES})"),true)},Err(e)=>publish(e,false)},
                Request::Preview(name)=>match file_preview(&manager,v,&name){Ok(text)=>{critical_section::with(|cs|STATE.borrow_ref_mut(cs).preview=text);publish("preview loaded",true)},Err(e)=>publish(e,false)},
                Request::Recover(name)=>match recover(&manager,v,&name).await{Ok(text)=>publish(&text,true),Err(e)=>publish(e,false)},
                Request::Payloads=>match scan_payloads(&manager,v){
                    Ok(scripts)=>{let count=scripts.len();critical_section::with(|cs|*SCANNED.borrow_ref_mut(cs)=Some(scripts));publish(&alloc::format!("{count} payload scripts on card"),true)},
                    Err(e)=>publish(e,false),
                },
            }}
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(5)).await;
    }
}

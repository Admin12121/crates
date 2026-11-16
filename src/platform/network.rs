//! Ordinary, bounded local-network diagnostics on the station interface.
//!
//! Named SDK limitations (not silent omissions): smoltcp exposes no ARP
//! request/table API, so ARP probing is impossible on this stack; embassy-net
//! offers no DHCP-client control (release/renew/rogue-server detection), so
//! DHCP-resilience assessment cannot be implemented here. Both stay listed as
//! stack limitations in the feature tracker.
use alloc::{format,string::String,vec::Vec};
use core::cell::RefCell;
use critical_section::Mutex;
use cyberdeck_core::{hid::session::SessionQueue,network::{ProbePlan,SERVICE_PORTS,service_name}};
use embassy_net::{Stack,IpAddress,Ipv4Address,tcp::{TcpSocket,ConnectError}};
use embassy_time::{Duration,Instant,Timer,with_timeout};
#[derive(Clone,Copy)]pub enum NetCommand{Info,Discover{start:u8},Probe{host:u8},Services{host:u8},Stop}
struct State{status:String,lines:Vec<String>,busy:bool,ready:bool}
static STATE:Mutex<RefCell<State>>=Mutex::new(RefCell::new(State{status:String::new(),lines:Vec::new(),busy:false,ready:false}));
static COMMAND:Mutex<RefCell<SessionQueue<NetCommand>>>=Mutex::new(RefCell::new(SessionQueue::new()));
pub fn submit(command:NetCommand)->bool{critical_section::with(|cs|{let mut q=COMMAND.borrow_ref_mut(cs);if matches!(command,NetCommand::Stop){q.stop();true}else{q.submit(command)}})}
fn current(token:u32)->bool{critical_section::with(|cs|COMMAND.borrow_ref(cs).is_current(token))}
fn append(line:String){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);if s.lines.len()>=32{s.lines.remove(0);}s.lines.push(line);});}
fn status(text:&str){critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.status.clear();s.status.push_str(text);});}
pub fn ready()->bool{critical_section::with(|cs|STATE.borrow_ref(cs).ready)}
pub fn snapshot()->(String,Vec<String>,bool){critical_section::with(|cs|{let s=STATE.borrow_ref(cs);(s.status.clone(),s.lines.clone(),s.busy)})}
async fn configured(stack:Stack<'static>,token:u32)->bool{
 let start=Instant::now();
 while !stack.is_config_up(){if !current(token){return false;}else if start.elapsed()>Duration::from_secs(30){status("No address. Join a Wi-Fi network first");return false;}Timer::after(Duration::from_millis(50)).await;}true
}
fn target(stack:Stack<'static>,host:u8)->Option<Ipv4Address>{
 let cfg=stack.config_v4()?;let local=cfg.address.address().octets();let mut ip=local;
 if host==0||host==255{return None;}ip[3]=host;
 let mask=if cfg.address.prefix_len()==0{0}else{u32::MAX<<(32-cfg.address.prefix_len())};
 let number=u32::from_be_bytes(ip);let network=u32::from_be_bytes(local)&mask;let broadcast=network|!mask;
 if number==network||number==broadcast||number&mask!=network||ip==local{return None;}Some(Ipv4Address::from(ip))
}
enum Probe{Open,Closed,TimedOut,Cancelled,NoRoute}
/// One bounded ICMP echo. Returns round-trip milliseconds when the target
/// answered; `None` on silence, refusal or cancellation.
async fn icmp_ping(stack:Stack<'static>,address:Ipv4Address,token:u32)->Option<u32>{
 use embassy_net::icmp::{IcmpEndpoint,IcmpSocket,PacketMetadata};
 let mut rx_meta=[PacketMetadata::EMPTY;4];let mut tx_meta=[PacketMetadata::EMPTY;4];
 let mut rx=[0u8;256];let mut tx=[0u8;64];
 let mut socket=IcmpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
 let ident=0x5244u16;
 if socket.bind(IcmpEndpoint::Ident(ident)).is_err(){return None;}
 // Echo request header: type 8, code 0, checksum left to the driver.
 let mut echo=[0u8;16];echo[0]=8;echo[1]=0;
 echo[2..4].copy_from_slice(&ident.to_be_bytes());echo[4..6].copy_from_slice(&1u16.to_be_bytes());
 echo[6..].copy_from_slice(b"CYBERDECK");
 let sent_at=Instant::now();
 if socket.send_to(&echo,IpAddress::Ipv4(address)).await.is_err(){return None;}
 let mut reply=[0u8;128];
 loop{
  if !current(token){return None;}
  let receive=async{socket.recv_from(&mut reply).await};
  match embassy_futures::select::select(receive,Timer::after(Duration::from_millis(400))).await{
   embassy_futures::select::Either::First(Ok((len,source)))=>{
    if source==IpAddress::Ipv4(address)&&len>=6&&reply[0]==0&&u16::from_be_bytes([reply[2],reply[3]])==ident{
     return Some(sent_at.elapsed().as_millis() as u32);
    }
   },
   _=>return None,
  }
 }
}
async fn connect(socket:&mut TcpSocket<'_>,address:Ipv4Address,port:u16,token:u32)->Probe{
 let started=Instant::now();
 let mut connecting=core::pin::pin!(socket.connect((IpAddress::Ipv4(address),port)));
 loop{
  match embassy_futures::select::select(connecting.as_mut(),Timer::after(Duration::from_millis(50))).await{
   embassy_futures::select::Either::First(Ok(()))=>return Probe::Open,
   embassy_futures::select::Either::First(Err(ConnectError::ConnectionReset))=>return Probe::Closed,
   embassy_futures::select::Either::First(Err(ConnectError::NoRoute))=>return Probe::NoRoute,
   embassy_futures::select::Either::First(Err(_))=>return Probe::TimedOut,
   embassy_futures::select::Either::Second(_)=>{}
  }
  if !current(token){return Probe::Cancelled;}else if started.elapsed()>=Duration::from_millis(650){return Probe::TimedOut;}
 }
}
async fn inspect_host(stack:Stack<'static>,address:Ipv4Address,banners:bool,token:u32){
 for port in SERVICE_PORTS{
  if !current(token){return;}
  let mut rx=[0;512];let mut tx=[0;512];let mut socket=TcpSocket::new(stack,&mut rx,&mut tx);socket.set_timeout(Some(Duration::from_secs(1)));
  match connect(&mut socket,address,port,token).await{
   Probe::Open=>{
    append(format!("{address}:{port} {} open",service_name(port)));
    if banners&&matches!(port,22|80|8000|8080){
     if matches!(port,80|8000|8080){let request=format!("HEAD / HTTP/1.0\r\nHost: {address}\r\n\r\n");let _=with_timeout(Duration::from_millis(500),socket.write(request.as_bytes())).await;}
     let mut data=[0;128];if let Ok(Ok(len))=with_timeout(Duration::from_millis(600),socket.read(&mut data)).await{
      let text:String=data[..len].iter().map(|b|if b.is_ascii_graphic()||*b==b' '{*b as char}else{' '}).collect();
      if !text.is_empty(){append(text);}
     }
    }
   },
   Probe::Closed=>append(format!("{address}:{port} closed")),
   Probe::NoRoute=>{append(String::from("No path to that device"));return;},
   Probe::TimedOut=>append(format!("{address}:{port} no response")),
   Probe::Cancelled=>return,
  }socket.abort();Timer::after(Duration::from_millis(20)).await;
 }
}
async fn dns_probe(stack:Stack<'static>,address:Ipv4Address,token:u32){
 use embassy_net::udp::{UdpSocket,PacketMetadata};
 let mut rx_meta=[PacketMetadata::EMPTY;1];let mut tx_meta=[PacketMetadata::EMPTY;1];
 let mut rx=[0;512];let mut tx=[0;128];let mut socket=UdpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
 if socket.bind(0).is_err(){append(String::from("Network busy"));return;}
 let id=(Instant::now().as_micros() as u16).wrapping_add(0x1212);
 let request=cyberdeck_core::network::dns_query(id);
 if !matches!(with_timeout(Duration::from_millis(500),socket.send_to(&request,(IpAddress::Ipv4(address),53))).await,Ok(Ok(()))){append(String::from("DNS check failed"));return;}
 let start=Instant::now();let mut response=[0;512];
 while current(token)&&start.elapsed()<Duration::from_millis(1500){
  if let Ok(Ok((len,meta)))=with_timeout(Duration::from_millis(100),socket.recv_from(&mut response)).await
   && meta.endpoint.addr==IpAddress::Ipv4(address)&&meta.endpoint.port==53&& let Some(rcode)=cyberdeck_core::network::dns_response(&response[..len],id){append(format!("DNS replied (code {rcode})"));return;}
 }
 append(format!("{address}:53 no DNS reply"));
}
/// LLMNR name-resolution probe: one multicast query on port 5355. Any reply
/// reveals a host that answers link-local names (typically Windows machines).
async fn llmnr_probe(stack:Stack<'static>,token:u32){
 use embassy_net::udp::{UdpSocket,PacketMetadata};
 let mut rx_meta=[PacketMetadata::EMPTY;2];let mut tx_meta=[PacketMetadata::EMPTY;2];
 let mut rx=[0;512];let mut tx=[0;256];
 let mut socket=UdpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
 if socket.bind(5355).is_err(){append(String::from("LLMNR check skipped: port busy"));return;}
 let id=(Instant::now().as_micros() as u16)|0x114E;
 let query=cyberdeck_core::network::llmnr_query(id);
 let target=(IpAddress::Ipv4(Ipv4Address::new(224,0,0,252)),5355);
 if !matches!(with_timeout(Duration::from_millis(500),socket.send_to(&query,target)).await,Ok(Ok(()))){append(String::from("LLMNR probe not sent"));return;}
 let start=Instant::now();let mut reply=[0;512];let mut answers=0u32;
 while current(token)&&start.elapsed()<Duration::from_millis(900){
  if let Ok(Ok((len,meta)))=with_timeout(Duration::from_millis(100),socket.recv_from(&mut reply)).await
   && len>=12&&reply[..2]==id.to_be_bytes(){answers+=1;append(format!("LLMNR responder at {}",meta.endpoint.addr));}
 }
 if answers==0{append(String::from("No LLMNR responder (normal on many networks)"));}
}
fn save_report(){
 let(status,lines,_)=snapshot();if lines.is_empty(){return;}
 let name=super::sd::next_name("NET","TXT");let mut report=format!("Admin12121 network report\n{status}\n");
 for line in lines{report.push_str(&line);report.push('\n');}
 if super::sd::enqueue_tracked(&name,report.into_bytes(),false).is_some(){append(format!("Report saved: {name}"));}else{append(String::from("Report not saved (no card)"));}
}
pub async fn run(stack:Stack<'static>)->!{
 loop{
  critical_section::with(|cs|STATE.borrow_ref_mut(cs).ready=stack.is_config_up()&&stack.is_link_up());
  let item=critical_section::with(|cs|COMMAND.borrow_ref_mut(cs).take());
  if let Some((token,command))=item{
   critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.lines.clear();s.busy=true;});
   status("Waiting for an address");
   if configured(stack,token).await{
     if let Some(cfg)=stack.config_v4(){
      append(format!("Address {}/{}",cfg.address.address(),cfg.address.prefix_len()));
      if let Some(gateway)=cfg.gateway{append(format!("Router {gateway}"));}
      for dns in &cfg.dns_servers{append(format!("DNS {dns}"));}
      match command{
       NetCommand::Info=>{},
       NetCommand::Discover{start}=>{
        status("Checking up to 16 nearby addresses");
        if let Some(plan)=ProbePlan::new(cfg.address.address().octets(),cfg.address.prefix_len(),start,16){
         for ip in plan.addresses(){
          if !current(token){break;}let address=Ipv4Address::from(*ip);
          let mut answered=false;
          if let Some(millis)=icmp_ping(stack,address,token).await{append(format!("{address} answered (ping {} ms)",millis));answered=true;}
          // Devices that mute ICMP still answer a web-port connect.
          if !answered{
           let mut rx=[0;128];let mut tx=[0;128];let mut socket=TcpSocket::new(stack,&mut rx,&mut tx);
           let result=connect(&mut socket,address,80,token).await;socket.abort();
           if matches!(result,Probe::Open|Probe::Closed){append(format!("{address} answered"));}
          }
          Timer::after(Duration::from_millis(30)).await;
         }
        }
        append(String::from("Quiet devices may be off or blocking"));
       },
       NetCommand::Probe{host}|NetCommand::Services{host}=>{if let Some(ip)=target(stack,host){status("Checking the chosen device");inspect_host(stack,ip,matches!(command,NetCommand::Services{..}),token).await;if matches!(command,NetCommand::Services{..})&&current(token){dns_probe(stack,ip,token).await;llmnr_probe(stack,token).await;}}else{append(String::from("Pick a device on this network (1-254)"));}},
      NetCommand::Stop=>{},
     }
    }
    status(if current(token){"Done"}else{"Cancelled"});
   }
   critical_section::with(|cs|STATE.borrow_ref_mut(cs).busy=false);save_report();
  }
  Timer::after(Duration::from_millis(50)).await;
 }
}

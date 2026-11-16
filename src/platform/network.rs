//! Ordinary, bounded local-network diagnostics on the station interface.
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
 while !stack.is_config_up(){if !current(token){return false;}if start.elapsed()>Duration::from_secs(30){status("No address: connect Wi-Fi first");return false;}Timer::after(Duration::from_millis(50)).await;}true
}
fn target(stack:Stack<'static>,host:u8)->Option<Ipv4Address>{
 let cfg=stack.config_v4()?;let local=cfg.address.address().octets();let mut ip=local;
 if host==0||host==255{return None;}ip[3]=host;
 let mask=if cfg.address.prefix_len()==0{0}else{u32::MAX<<(32-cfg.address.prefix_len())};
 let number=u32::from_be_bytes(ip);let network=u32::from_be_bytes(local)&mask;let broadcast=network|!mask;
 if number==network||number==broadcast||number&mask!=network||ip==local{return None;}Some(Ipv4Address::from(ip))
}
enum Probe{Open,Closed,TimedOut,Cancelled,NoRoute}
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
  if !current(token){return Probe::Cancelled;}if started.elapsed()>=Duration::from_millis(650){return Probe::TimedOut;}
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
   Probe::NoRoute=>{append(String::from("No route to the selected host"));return;},
   Probe::TimedOut=>append(format!("{address}:{port} no response")),
   Probe::Cancelled=>return,
  }socket.abort();Timer::after(Duration::from_millis(20)).await;
 }
}
async fn dns_probe(stack:Stack<'static>,address:Ipv4Address,token:u32){
 use embassy_net::udp::{UdpSocket,PacketMetadata};
 let mut rx_meta=[PacketMetadata::EMPTY;1];let mut tx_meta=[PacketMetadata::EMPTY;1];
 let mut rx=[0;512];let mut tx=[0;128];let mut socket=UdpSocket::new(stack,&mut rx_meta,&mut rx,&mut tx_meta,&mut tx);
 if socket.bind(0).is_err(){append(String::from("UDP socket unavailable"));return;}
 let id=(Instant::now().as_micros() as u16).wrapping_add(0x1212);
 let request=cyberdeck_core::network::dns_query(id);
 if !matches!(with_timeout(Duration::from_millis(500),socket.send_to(&request,(IpAddress::Ipv4(address),53))).await,Ok(Ok(()))){append(String::from("UDP DNS send failed"));return;}
 let start=Instant::now();let mut response=[0;512];
 while current(token)&&start.elapsed()<Duration::from_millis(1500){
  if let Ok(Ok((len,meta)))=with_timeout(Duration::from_millis(100),socket.recv_from(&mut response)).await{
   if meta.endpoint.addr==IpAddress::Ipv4(address)&&meta.endpoint.port==53{if let Some(rcode)=cyberdeck_core::network::dns_response(&response[..len],id){append(format!("{address}:53 UDP DNS reply rcode {rcode}"));return;}}
  }
 }
 append(format!("{address}:53 UDP no matching reply"));
}
fn save_report(){
 let(status,lines,_)=snapshot();if lines.is_empty(){return;}
 let name=super::sd::next_name("NET","TXT");let mut report=format!("Admin12121 network report\n{status}\n");
 for line in lines{report.push_str(&line);report.push('\n');}
 if super::sd::enqueue_tracked(&name,report.into_bytes(),false).is_some(){append(format!("Report queued: {name}"));}else{append(String::from("Report not saved: SD absent/busy"));}
}
pub async fn run(stack:Stack<'static>)->!{
 loop{
  critical_section::with(|cs|STATE.borrow_ref_mut(cs).ready=stack.is_config_up()&&stack.is_link_up());
  let item=critical_section::with(|cs|COMMAND.borrow_ref_mut(cs).take());
  if let Some((token,command))=item{
   critical_section::with(|cs|{let mut s=STATE.borrow_ref_mut(cs);s.lines.clear();s.busy=true;});
   status("Waiting for network address");
   if configured(stack,token).await{
    if let Some(cfg)=stack.config_v4(){
     append(format!("Address {}/{}",cfg.address.address(),cfg.address.prefix_len()));
     if let Some(gateway)=cfg.gateway{append(format!("Gateway {gateway}"));}
     for dns in &cfg.dns_servers{append(format!("DNS {dns}"));}
     match command{
      NetCommand::Info=>{},
      NetCommand::Discover{start}=>{
       status("Discovering up to 16 local hosts");
       if let Some(plan)=ProbePlan::new(cfg.address.address().octets(),cfg.address.prefix_len(),start,16){
        for ip in plan.addresses(){
         if !current(token){break;}let address=Ipv4Address::from(*ip);
         let mut rx=[0;128];let mut tx=[0;128];let mut socket=TcpSocket::new(stack,&mut rx,&mut tx);
         let result=connect(&mut socket,address,80,token).await;socket.abort();
         if matches!(result,Probe::Open|Probe::Closed){append(format!("{address} reachable (TCP response)"));}
         Timer::after(Duration::from_millis(30)).await;
        }
       }
       append(String::from("Silent hosts may be filtered or offline"));
      },
      NetCommand::Probe{host}|NetCommand::Services{host}=>{if let Some(ip)=target(stack,host){status("Checking selected local host");inspect_host(stack,ip,matches!(command,NetCommand::Services{..}),token).await;if matches!(command,NetCommand::Services{..})&&current(token){dns_probe(stack,ip,token).await;}}else{append(String::from("Select another host inside this subnet"));}},
      NetCommand::Stop=>{},
     }
    }
    status(if current(token){"Diagnostics complete"}else{"Diagnostics cancelled"});
   }
   critical_section::with(|cs|STATE.borrow_ref_mut(cs).busy=false);save_report();
  }
  Timer::after(Duration::from_millis(50)).await;
 }
}

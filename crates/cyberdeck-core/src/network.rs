//! Bounded local-network configuration and diagnostic target plans.
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
#[derive(Clone,PartialEq,Eq)]
pub struct Credentials {pub ssid:String,pub password:String}
impl Credentials {
 pub fn new(ssid:&str,password:&str)->Result<Self,&'static str>{
  if ssid.is_empty()||ssid.len()>32||ssid.bytes().any(|b|b==0||b==b'\n'||b==b'\r'){return Err("SSID must be 1-32 bytes");}
  if (!password.is_empty()&&!(8..=63).contains(&password.len()))||password.bytes().any(|b|b==0||b==b'\n'||b==b'\r'){return Err("Password must be empty or 8-63 bytes");}
  Ok(Self{ssid:ssid.to_string(),password:password.to_string()})
 }
}
impl fmt::Debug for Credentials {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.debug_struct("Credentials").field("ssid",&self.ssid).field("password",&"[redacted]").finish()}}
pub fn parse_ipv4(text:&str)->Option<[u8;4]>{
 let mut ip=[0;4];let mut parts=text.split('.');
 for byte in &mut ip {let part=parts.next()?;if part.is_empty()||!part.bytes().all(|b|b.is_ascii_digit()){return None;}*byte=part.parse().ok()?;}
 if parts.next().is_some(){None}else{Some(ip)}
}
/// At most sixteen explicit hosts in the configured local subnet, excluding self,
/// network and broadcast. This is discovery by bounded connection attempts.
pub struct ProbePlan {addresses:Vec<[u8;4]>}
impl ProbePlan{
 pub fn new(local:[u8;4],prefix:u8,start:u8,count:u8)->Option<Self>{
  if prefix>32{return None;}let own=u32::from_be_bytes(local);
  let mask=if prefix==0{0}else{u32::MAX<<(32-prefix)};
  let network=own&mask;let broadcast=network|!mask;
  let mut addresses=Vec::new();
  if prefix>=31{return Some(Self{addresses});}
  for offset in u32::from(start.max(1))..u32::from(start.max(1))+u32::from(count.min(16)){
   let Some(ip)=network.checked_add(offset)else{break;};
   if ip>=broadcast{break;}else if ip!=own{addresses.push(ip.to_be_bytes());}
  }Some(Self{addresses})
 }
 pub fn addresses(&self)->&[[u8;4]]{&self.addresses}
}
pub const SERVICE_PORTS:[u16;8]=[22,53,80,443,445,3389,8000,8080];
pub fn service_name(port:u16)->&'static str{match port{22=>"SSH",53=>"DNS",80=>"HTTP",443=>"HTTPS",445=>"SMB",3389=>"RDP",8000|8080=>"HTTP-alt",_=>"TCP"}}

/// One ordinary A query for a reserved invalid name; no external resolver is used.
pub fn dns_query(id:u16)->Vec<u8>{let mut out=alloc::vec![0u8;12];out[..2].copy_from_slice(&id.to_be_bytes());out[2]=1;out[5]=1;for label in [b"admin12121".as_slice(),b"invalid".as_slice()]{out.push(label.len() as u8);out.extend_from_slice(label);}out.extend_from_slice(&[0,0,1,0,1]);out}
pub fn dns_response(packet:&[u8],id:u16)->Option<u8>{if packet.len()<12||packet[..2]!=id.to_be_bytes()||packet[2]&0x80==0||packet[2]&0x78!=0||packet[4..6]!=[0,1]{return None;}Some(packet[3]&0x0f)}
/// LLMNR probe: single-label A query for the deck's own name, sent to the
/// multicast resolver group (224.0.0.252:5355). Replies reveal hosts that
/// answer link-local name resolution, which plain DNS probes cannot see.
pub fn llmnr_query(id:u16)->Vec<u8>{let mut out=alloc::vec![0u8;12];out[..2].copy_from_slice(&id.to_be_bytes());out[2]=1;out[5]=1;out.push(10);out.extend_from_slice(b"admin12121");out.extend_from_slice(&[0,0,1,0,1]);out}

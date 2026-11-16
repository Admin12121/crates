//! Bounded NMEA receiver and coordinate/track projection for the FIELD UART.
use alloc::string::{String,ToString};
use alloc::vec::Vec;
use alloc::format;
pub const FIX_TTL_MS:u64=5000;
#[derive(Debug,Default,Clone,PartialEq,Eq)]
pub struct Fix {
 pub latitude_e7:i32,pub longitude_e7:i32,pub altitude_dm:i32,
 pub satellites:u8,pub hdop_centi:u16,pub speed_kmh_tenths:u16,
 pub utc_time:String,pub utc_date:String,pub received_ms:u64,
}
impl Fix {
 pub fn latitude(&self)->String{coordinate(self.latitude_e7)}
 pub fn longitude(&self)->String{coordinate(self.longitude_e7)}
 pub fn csv_row(&self,now:u64)->String{format!("{now},{},{},{},{},{},{},{}\n",self.utc_date,self.utc_time,self.latitude(),self.longitude(),self.altitude_dm,self.satellites,self.hdop_centi)}
}
pub fn coordinate(value:i32)->String{let n=i64::from(value).abs();format!("{}{}.{:07}",if value<0{"-"}else{""},n/10_000_000,n%10_000_000)}
/// Coordinates are approximate local distances; suitable for a small-radius device geofence.
pub fn geofence_contains(fix:&Fix,latitude_e7:i32,longitude_e7:i32,radius_m:u32)->bool{
 let dy=(i64::from(fix.latitude_e7)-i64::from(latitude_e7))/90;
 let latitude=(latitude_e7.unsigned_abs()/10_000_000).min(90) as usize;
 const COS:[i64;10]=[1000,985,940,866,766,643,500,342,174,0];
 let band=latitude/10;let fraction=latitude%10;
 let cos=if band>=9{0}else{COS[band]+(COS[band+1]-COS[band])*fraction as i64/10};
 let dx=(i64::from(fix.longitude_e7)-i64::from(longitude_e7))/90*cos/1000;
 dy.saturating_mul(dy).saturating_add(dx.saturating_mul(dx))<=i64::from(radius_m).saturating_mul(i64::from(radius_m))
}
pub struct Nmea{buffer:[u8;128],len:usize,collecting:bool,latest:Option<Fix>,valid:bool,checksum_errors:u32,malformed:u32,sentences:u32}
impl Default for Nmea{fn default()->Self{Self::new()}}
impl Nmea{
 pub const fn new()->Self{Self{buffer:[0;128],len:0,collecting:false,latest:None,valid:false,checksum_errors:0,malformed:0,sentences:0}}
 pub fn fix(&self)->Option<&Fix>{self.latest.as_ref()}
 pub fn fresh_fix(&self,now:u64)->Option<&Fix>{self.latest.as_ref().filter(|f|self.valid&&now.saturating_sub(f.received_ms)<FIX_TTL_MS)}
 pub fn checksum_errors(&self)->u32{self.checksum_errors}
 pub fn malformed(&self)->u32{self.malformed}
 pub fn sentences(&self)->u32{self.sentences}
 /// Accept one UART byte; true only when a supported, valid sentence updates state.
 pub fn push(&mut self,byte:u8,now:u64)->bool{
  if byte==b'$'{self.len=0;self.collecting=true;return false;}
  if !self.collecting{return false;}
  if byte==b'\r'{return false;}
  if byte==b'\n'{self.collecting=false;return self.consume(now);}
  if self.len>=self.buffer.len(){self.collecting=false;self.malformed=self.malformed.saturating_add(1);return false;}
  self.buffer[self.len]=byte;self.len+=1;false
 }
 fn consume(&mut self,now:u64)->bool{
  let data=&self.buffer[..self.len];
  let Some(star)=data.iter().position(|b|*b==b'*')else{self.malformed=self.malformed.saturating_add(1);return false;};
  if star+3!=data.len(){self.malformed=self.malformed.saturating_add(1);return false;}
  let checksum=core::str::from_utf8(&data[star+1..]).ok().and_then(|s|u8::from_str_radix(s,16).ok());
  if checksum!=Some(data[..star].iter().fold(0,|s,b|s^b)){self.checksum_errors=self.checksum_errors.saturating_add(1);return false;}
  let Ok(body)=core::str::from_utf8(&data[..star])else{self.malformed=self.malformed.saturating_add(1);return false;};
  let fields:Vec<&str>=body.split(',').take(24).collect();
  if fields.is_empty(){return false;}
  self.sentences=self.sentences.saturating_add(1);
  let kind=fields[0];let get=|i:usize|fields.get(i).copied().unwrap_or("");
  let rmc=kind.len()==5&&kind.ends_with("RMC");
  let gga=kind.len()==5&&kind.ends_with("GGA");
  if !rmc&&!gga{return false;}
  if (rmc&&get(2)!="A")||(gga&&get(6).parse::<u8>().unwrap_or(0)==0){self.valid=false;return true;}
  let(lat_i,ns_i,lon_i,ew_i)=if rmc{(3,4,5,6)}else{(2,3,4,5)};
  let Some(lat)=parse_coordinate(get(lat_i),get(ns_i),true)else{self.malformed=self.malformed.saturating_add(1);return false;};
  let Some(lon)=parse_coordinate(get(lon_i),get(ew_i),false)else{self.malformed=self.malformed.saturating_add(1);return false;};
  let time=get(1);if !valid_clock(time){self.malformed=self.malformed.saturating_add(1);return false;}
  let mut fix=self.latest.take().unwrap_or_default();
  fix.latitude_e7=lat;fix.longitude_e7=lon;fix.utc_time=time.to_string();fix.received_ms=now;
  if rmc{
   let date=get(9);if !valid_date(date){self.valid=false;self.malformed=self.malformed.saturating_add(1);return false;}fix.utc_date=date.to_string();
   fix.speed_kmh_tenths=(scaled_decimal(get(7),1000).unwrap_or(0).max(0).saturating_mul(1852)/100000).min(u16::MAX as i64) as u16;
  }else{
   fix.satellites=get(7).parse::<u8>().unwrap_or(0);
   fix.hdop_centi=scaled_decimal(get(8),100).unwrap_or(0).clamp(0,u16::MAX as i64) as u16;
   fix.altitude_dm=scaled_decimal(get(9),10).unwrap_or(0).clamp(i32::MIN as i64,i32::MAX as i64) as i32;
  }
  self.latest=Some(fix);self.valid=true;true
 }
}
fn scaled_decimal(text:&str,scale:i64)->Option<i64>{
 let negative=text.starts_with('-');let text=if negative{&text[1..]}else{text};
 let mut parts=text.split('.');let whole=parts.next()?.parse::<i64>().ok()?;let fraction=parts.next().unwrap_or("");
 if parts.next().is_some()||fraction.len()>9||!fraction.bytes().all(|b|b.is_ascii_digit()){return None;}
 let divisor=10i64.checked_pow(fraction.len() as u32)?;let frac=if fraction.is_empty(){0}else{fraction.parse::<i64>().ok()?};
 let value=whole.checked_mul(scale)?.checked_add(frac.checked_mul(scale)?/divisor)?;Some(if negative{-value}else{value})
}
fn parse_coordinate(text:&str,hemisphere:&str,latitude:bool)->Option<i32>{
 let value=scaled_decimal(text,10_000_000)?;if value<0{return None;}
 let degrees=value/1_000_000_000;let minutes=value%1_000_000_000;
 if minutes>=600_000_000||degrees>if latitude{90}else{180}||((degrees==if latitude{90}else{180})&&minutes!=0){return None;}
 let positive=if latitude{hemisphere=="N"}else{hemisphere=="E"};
 if !positive&&!(if latitude{hemisphere=="S"}else{hemisphere=="W"}){return None;}
 let result=degrees*10_000_000+minutes/60;Some((if positive{result}else{-result}) as i32)
}
#[derive(Clone)]pub struct TrackPoint{pub fix:Fix,pub uptime_ms:u64}
pub struct TrackLog<const N:usize>{points:Vec<TrackPoint>,dropped:u32}
impl<const N:usize> Default for TrackLog<N>{fn default()->Self{Self::new()}}
impl<const N:usize> TrackLog<N>{
 pub fn new()->Self{Self{points:Vec::new(),dropped:0}}
 pub fn record(&mut self,fix:&Fix,now:u64){if N==0{self.dropped=self.dropped.saturating_add(1);return;}if self.points.len()>=N{self.points.remove(0);self.dropped=self.dropped.saturating_add(1);}self.points.push(TrackPoint{fix:fix.clone(),uptime_ms:now});}
 pub fn len(&self)->usize{self.points.len()}pub fn is_empty(&self)->bool{self.points.is_empty()}pub fn dropped(&self)->u32{self.dropped}
 pub fn points(&self)->&[TrackPoint]{&self.points}
 pub fn csv(&self)->String{let mut out=String::from("uptime_ms,utc_date,utc_time,latitude,longitude,altitude_dm,satellites,hdop_centi\n");for p in &self.points{out.push_str(&p.fix.csv_row(p.uptime_ms));}out}
}

fn valid_clock(time:&str)->bool{if time.len()<6||time.len()>10{return false;}let bytes=time.as_bytes();if !bytes[..6].iter().all(u8::is_ascii_digit){return false;}if bytes.len()>6&&(bytes[6]!=b'.'||bytes.len()==7||!bytes[7..].iter().all(u8::is_ascii_digit)){return false;}let hour=(bytes[0]-b'0')*10+bytes[1]-b'0';let minute=(bytes[2]-b'0')*10+bytes[3]-b'0';let second=(bytes[4]-b'0')*10+bytes[5]-b'0';hour<24&&minute<60&&(second<60||(hour==23&&minute==59&&second==60))}
fn valid_date(date:&str)->bool{if date.len()!=6||!date.bytes().all(|b|b.is_ascii_digit()){return false;}let bytes=date.as_bytes();let day=(bytes[0]-b'0')*10+bytes[1]-b'0';let month=(bytes[2]-b'0')*10+bytes[3]-b'0';let year=(bytes[4]-b'0')*10+bytes[5]-b'0';let days=match month{1|3|5|7|8|10|12=>31,4|6|9|11=>30,2=>if year%4==0{29}else{28},_=>0};day>0&&day<=days}
pub struct WardriveObservation<'a>{pub address:&'a str,pub name:&'a str,pub auth:&'a str,pub channel:u8,pub rssi:i8,pub kind:&'a str}
pub fn wigle_header()->&'static str{"WigleWifi-1.4,appRelease=0.1,model=Admin12121,release=0.1,device=ESP32S3,display=Admin12121,board=FIELD,brand=Admin12121\nMAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"}
pub fn utc_datetime(fix:&Fix)->Option<String>{if !valid_date(&fix.utc_date)||!valid_clock(&fix.utc_time){return None;}let date=&fix.utc_date;let year=date[4..6].parse::<u16>().ok()?;let year=if year<80{2000+year}else{1900+year};Some(format!("{year}-{}-{} {}:{}:{}",&date[2..4],&date[..2],&fix.utc_time[..2],&fix.utc_time[2..4],&fix.utc_time[4..6]))}
pub fn wigle_row(fix:&Fix,observation:&WardriveObservation<'_>)->Option<String>{let time=utc_datetime(fix)?;let name=observation.name.replace('"',"\"\"").replace(['\r','\n']," ");Some(format!("{},\"{}\",{},{},{},{},{},{},{}.{},0,{}\n",observation.address,name,observation.auth,time,observation.channel,observation.rssi,fix.latitude(),fix.longitude(),fix.altitude_dm/10,fix.altitude_dm.unsigned_abs()%10,observation.kind))}

/// Recent valid fixes used to correlate a radio observation with its receive time.
pub struct FixHistory<const N: usize> { fixes: Vec<Fix> }
impl<const N: usize> Default for FixHistory<N> { fn default()->Self {Self::new()} }
impl<const N: usize> FixHistory<N> {
    pub fn new()->Self {Self {fixes:Vec::new()}}
    pub fn push(&mut self, fix:&Fix) {
        if N==0 {return;}
        if let Some(previous)=self.fixes.iter_mut().find(|f|f.received_ms==fix.received_ms) {*previous=fix.clone();return;}
        if self.fixes.len()>=N {self.fixes.remove(0);}
        self.fixes.push(fix.clone());
    }
    pub fn closest(&self, observed_ms:u64, max_delta_ms:u64)->Option<&Fix> {
        self.fixes.iter().rev().filter(|fix|fix.received_ms.abs_diff(observed_ms)<=max_delta_ms)
            .min_by_key(|fix|fix.received_ms.abs_diff(observed_ms))
    }
    pub fn len(&self)->usize {self.fixes.len()}
    pub fn is_empty(&self)->bool {self.fixes.is_empty()}
}
/// Bounded receive-time cursor: a cached row can only be exported once.
pub struct ObservationCursor<const N:usize> { seen:Vec<(String,u64)> }
impl<const N:usize> Default for ObservationCursor<N> {fn default()->Self {Self::new()}}
impl<const N:usize> ObservationCursor<N> {
    pub fn new()->Self {Self {seen:Vec::new()}}
    pub fn accept(&mut self,key:&str,observed_ms:u64,now_ms:u64,max_age_ms:u64)->bool {
        if N==0 || observed_ms>now_ms || now_ms-observed_ms>max_age_ms {return false;}
        if let Some((_,last))=self.seen.iter_mut().find(|(known,_)|known==key) {
            if observed_ms<=*last {return false;}
            *last=observed_ms;return true;
        }
        if self.seen.len()>=N {self.seen.remove(0);}
        self.seen.push((String::from(key),observed_ms));true
    }
    pub fn len(&self)->usize {self.seen.len()}
    pub fn is_empty(&self)->bool {self.seen.is_empty()}
}

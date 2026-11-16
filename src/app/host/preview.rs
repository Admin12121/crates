//! Export the actual Canvas view as PNG without a display or image dependencies.
use admin12121_ui_host::{app::{App,Live,Tool},platform::{self,Button},registry};
use cyberdeck_core::{net::MacAddr,ui::{Canvas,Rect,Rgb565,font}};
use std::{fs,io,path::Path};

struct Image {width:u16,height:u16,pixels:Vec<u8>}
impl Image {
    fn new(width:u16,height:u16)->Self {Self {width,height,pixels:vec![0;usize::from(width)*usize::from(height)*3]}}
    fn save(&self,path:&Path)->io::Result<()> {
        let mut raw=Vec::new();
        for row in self.pixels.chunks(usize::from(self.width)*3) {raw.push(0);raw.extend_from_slice(row);}
        let mut zlib=vec![0x78,0x01];
        let chunks=raw.chunks(65535);let count=chunks.len();
        for (index,chunk) in chunks.enumerate(){
            zlib.push(if index+1==count {1}else{0});
            let len=chunk.len() as u16;zlib.extend_from_slice(&len.to_le_bytes());zlib.extend_from_slice(&(!len).to_le_bytes());zlib.extend_from_slice(chunk);
        }
        let (mut a,mut b)=(1u32,0u32);
        for byte in raw {a=(a+u32::from(byte))%65521;b=(b+a)%65521;}
        zlib.extend_from_slice(&((b<<16)|a).to_be_bytes());
        let mut png=b"\x89PNG\r\n\x1a\n".to_vec();
        let mut header=Vec::new();header.extend_from_slice(&u32::from(self.width).to_be_bytes());header.extend_from_slice(&u32::from(self.height).to_be_bytes());header.extend_from_slice(&[8,2,0,0,0]);
        chunk(&mut png,b"IHDR",&header);chunk(&mut png,b"IDAT",&zlib);chunk(&mut png,b"IEND",&[]);
        fs::write(path,png)
    }
}
fn chunk(png:&mut Vec<u8>,kind:&[u8;4],data:&[u8]){
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());png.extend_from_slice(kind);png.extend_from_slice(data);
    let mut crc=0xffff_ffffu32;
    for byte in kind.iter().chain(data) {crc^=u32::from(*byte);for _ in 0..8{crc=if crc&1==1{(crc>>1)^0xedb8_8320}else{crc>>1};}}
    png.extend_from_slice(&(!crc).to_be_bytes());
}
impl Canvas for Image {
    fn width(&self)->u16 {self.width}
    fn height(&self)->u16 {self.height}
    fn fill_rect(&mut self,rect:Rect,color:Rgb565){
        let (r,g,b)=color.components();
        for y in rect.y.max(0)..rect.bottom().min(self.height as i16) {
            for x in rect.x.max(0)..rect.right().min(self.width as i16) {
                let pixel=(y as usize*usize::from(self.width)+x as usize)*3;self.pixels[pixel..pixel+3].copy_from_slice(&[r,g,b]);
            }
        }
    }
    fn draw_bitmap(&mut self,x:i16,y:i16,src_w:u16,src_h:u16,dst_w:u16,dst_h:u16,pixels:&[u8]){
        for row in 0..u32::from(dst_h) {
            for column in 0..u32::from(dst_w) {
                let sx=(column*u32::from(src_w)/u32::from(dst_w)) as usize;
                let sy=(row*u32::from(src_h)/u32::from(dst_h)) as usize;
                let at=(sy*usize::from(src_w)+sx)*2;
                if at+1>=pixels.len() {continue;}
                let value=u16::from_be_bytes([pixels[at],pixels[at+1]]);
                if value==0x0001 {continue;}
                let color=Rgb565(value);
                let (r,g,b)=color.components();
                let px=(y as usize+row as usize)*usize::from(self.width)+(x as usize+column as usize);
                if x>=0 && y>=0 && px*3+2<self.pixels.len() {self.pixels[px*3..px*3+3].copy_from_slice(&[r,g,b]);}
            }
        }
    }
    fn draw_glyph(&mut self,x:i16,y:i16,ch:char,fg:Rgb565,bg:Rgb565,scale:u8){
        let scale=scale.max(1);self.fill_rect(Rect::new(x,y,u16::from(font::ADVANCE)*u16::from(scale),u16::from(font::GLYPH_H)*u16::from(scale)),bg);
        for (column,bits) in font::glyph(ch).iter().enumerate(){for row in 0..7{if bits&(1<<row)!=0 {self.fill_rect(Rect::new(x+column as i16*i16::from(scale),y+row*i16::from(scale),u16::from(scale),u16::from(scale)),fg);}}}
    }
}
fn open(group:usize,tool:usize,run:bool)->App {
    let mut app=App::new(registry());
    for tool in [Tool::GpsStatus,Tool::GpsRecord,Tool::GpsWardrive,Tool::NetInfo,Tool::NetDiscover,Tool::NetProbe,Tool::NetServices] {app.set_tool_available(tool);}
    app.set_payloads(&["HID test","Text editor","Presenter"]);
    for _ in 0..group {app.handle(Button::Down);}app.handle(Button::Select);
    for _ in 0..tool {app.handle(Button::Down);}app.handle(Button::Select);
    if run {app.handle(Button::Select);}app
}
fn live()->Live {
    let mut live=Live::default();
    live.wifi_status="Listening on channel 6".into();live.wifi_frames=1284;live.wifi_dropped=2;
    for (name,channel,rssi) in [("Workshop",6,-42),("Guest network",11,-67),("Sensor lab",1,-73)] {
        live.aps.push(platform::wifi::ApRow{ssid:name.into(),bssid:MacAddr::new([0x24,0x6f,0x28,0x10,channel,0x01]),channel,rssi,security:"WPA2"});
    }
    live.ble_status="Scanning...".into();live.ble_frames=86;
    live.ble_devices.push(platform::ble::BleDevice{address:"C4:18:02:AA:BB:01".into(),name:"Lab sensor".into(),rssi:-48,kind:"Sensor",detail:"Temperature service advertised".into()});
    live.usb_status="Connected".into();live.usb_percent=62;live.usb_keystrokes=24;
    live.usb_preview=vec!["REM Local text example".into(),"DELAY 1000".into(),"STRING Admin12121".into(),"ENTER".into()];
    live.rf_peak=48;live.rf_packets=328;live.rf_dropped=0;
    live.rf_envelope=(0..126).map(|n|if (45..54).contains(&n){220-(n as i16-49).unsigned_abs() as u8*25}else{12+(n*7%36) as u8}).collect();
    live.gps_lines=vec!["3D fix  /  9 satellites".into(),"Latitude   27.7172 N".into(),"Longitude  85.3240 E".into(),"Altitude   1,342 m".into(),"Track points: 128".into()];
    live.net_lines=vec!["Joined Workshop".into(),"Address 192.168.1.42".into(),"Router 192.168.1.1".into(),"Signal -42".into()];
    live
}
fn render(app:&mut App,width:u16,height:u16,path:&Path)->io::Result<()> {let mut image=Image::new(width,height);app.render(&mut image);image.save(path)}
fn main()->io::Result<()> {
    let output=std::env::args_os().nth(1).ok_or_else(||io::Error::new(io::ErrorKind::InvalidInput,"usage: ui-preview OUTPUT_DIRECTORY"))?;
    let output=Path::new(&output);fs::create_dir_all(output)?;
    // Splash: what the device shows for ~2.6 s at power-on.
    let mut splash=App::new(registry());splash.enter_splash(0);splash.splash_tick(1900);splash.set_live(live());
    render(&mut splash,240,320,&output.join("splash-240x320.png"))?;
    // Category intro: animated emblem frame, Lupala-style.
    let mut intro=App::new(registry());intro.handle(Button::Select);intro.set_anim_clock(1200);intro.set_live(live());
    render(&mut intro,240,320,&output.join("category-intro-240x320.png"))?;
    // Home tiles carry live counters, so seed them like the running device does.
    let mut home=App::new(registry());home.set_live(live());render(&mut home,240,320,&output.join("home-240x320.png"))?;
    let mut small=App::new(registry());small.set_live(live());render(&mut small,128,160,&output.join("home-128x160.png"))?;
    // Module list for the first group (one Select on Home opens it).
    let mut group=App::new(registry());group.handle(Button::Select);group.set_live(live());
    render(&mut group,240,320,&output.join("wifi-tools-240x320.png"))?;
    let mut setup=open(0,1,false);setup.set_live(live());render(&mut setup,240,320,&output.join("wifi-setup-240x320.png"))?;
    render(&mut setup,128,160,&output.join("wifi-setup-128x160.png"))?;
    let mut wifi=open(0,0,true);wifi.set_live(live());render(&mut wifi,240,320,&output.join("wifi-live-240x320.png"))?;
    let mut handshake=open(0,2,true);
    let mut handshake_live=live();handshake_live.eapol=6;handshake_live.handshakes=1;handshake_live.pmkids=2;
    handshake.set_live(handshake_live);
    render(&mut handshake,240,320,&output.join("wifi-handshake-240x320.png"))?;
    // Evil Twin: portal counters as the device shows them.
    let mut twin=open(0,5,true);
    let mut twin_live=live();twin_live.portal_clients=2;twin_live.portal_requests=7;
    twin.set_live(twin_live);
    render(&mut twin,240,320,&output.join("wifi-evil-twin-240x320.png"))?;
    // Karma: probe requests as the device lists them.
    let mut karma=open(0,6,true);
    let mut karma_live=live();karma_live.probe_ssids=3;karma_live.probe_rows=4;
    karma_live.packet_lines=vec![
        String::from("WORKSHOP  02:AA:BB:CC:DD:01  SIG -48"),
        String::from("GUEST  02:AA:BB:CC:DD:02  SIG -52"),
        String::from("SENSOR-LAB  02:AA:BB:CC:DD:03  SIG -66"),
        String::from("WILDCARD  02:AA:BB:CC:DD:04  SIG -71"),
    ];
    karma.set_live(karma_live);
    render(&mut karma,240,320,&output.join("wifi-karma-240x320.png"))?;
    // Frame inspector: the dissector output as the device renders it.
    let mut inspector=open(1,1,true);
    let mut inspector_live=live();
    inspector_live.packet_lines=vec![
        String::from("802.11 data type 2 sub 0"),
        String::from("  24:6F:28:10:06:01 > 02:AA:BB:CC:DD:EE"),
        String::from("  bssid 24:6F:28:10:06:01  seq 4121"),
        String::from("  ipv4"),
        String::from("    192.168.1.42 > 93.184.216.34"),
        String::from("    ttl 64  52 B  proto 6"),
        String::from("    tcp 51422 > 443  syn"),
    ];
    inspector.set_live(inspector_live);
    render(&mut inspector,240,320,&output.join("packet-inspector-240x320.png"))?;
    wifi.handle(Button::Back);render(&mut wifi,240,320,&output.join("wifi-results-240x320.png"))?;
    let mut ble=open(2,0,true);ble.set_live(live());render(&mut ble,240,320,&output.join("ble-live-240x320.png"))?;
    // BLE HID setup: payload + layout, same picker as the USB path.
    let mut blehid=open(2,3,false);blehid.set_live(live());render(&mut blehid,240,320,&output.join("ble-hid-setup-240x320.png"))?;
    let mut usb=open(3,1,false);usb.set_live(live());render(&mut usb,240,320,&output.join("usb-setup-240x320.png"))?;
    let mut rf=open(4,0,true);rf.set_live(live());render(&mut rf,240,320,&output.join("rf-live-240x320.png"))?;
    let mut gps=open(5,0,true);gps.set_live(live());render(&mut gps,240,320,&output.join("gps-live-240x320.png"))?;
    let mut network=open(6,0,false);network.set_live(live());render(&mut network,240,320,&output.join("network-setup-240x320.png"))?;
    println!("Wrote 11 reference-data previews to {}",output.display());Ok(())
}

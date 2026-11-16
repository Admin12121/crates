//! Passive monitor observations shared by the actor and host tests.

use alloc::{string::String, vec::Vec};
use super::{CaptureFilter,PacketSummary,ProtocolHistogram,hexdump,classify};
use crate::net::MacAddr;
use crate::time::Timestamp;
use crate::wifi::{ap::ScanEngine,eapol::HandshakeStore,frame::{self,FrameHeader,WpsInfo}};
#[derive(Clone,Debug)]
pub struct InspectorRow {pub summary:String,pub metadata:String,pub hex:String}
/// Newest frame kept verbatim so the inspector can dissect it on demand.
#[derive(Clone)]
pub struct LatestFrame {data:[u8;crate::packet::dissect::MAX_FRAME],len:u16}
impl LatestFrame {
    pub const fn new()->Self {Self {data:[0;crate::packet::dissect::MAX_FRAME],len:0}}
    pub fn set(&mut self,frame:&[u8]) {
        let length=frame.len().min(self.data.len());
        self.data[..length].copy_from_slice(&frame[..length]);
        self.len=length as u16;
    }
    pub fn bytes(&self)->&[u8] {&self.data[..usize::from(self.len)]}
}
#[derive(Clone,Debug)]
pub struct WpsObservation {pub bssid:MacAddr,pub info:WpsInfo,pub channel:u8,pub rssi:i8}
/// One station asking for one SSID (the Karma view).
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ProbeRow {pub client:MacAddr,pub ssid:Vec<u8>,pub channel:u8,pub rssi:i8}
/// Bounded probe-request table.
pub const MAX_PROBES: usize = 16;
pub struct PassiveEngine<const A:usize,const S:usize,const H:usize,const R:usize> {
    pub scan:ScanEngine<A,S>,
    pub handshakes:HandshakeStore<H>,
    pub frames:Vec<InspectorRow>,
    pub wps:Vec<WpsObservation>,
    pub histogram:ProtocolHistogram,
    pub latest:LatestFrame,
    pub probes:Vec<ProbeRow>,
}
impl<const A:usize,const S:usize,const H:usize,const R:usize> Default for PassiveEngine<A,S,H,R> {
    fn default()->Self {Self::new()}
}
impl<const A:usize,const S:usize,const H:usize,const R:usize> PassiveEngine<A,S,H,R> {
    pub const fn new()->Self {Self {scan:ScanEngine::new(),handshakes:HandshakeStore::new(),frames:Vec::new(),wps:Vec::new(),probes:Vec::new(),latest:LatestFrame::new(),histogram:ProtocolHistogram {beacons:0,probe_requests:0,probe_responses:0,authentication:0,association:0,deauthentication:0,disassociation:0,action:0,eapol:0,data:0,control:0,other:0,malformed:0}}}
    pub fn on_frame(&mut self,data:&[u8],rssi:i8,channel:u8,ts_us:u64,filter:&CaptureFilter,original_len:u32) {
        self.scan.on_frame(data,rssi,channel,ts_us/1000);
        if let Some(header)=FrameHeader::parse(data) {
            if header.fc.is_management() && matches!(header.fc.subtype,frame::subtype::BEACON | frame::subtype::PROBE_RESP) {
                let ies=header.ies();
                if let Some(ssid)=frame::find_ssid(ies) {self.handshakes.note_ssid(header.addr3,ssid);}
                if let Some(info)=frame::parse_wps(ies) {
                    let row=WpsObservation {bssid:header.addr3,info,channel,rssi};
                    if let Some(old)=self.wps.iter_mut().find(|w|w.bssid==row.bssid) {*old=row;}
                    else if A>0 {if self.wps.len()>=A {self.wps.remove(0);}self.wps.push(row);}
                }
            }
            if header.fc.is_management() && header.fc.subtype==frame::subtype::PROBE_REQ {
                // Karma view: which station is asking for which SSID (empty = wildcard).
                self.note_probe(header.addr2,frame::find_ssid(header.ies()).unwrap_or(&[]),channel,rssi);
            }
            if header.fc.is_data() && !header.fc.protected && !(header.fc.to_ds && header.fc.from_ds) {
                if let Some(eapol)=crate::wifi::ap::eapol_payload(header.body) {
                    let (ap,client)=if header.fc.to_ds {(header.addr1,header.addr2)}
                        else if header.fc.from_ds {(header.addr2,header.addr1)}
                        else {(header.addr3,header.addr2)};
                    let ssid=self.scan.aps.get(ap).map(|a|a.ssid.as_bytes());
                    self.handshakes.on_eapol(eapol,ap,client,ssid,channel,ts_us/1000);
                }
            }
        }
        if !filter.matches(data) {return}
        self.latest.set(data);
        self.histogram.count(classify(data).0);
        if R==0 {return}
        let summary=PacketSummary::build(self.scan.frames,Timestamp::from_micros(ts_us),data,channel,rssi);
        let row=InspectorRow {summary:summary.render_line(64),
            metadata:alloc::format!("{} us | {} -> {} | ch{} {} dBm | {} / {} B",ts_us,summary.source,summary.destination,channel,rssi,data.len(),original_len),
            hex:hexdump(data,8)};
        if self.frames.len()>=R {self.frames.pop();}
        self.frames.insert(0,row);
    }
    /// Record a probe request, merging repeats from the same station and SSID.
    fn note_probe(&mut self,client:MacAddr,ssid:&[u8],channel:u8,rssi:i8) {
        if let Some(existing)=self.probes.iter_mut().find(|row|row.client==client&&row.ssid==ssid) {
            existing.channel=channel;existing.rssi=rssi;return;
        }
        if self.probes.len()>=MAX_PROBES {self.probes.remove(0);}
        self.probes.push(ProbeRow {client,ssid:ssid.to_vec(),channel,rssi});
    }
    /// Distinct non-empty SSIDs stations have asked for.
    pub fn probe_ssids(&self)->usize {
        let mut seen:Vec<&[u8]>=Vec::new();
        for row in &self.probes {
            if row.ssid.is_empty() {continue}
            if !seen.contains(&row.ssid.as_slice()) {seen.push(&row.ssid);}
        }
        seen.len()
    }
    pub fn export_hashes(&self)->String {
        let mut text=String::new();
        for h in self.handshakes.iter() {
            for line in [h.pmkid_hc22000(),h.hc22000()].into_iter().flatten() {text.push_str(&line);text.push('\n');}
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::wifi::{frame, eapol::*};
    #[test]
    fn probe_requests_are_recorded_per_client() {
        let mut engine:PassiveEngine<4,4,2,2>=PassiveEngine::new();
        let filter=super::super::CaptureFilter::default();
        engine.on_frame(&probe_request(MacAddr([0x30;6]),b"Lab"),-50,6,1_000,&filter,40);
        engine.on_frame(&probe_request(MacAddr([0x31;6]),b"Lab"),-55,6,2_000,&filter,40);
        // A repeat from the same station updates in place instead of adding a row.
        engine.on_frame(&probe_request(MacAddr([0x30;6]),b"Lab"),-45,11,3_000,&filter,40);
        engine.on_frame(&probe_request(MacAddr([0x32;6]),b""),-60,1,4_000,&filter,34);
        assert_eq!(engine.probes.len(),3);
        assert_eq!(engine.probes[0].rssi,-45);
        assert_eq!(engine.probes[0].channel,11);
        assert_eq!(engine.probe_ssids(),1,"wildcard probes are not a named SSID");
    }
    #[test]
    fn probe_table_is_bounded() {
        let mut engine:PassiveEngine<4,4,2,2>=PassiveEngine::new();
        let filter=super::super::CaptureFilter::default();
        for index in 0..(MAX_PROBES+8) {
            let mac=MacAddr([0x40,(index&0xFF) as u8,0,0,0,1]);
            engine.on_frame(&probe_request(mac,b"x"),-40,6,index as u64,&filter,36);
        }
        assert_eq!(engine.probes.len(),MAX_PROBES);
    }
    fn probe_request(client:MacAddr,ssid:&[u8])->Vec<u8> {
        let mut frame=alloc::vec![0x40,0x00,0,0];
        frame.extend_from_slice(&[0xFF;6]);
        frame.extend_from_slice(client.as_bytes());
        frame.extend_from_slice(&[0xFF;6]);
        frame.extend_from_slice(&[0,0]);
        frame.push(0);
        frame.push(ssid.len() as u8);
        frame.extend_from_slice(ssid);
        frame
    }

    #[test]
    fn beacon_client_handshake_and_inspector_are_connected() {
        let ap=MacAddr([0x10;6]);let client=MacAddr([0x20;6]);
        let mut engine:PassiveEngine<4,4,2,2>=PassiveEngine::new();
        let beacon=frame::beacon_frame(b"AdminLab",ap,&frame::BeaconOptions::default());
        engine.on_frame(beacon.as_slice(),-40,1,1234567,&super::super::CaptureFilter::default(),beacon.as_slice().len() as u32);
        let mut kde=PMKID_KDE_PREFIX.to_vec();kde.extend_from_slice(&[0xaa;16]);
        let m1=build_eapol_key(DESCRIPTOR_RSN,KEY_INFO_ACK,1,&[1;32],&kde);
        let m2=build_eapol_key(DESCRIPTOR_RSN,KEY_INFO_MIC,1,&[2;32],&[]);
        for (index,key) in [m1,m2].into_iter().enumerate() {
            let mut data=alloc::vec![0x08,1,0,0];data.extend_from_slice(ap.as_bytes());data.extend_from_slice(client.as_bytes());data.extend_from_slice(ap.as_bytes());data.extend_from_slice(&[0;2]);
            data.extend_from_slice(&[0xaa,0xaa,3,0,0,0,0x88,0x8e]);data.extend_from_slice(&key);
            engine.on_frame(&data,-41,1,2_000_000+index as u64,&super::super::CaptureFilter::default(),data.len() as u32);
        }
        assert_eq!(engine.scan.aps.len(),1);assert_eq!(engine.scan.stations.len(),1);
        assert_eq!(engine.handshakes.pmkid_count(),1);assert_eq!(engine.handshakes.complete_count(),1);
        assert!(engine.export_hashes().contains("WPA*01*"));assert!(engine.export_hashes().contains("WPA*02*"));
        assert_eq!(engine.frames.len(),2);assert!(engine.frames[0].metadata.contains("2000001"));
        assert!(engine.frames[0].hex.contains("0000"));assert_eq!(engine.histogram.eapol,2);
    }
    #[test]
    fn rejected_frames_preserve_latest_accepted_inspection() {
        let mut engine: PassiveEngine<4, 4, 2, 2> = PassiveEngine::new();
        let filter = super::super::CaptureFilter { data_only: true, ..Default::default() };
        let mut data = alloc::vec![0u8; 32];
        data[0] = 0x08;
        data[1] = 0x01;
        data[4..10].copy_from_slice(&[1; 6]);
        data[10..16].copy_from_slice(&[2; 6]);
        data[16..22].copy_from_slice(&[1; 6]);
        data[24..32].copy_from_slice(&[0xAA, 0xAA, 3, 0, 0, 0, 8, 0]);
        engine.on_frame(&data, -40, 1, 1_000, &filter, 32);
        assert_eq!(engine.latest.bytes(), data.as_slice());
        let beacon = frame::beacon_frame(b"Discovered", MacAddr([1; 6]), &frame::BeaconOptions::default());
        engine.on_frame(beacon.as_slice(), -45, 1, 2_000, &filter, beacon.as_slice().len() as u32);
        assert_eq!(engine.scan.aps.len(), 1, "a rejected frame still contributes passive discovery");
        assert_eq!(engine.frames.len(), 1);
        assert_eq!(engine.histogram.data, 1);
        assert_eq!(engine.histogram.beacons, 0);
        assert_eq!(engine.latest.bytes(), data.as_slice(), "inspector keeps the latest frame accepted by its filter");
    }

    #[test]
    fn filter_limits_inspector_but_preserves_passive_discovery() {
        let mut engine:PassiveEngine<4,4,2,2>=PassiveEngine::new();
        let beacon=frame::beacon_frame(b"Lab",MacAddr([1;6]),&frame::BeaconOptions::default());
        let filter=super::super::CaptureFilter {data_only:true,..Default::default()};
        engine.on_frame(beacon.as_slice(),-40,1,1234,&filter,100);
        assert_eq!(engine.scan.aps.len(),1);assert!(engine.frames.is_empty());
    }
}

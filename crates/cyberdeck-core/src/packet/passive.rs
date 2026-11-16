//! Passive monitor observations shared by the actor and host tests.

use alloc::{string::String, vec::Vec};
use super::{CaptureFilter,PacketSummary,ProtocolHistogram,hexdump,classify};
use crate::net::MacAddr;
use crate::time::Timestamp;
use crate::wifi::{ap::ScanEngine,eapol::HandshakeStore,frame::{self,FrameHeader,WpsInfo}};
#[derive(Clone,Debug)]
pub struct InspectorRow {pub summary:String,pub metadata:String,pub hex:String}
#[derive(Clone,Debug)]
pub struct WpsObservation {pub bssid:MacAddr,pub info:WpsInfo,pub channel:u8,pub rssi:i8}
pub struct PassiveEngine<const A:usize,const S:usize,const H:usize,const R:usize> {
    pub scan:ScanEngine<A,S>,
    pub handshakes:HandshakeStore<H>,
    pub frames:Vec<InspectorRow>,
    pub wps:Vec<WpsObservation>,
    pub histogram:ProtocolHistogram,
}
impl<const A:usize,const S:usize,const H:usize,const R:usize> Default for PassiveEngine<A,S,H,R> {
    fn default()->Self {Self::new()}
}
impl<const A:usize,const S:usize,const H:usize,const R:usize> PassiveEngine<A,S,H,R> {
    pub const fn new()->Self {Self {scan:ScanEngine::new(),handshakes:HandshakeStore::new(),frames:Vec::new(),wps:Vec::new(),histogram:ProtocolHistogram {beacons:0,probe_requests:0,probe_responses:0,authentication:0,association:0,deauthentication:0,disassociation:0,action:0,eapol:0,data:0,control:0,other:0,malformed:0}}}
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
        self.histogram.count(classify(data).0);
        if R==0 {return}
        let summary=PacketSummary::build(self.scan.frames,Timestamp::from_micros(ts_us),data,channel,rssi);
        let row=InspectorRow {summary:summary.render_line(64),
            metadata:alloc::format!("{} us | {} -> {} | ch{} {} dBm | {} / {} B",ts_us,summary.source,summary.destination,channel,rssi,data.len(),original_len),
            hex:hexdump(data,8)};
        if self.frames.len()>=R {self.frames.pop();}
        self.frames.insert(0,row);
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
    fn filter_limits_inspector_but_preserves_passive_discovery() {
        let mut engine:PassiveEngine<4,4,2,2>=PassiveEngine::new();
        let beacon=frame::beacon_frame(b"Lab",MacAddr([1;6]),&frame::BeaconOptions::default());
        let filter=super::super::CaptureFilter {data_only:true,..Default::default()};
        engine.on_frame(beacon.as_slice(),-40,1,1234,&filter,100);
        assert_eq!(engine.scan.aps.len(),1);assert!(engine.frames.is_empty());
    }
}

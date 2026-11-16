//! Passive monitor observations shared by the actor and host tests.
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

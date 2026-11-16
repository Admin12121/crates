//! Bounded actor/session and FAT/PCAP validation helpers.
use alloc::string::String;


/// One owner from submission until completion. A rejected start never modifies cancellation.
#[derive(Debug, Default)]
pub struct SessionGate { next: u32, pending: Option<u32>, active: Option<u32>, cancelled: bool }
impl SessionGate {
    pub const fn new()->Self { Self { next:0,pending:None,active:None,cancelled:false } }
    pub fn reserve(&mut self)->Option<u32> {
        if self.pending.is_some() || self.active.is_some() {return None}
        self.next=self.next.wrapping_add(1); self.pending=Some(self.next); self.cancelled=false; Some(self.next)
    }
    pub fn activate(&mut self)->Option<u32> { let id=self.pending.take()?; self.active=Some(id); Some(id) }
    pub fn cancel(&mut self) { self.pending=None; if self.active.is_some() { self.cancelled=true; } }
    pub fn cancelled(&self,id:u32)->bool { self.active!=Some(id) || self.cancelled }
    pub fn complete(&mut self,id:u32) { if self.active==Some(id) {self.active=None;} }
}
/// FAT short filenames: three category letters, five digits and a three-letter extension.
pub fn file_name(stem:&str,extension:&str,index:u32)->Option<String> {
    if index>99999 {return None}
    let base:String=stem.bytes().filter(u8::is_ascii_alphanumeric).take(3).map(|b|char::from(b.to_ascii_uppercase())).collect();
    let ext:String=if extension.eq_ignore_ascii_case("PCAP") {String::from("CAP")} else { extension.bytes().filter(u8::is_ascii_alphanumeric).take(3).map(|b|char::from(b.to_ascii_uppercase())).collect() };
    if base.is_empty() || ext.is_empty() {return None}
    Some(alloc::format!("{base}{index:05}.{ext}"))
}
pub fn valid_file_name(name:&str)->bool {
    let mut parts=name.split('.');
    let(base,ext)=(parts.next().unwrap_or(""),parts.next().unwrap_or(""));
    parts.next().is_none() && !base.is_empty() && base.len()<=8 && !ext.is_empty() && ext.len()<=3 &&
        base.bytes().chain(ext.bytes()).all(|b|b.is_ascii_alphanumeric() || b==b'_')
}
/// Validate our little-endian classic-PCAP global header and return the snapshot length.
pub fn pcap_snaplen(data:&[u8])->Option<u32> {
    if data.len()<24 || data[..4]!=crate::pcap::PCAP_MAGIC.to_le_bytes() || data[4..8]!=[2,0,4,0] ||
       data[20..24]!=crate::pcap::LINKTYPE_IEEE802_11_RADIOTAP.to_le_bytes() {return None}
    let snap=u32::from_le_bytes(data[16..20].try_into().ok()?);
    (snap>=crate::pcap::Radiotap::LEN as u32 && snap<=65535).then_some(snap)
}
pub fn pcap_record_size(header:&[u8],snaplen:u32)->Option<usize> {
    if header.len()<16 {return None}
    let micros=u32::from_le_bytes(header[4..8].try_into().ok()?);
    let included=u32::from_le_bytes(header[8..12].try_into().ok()?);
    let original=u32::from_le_bytes(header[12..16].try_into().ok()?);
    (micros<1_000_000 && included<=snaplen && included<=original).then_some(16+included as usize)
}
pub fn valid_pcap_prefix(data:&[u8])->Option<usize> {
    let snap=pcap_snaplen(data)?;
    let mut offset=24usize;
    while let Some(header)=data.get(offset..offset+16) {
        let Some(size)=pcap_record_size(header,snap) else {break};
        if offset+size>data.len(){break}
        offset+=size;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_restart_cannot_clear_active_cancel() {
        let mut gate = SessionGate::new();
        let id = gate.reserve().unwrap();
        assert_eq!(gate.activate(),Some(id));
        gate.cancel();
        assert!(gate.reserve().is_none());
        assert!(gate.cancelled(id));
        gate.complete(id);
        let next=gate.reserve().unwrap();
        assert_ne!(next,id);
        assert_eq!(gate.activate(),Some(next));
        assert!(!gate.cancelled(next));
    }
    #[test]
    fn cancelling_queued_command_does_not_run_it() {
        let mut gate=SessionGate::new();
        gate.reserve().unwrap(); gate.cancel();
        assert_eq!(gate.activate(),None);
        assert!(gate.reserve().is_some());
    }
    #[test]
    fn fat_names_fit_basename_and_extension_and_survive_limits() {
        assert_eq!(file_name("CAPTURE","PCAP",2).as_deref(),Some("CAP00002.CAP"));
        assert_eq!(file_name("wi-fi","csv",99999).as_deref(),Some("WIF99999.CSV"));
        assert!(file_name("CAPTURE","PCAP",100000).is_none());
        assert!(valid_file_name("CAP00002.CAP"));
        assert!(!valid_file_name("CAPTURE002.PCAP"));
        assert!(!valid_file_name("../A.CAP"));
    }
    #[test]
    fn torn_record_recovery_keeps_only_complete_records() {
        let mut writer=crate::pcap::PcapWriter::new(crate::pcap::VecSink::default(),512,false,10000).unwrap();
        writer.write_frame_on_channel(crate::time::Timestamp::from_micros(42),&[1;40],2412,-40).unwrap();
        let(sink,_)=writer.finish().unwrap();
        assert_eq!(valid_pcap_prefix(&sink.0),Some(sink.0.len()));
        assert_eq!(valid_pcap_prefix(&sink.0[..sink.0.len()-1]),Some(24));
        assert_eq!(valid_pcap_prefix(&[1;30]),None);
    }
}

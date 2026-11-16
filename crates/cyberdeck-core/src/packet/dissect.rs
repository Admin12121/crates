//! On-device dissection: one captured frame becomes an indented layer list.
//!
//! Scope is deliberately the protocols a 2.4 GHz monitor sees on this hardware:
//! 802.11 management/data, LLC/SNAP, IPv4, ARP, TCP, UDP, DNS and DHCP. Every
//! parser is length-checked, so malformed or truncated frames produce fewer lines
//! instead of panicking.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::wifi::frame::{self, FrameHeader};

/// Largest frame the dissector will look at; mirrors the capture snap length.
pub const MAX_FRAME: usize = 512;
/// Upper bound on produced lines, so one frame cannot flood the screen.
pub const MAX_LINES: usize = 24;

/// One line of the dissection, with a nesting depth for indentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub depth: u8,
    pub text: String,
}

impl Line {
    fn new(depth: u8, text: String) -> Self {
        Self { depth, text }
    }

    /// Text prefixed with two spaces per depth level.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for _ in 0..self.depth {
            out.push_str("  ");
        }
        out.push_str(&self.text);
        out
    }
}

/// Dissect a frame into display-ready lines.
pub fn lines(data: &[u8]) -> Vec<String> {
    dissect(data).iter().map(Line::render).collect()
}

/// Dissect a raw 802.11 frame (FCS already stripped).
pub fn dissect(data: &[u8]) -> Vec<Line> {
    let mut out = Vec::new();
    let data = data.get(..MAX_FRAME.min(data.len())).unwrap_or(&[]);
    let Some(header) = FrameHeader::parse(data) else {
        out.push(Line::new(0, format!("{} bytes: no 802.11 header", data.len())));
        return out;
    };
    let fc = header.fc;
    out.push(Line::new(
        0,
        format!("802.11 {} type {} sub {}", kind(fc.frame_type), fc.frame_type, fc.subtype),
    ));
    out.push(Line::new(1, format!("{} > {}", header.addr2, header.addr1)));
    out.push(Line::new(1, format!("bssid {}  seq {}", header.addr3, header.sequence >> 4)));
    if fc.protected {
        out.push(Line::new(1, String::from("encrypted payload")));
    } else if fc.is_management() {
        management(&header, &mut out);
    } else if fc.is_data() {
        data_layers(header.body, &mut out);
    }
    out.truncate(MAX_LINES);
    out
}

fn kind(frame_type: u8) -> &'static str {
    match frame_type {
        frame::FRAME_TYPE_MGMT => "management",
        frame::FRAME_TYPE_CTRL => "control",
        frame::FRAME_TYPE_DATA => "data",
        _ => "extension",
    }
}

fn management(header: &FrameHeader<'_>, out: &mut Vec<Line>) {
    let ies = header.ies();
    if let Some(ssid) = frame::find_ssid(ies) {
        out.push(Line::new(1, format!("ssid {}", printable(ssid))));
    }
    let mut at = 0;
    let mut count = 0;
    let mut channel = 0u8;
    let mut rsn = false;
    while at + 2 <= ies.len() && count < 64 {
        let id = ies[at];
        let length = usize::from(ies[at + 1]);
        let start = (at + 2).min(ies.len());
        let body = ies.get(start..(start + length).min(ies.len())).unwrap_or(&[]);
        match id {
            frame::ie::DS_PARAM => channel = *body.first().unwrap_or(&0),
            frame::ie::RSN => rsn = true,
            _ => {}
        }
        count += 1;
        at = at.saturating_add(2 + length);
    }
    if channel > 0 {
        out.push(Line::new(1, format!("channel {channel}")));
    }
    out.push(Line::new(1, format!("{count} IEs{}", if rsn { "  rsn" } else { "" })));
}

fn data_layers(body: &[u8], out: &mut Vec<Line>) {
    let Some((ethertype, payload)) = llc(body) else {
        out.push(Line::new(1, format!("{} bytes of data", body.len())));
        return;
    };
    match ethertype {
        0x0800 => {
            out.push(Line::new(1, String::from("ipv4")));
            ipv4(payload, out);
        }
        0x0806 => {
            out.push(Line::new(1, String::from("arp")));
            arp(payload, out);
        }
        0x86DD => out.push(Line::new(1, String::from("ipv6"))),
        other => out.push(Line::new(1, format!("ethertype 0x{other:04X}"))),
    }
}

/// Strip the 802.11 LLC/SNAP header and return the EtherType plus its payload.
fn llc(body: &[u8]) -> Option<(u16, &[u8])> {
    if body.len() < 8 || body[0] != 0xAA || body[1] != 0xAA || body[2] != 0x03 {
        return None;
    }
    let ethertype = u16::from_be_bytes([body[6], body[7]]);
    Some((ethertype, &body[8..]))
}

fn ipv4(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 20 {
        out.push(Line::new(2, String::from("truncated header")));
        return;
    }
    let header_len = usize::from(payload[0] & 0x0F) * 4;
    if header_len < 20 || payload.len() < header_len {
        out.push(Line::new(2, String::from("bad header length")));
        return;
    }
    let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let protocol = payload[9];
    let fragment = u16::from_be_bytes([payload[6], payload[7]]) & 0x1FFF != 0;
    out.push(Line::new(2, format!("{} > {}", ip(&payload[12..16]), ip(&payload[16..20]))));
    out.push(Line::new(
        2,
        format!("ttl {}  {total} B  proto {}{}", payload[8], protocol, if fragment { "  fragment" } else { "" }),
    ));
    let inner = payload.get(header_len..).unwrap_or(&[]);
    match protocol {
        6 => tcp(inner, out),
        17 => udp(inner, out),
        1 => out.push(Line::new(2, String::from("icmp"))),
        _ => {}
    }
}

fn tcp(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 20 {
        return;
    }
    let source = u16::from_be_bytes([payload[0], payload[1]]);
    let destination = u16::from_be_bytes([payload[2], payload[3]]);
    let flags = payload[13];
    let mut state = String::new();
    for (mask, name) in [(0x02, "syn"), (0x10, "ack"), (0x08, "psh"), (0x01, "fin"), (0x04, "rst")] {
        if flags & mask != 0 {
            if !state.is_empty() {
                state.push(' ');
            }
            state.push_str(name);
        }
    }
    out.push(Line::new(2, format!("tcp {source} > {destination}  {state}")));
}

fn udp(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 8 {
        return;
    }
    let source = u16::from_be_bytes([payload[0], payload[1]]);
    let destination = u16::from_be_bytes([payload[2], payload[3]]);
    out.push(Line::new(2, format!("udp {source} > {destination}")));
    let inner = &payload[8..];
    if destination == 53 || source == 53 {
        dns(inner, out);
    } else if (67..=68).contains(&destination) || (67..=68).contains(&source) {
        dhcp(inner, out);
    }
}

/// First question name of a DNS message; compression pointers stop the walk.
fn dns(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 12 {
        return;
    }
    let mut at = 12;
    let mut name = String::new();
    let mut labels = 0;
    while at < payload.len() && labels < 8 {
        let length = usize::from(payload[at]);
        if length == 0 || length > 63 {
            break;
        }
        let start = at + 1;
        let end = start + length;
        if end > payload.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&printable(&payload[start..end]));
        at = end;
        labels += 1;
    }
    if !name.is_empty() {
        out.push(Line::new(3, format!("dns {name}")));
    }
}

fn dhcp(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 240 || payload[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return;
    }
    let mut at = 240;
    while at + 2 <= payload.len() {
        let code = payload[at];
        let length = usize::from(payload[at + 1]);
        if code == 255 || at + 2 + length > payload.len() {
            break;
        }
        if code == 53 && length >= 1 {
            let label = match payload[at + 2] {
                1 => "discover",
                2 => "offer",
                3 => "request",
                4 => "decline",
                5 => "ack",
                6 => "nak",
                7 => "release",
                _ => "message",
            };
            out.push(Line::new(3, format!("dhcp {label}")));
            return;
        }
        at += 2 + length;
    }
}

fn arp(payload: &[u8], out: &mut Vec<Line>) {
    if payload.len() < 28 {
        out.push(Line::new(2, String::from("truncated header")));
        return;
    }
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);
    let sender_ip = ip(&payload[14..18]);
    let target_ip = ip(&payload[24..28]);
    let verb = if opcode == 1 { "request" } else { "reply" };
    out.push(Line::new(2, format!("arp {verb} {sender_ip} > {target_ip}")));
}

fn ip(bytes: &[u8]) -> String {
    if bytes.len() < 4 {
        return String::from("?");
    }
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Lossy ASCII view: control bytes become dots, so a name never breaks layout.
fn printable(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push(if byte.is_ascii_graphic() || *byte == b' ' { char::from(*byte) } else { '.' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(lines: &[String]) -> String {
        lines.join("\n")
    }

    fn data_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = alloc::vec![0x08, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&[0x02; 6]);
        frame.extend_from_slice(&[0x04; 6]);
        frame.extend_from_slice(&[0x04; 6]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_tcp() -> Vec<u8> {
        let mut packet = alloc::vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        packet.extend_from_slice(&[0x01, 0xBB, 0x01, 0xBB]);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        packet.push(0x50);
        packet.push(0x02);
        packet.extend_from_slice(&[0x20, 0x00, 0, 0, 0, 0]);
        packet
    }

    #[test]
    fn beacon_reports_ssid_and_element_count() {
        let beacon = frame::beacon_frame(b"AdminLab", crate::net::MacAddr([0x10; 6]), &frame::BeaconOptions::default());
        let text = joined(&lines(beacon.as_slice()));
        assert!(text.contains("802.11 management"), "{text}");
        assert!(text.contains("ssid AdminLab"), "{text}");
        assert!(text.contains("IEs"), "{text}");
    }

    #[test]
    fn tcp_frame_shows_ports_and_flags() {
        let frame_data = data_frame(0x0800, &ipv4_tcp());
        let text = joined(&lines(&frame_data));
        assert!(text.contains("ipv4"), "{text}");
        assert!(text.contains("10.0.0.1 > 10.0.0.2"), "{text}");
        assert!(text.contains("tcp 443 > 443  syn"), "{text}");
    }

    #[test]
    fn udp_dns_query_is_named() {
        let mut dns = alloc::vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0, 1, 0, 1]);
        let mut udp = alloc::vec![0x30, 0x39, 0x00, 0x35];
        udp.extend_from_slice(&((dns.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&dns);
        let mut packet = alloc::vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 168, 1, 10, 8, 8, 8, 8];
        let total = (20 + udp.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&udp);
        let text = joined(&lines(&data_frame(0x0800, &packet)));
        assert!(text.contains("udp 12345 > 53"), "{text}");
        assert!(text.contains("dns example.com"), "{text}");
    }

    #[test]
    fn arp_request_names_both_hosts() {
        let mut arp = alloc::vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend_from_slice(&[0xAA; 6]);
        arp.extend_from_slice(&[192, 168, 1, 10]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[192, 168, 1, 1]);
        let text = joined(&lines(&data_frame(0x0806, &arp)));
        assert!(text.contains("arp request 192.168.1.10 > 192.168.1.1"), "{text}");
    }

    #[test]
    fn encrypted_and_runt_frames_stay_bounded() {
        let mut encrypted = data_frame(0x0800, &ipv4_tcp());
        encrypted[0] |= 0x40;
        let text = joined(&lines(&encrypted));
        assert!(text.contains("encrypted payload"), "{text}");
        assert!(!text.contains("tcp"), "{text}");

        let runt = joined(&lines(&[0u8; 10]));
        assert!(runt.contains("no 802.11 header"), "{runt}");

        // A frame that lies about its IP header length must not panic or loop.
        let bad = data_frame(0x0800, &[0x4F, 0, 0, 0, 0, 0, 0, 0, 64, 6]);
        assert!(!lines(&bad).is_empty());
    }

    #[test]
    fn dissection_is_capped() {
        let beacon = frame::beacon_frame(b"x", crate::net::MacAddr([1; 6]), &frame::BeaconOptions::default());
        assert!(dissect(beacon.as_slice()).len() <= MAX_LINES);
    }

    #[test]
    fn depth_renders_as_indentation() {
        let line = Line::new(2, String::from("tcp"));
        assert_eq!(line.render(), "    tcp");
    }
}

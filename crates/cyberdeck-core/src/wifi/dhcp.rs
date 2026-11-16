//! Minimal DHCP server for the captive-portal AP.
//!
//! Only the two exchanges a client needs in order to join are answered:
//! DISCOVER → OFFER and REQUEST → ACK. Every read is length-checked, so a
//! malformed or hostile packet is ignored rather than panicking.

use alloc::vec::Vec;

/// BOOTP/DHCP fixed header length, including the magic cookie.
pub const HEADER_LEN: usize = 240;
/// Upper bound on a reply this server can build.
pub const MAX_REPLY: usize = 300;

const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Port the server listens on.
pub const SERVER_PORT: u16 = 67;
/// Port clients listen on.
pub const CLIENT_PORT: u16 = 68;

pub const OPTION_SUBNET_MASK: u8 = 1;
pub const OPTION_ROUTER: u8 = 3;
pub const OPTION_DNS: u8 = 6;
pub const OPTION_LEASE_TIME: u8 = 51;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER_ID: u8 = 54;
const OPTION_END: u8 = 255;

/// Address plan handed to clients of the captive portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub client_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub mask: [u8; 4],
    pub router: [u8; 4],
    pub dns: [u8; 4],
    pub lease_seconds: u32,
}

impl Lease {
    /// One client address on the portal's own /24.
    pub const fn new(client_ip: [u8; 4], server_ip: [u8; 4]) -> Self {
        Self {
            client_ip,
            server_ip,
            mask: [255, 255, 255, 0],
            router: server_ip,
            dns: server_ip,
            lease_seconds: 3600,
        }
    }
}

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Unknown(u8),
}

impl MessageType {
    pub const fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            other => Self::Unknown(other),
        }
    }

    pub const fn raw(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Unknown(value) => value,
        }
    }
}

/// Run-length encoded option area after the fixed header.
fn options(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() <= HEADER_LEN || packet[236..240] != MAGIC {
        return None;
    }
    Some(&packet[HEADER_LEN..])
}

/// Find one option's value.
pub fn option(packet: &[u8], code: u8) -> Option<&[u8]> {
    let mut data = options(packet)?;
    while data.len() >= 2 {
        let id = data[0];
        let length = usize::from(data[1]);
        let start = 2;
        let end = start + length;
        if end > data.len() {
            return None;
        }
        if id == OPTION_END {
            return None;
        }
        if id == code {
            return Some(&data[start..end]);
        }
        data = &data[end..];
    }
    None
}

/// DHCP message type requested by the client.
pub fn message_type(packet: &[u8]) -> Option<MessageType> {
    option(packet, OPTION_MESSAGE_TYPE)?.first().map(|raw| MessageType::from_raw(*raw))
}

/// Client hardware address (`chaddr`).
pub fn client_mac(packet: &[u8]) -> Option<[u8; 6]> {
    packet.get(28..34)?.try_into().ok()
}

/// Build the reply for `request`, or `None` when the packet is not something this
/// server answers (not DHCP, wrong cookie, RELEASE, truncation).
pub fn reply(request: &[u8], lease: &Lease) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN || request[236..240] != MAGIC {
        return None;
    }
    let answer = match message_type(request)? {
        MessageType::Discover => MessageType::Offer,
        MessageType::Request => MessageType::Ack,
        _ => return None,
    };
    let mut out = Vec::with_capacity(MAX_REPLY);
    out.resize(HEADER_LEN, 0);
    out[0] = 2; // BOOTREPLY
    out[1] = 1; // hardware type: Ethernet
    out[2] = 6; // hardware address length
    out[4..8].copy_from_slice(&request[4..8]); // transaction id
    out[16..20].copy_from_slice(&lease.client_ip); // yiaddr
    out[20..24].copy_from_slice(&lease.server_ip); // siaddr
    out[28..34].copy_from_slice(&request[28..34]); // chaddr, echoed back
    out[236..240].copy_from_slice(&MAGIC);

    out.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, answer.raw()]);
    out.push(OPTION_SERVER_ID);
    out.push(4);
    out.extend_from_slice(&lease.server_ip);
    out.push(OPTION_LEASE_TIME);
    out.push(4);
    out.extend_from_slice(&lease.lease_seconds.to_be_bytes());
    out.push(OPTION_SUBNET_MASK);
    out.push(4);
    out.extend_from_slice(&lease.mask);
    out.push(OPTION_ROUTER);
    out.push(4);
    out.extend_from_slice(&lease.router);
    out.push(OPTION_DNS);
    out.push(4);
    out.extend_from_slice(&lease.dns);
    out.push(OPTION_END);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: [u8; 4] = [192, 168, 4, 1];
    const CLIENT: [u8; 4] = [192, 168, 4, 23];
    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// Build a client packet the way a real client would.
    fn client_message(kind: MessageType, extra: &[u8]) -> Vec<u8> {
        let mut packet = alloc::vec![0u8; HEADER_LEN];
        packet[0] = 1;
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        packet[28..34].copy_from_slice(&MAC);
        packet[236..240].copy_from_slice(&MAGIC);
        packet.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, kind.raw()]);
        packet.extend_from_slice(extra);
        packet.push(OPTION_END);
        packet
    }

    #[test]
    fn discover_gets_an_offer_for_the_lease() {
        let request = client_message(MessageType::Discover, &[]);
        let out = reply(&request, &Lease::new(CLIENT, SERVER)).expect("offer");
        assert_eq!(out[0], 2, "BOOTREPLY");
        assert_eq!(&out[4..8], &[0xDE, 0xAD, 0xBE, 0xEF], "transaction id echoed");
        assert_eq!(&out[16..20], &CLIENT, "yiaddr is the offered address");
        assert_eq!(&out[28..34], &MAC, "client hardware address echoed");
        assert_eq!(message_type(&out), Some(MessageType::Offer));
        assert_eq!(option(&out, OPTION_SERVER_ID), Some(&SERVER[..]));
        assert_eq!(option(&out, OPTION_SUBNET_MASK), Some(&[255, 255, 255, 0][..]));
        assert_eq!(option(&out, OPTION_LEASE_TIME), Some(&3600u32.to_be_bytes()[..]));
        assert_eq!(out.last(), Some(&OPTION_END));
        assert!(out.len() <= MAX_REPLY);
    }

    #[test]
    fn request_gets_an_ack() {
        let request = client_message(MessageType::Request, &[50, 4, 192, 168, 4, 23]);
        let out = reply(&request, &Lease::new(CLIENT, SERVER)).expect("ack");
        assert_eq!(message_type(&out), Some(MessageType::Ack));
    }

    #[test]
    fn release_and_unknown_messages_are_ignored() {
        for kind in [MessageType::Release, MessageType::Decline, MessageType::Nak] {
            assert!(reply(&client_message(kind, &[]), &Lease::new(CLIENT, SERVER)).is_none());
        }
    }

    #[test]
    fn malformed_packets_never_panic() {
        assert!(reply(&[], &Lease::new(CLIENT, SERVER)).is_none());
        assert!(reply(&[0u8; 100], &Lease::new(CLIENT, SERVER)).is_none());
        // Right length, wrong magic cookie.
        let mut bad = client_message(MessageType::Discover, &[]);
        bad[236] = 0;
        assert!(reply(&bad, &Lease::new(CLIENT, SERVER)).is_none());
        // Option length that runs past the packet.
        let mut lying = alloc::vec![0u8; HEADER_LEN];
        lying[236..240].copy_from_slice(&MAGIC);
        lying.extend_from_slice(&[OPTION_MESSAGE_TYPE, 9, 1]);
        assert_eq!(message_type(&lying), None);
        assert!(option(&lying, OPTION_SERVER_ID).is_none());
    }

    #[test]
    fn option_walk_skips_earlier_options() {
        let packet = client_message(MessageType::Request, &[12, 3, b'a', b'b', b'c']);
        assert_eq!(option(&packet, 12), Some(&b"abc"[..]));
        assert_eq!(message_type(&packet), Some(MessageType::Request));
        assert!(option(&packet, 60).is_none());
    }
}

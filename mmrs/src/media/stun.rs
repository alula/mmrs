use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

const BINDING_REQUEST: u16 = 0x0001;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;

/// Also rules out Discord IP discovery requests, which start with the same
/// `00 01` but carry an SSRC where STUN has the magic cookie.
pub fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= HEADER_LEN
        && packet[0] < 4
        && packet[4..8] == MAGIC_COOKIE
        && usize::from(be16(packet, 2)) + HEADER_LEN == packet.len()
}

pub struct BindingRequest<'a> {
    packet: &'a [u8],
    pub username: &'a str,
    integrity_offset: usize,
}

impl<'a> BindingRequest<'a> {
    /// Expects a packet that passed [`is_stun`].
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        if be16(packet, 0) != BINDING_REQUEST {
            return None;
        }
        let mut username = None;
        let mut integrity_offset = None;

        let mut offset = HEADER_LEN;
        while offset + 4 <= packet.len() {
            let kind = be16(packet, offset);
            let len = usize::from(be16(packet, offset + 2));
            let value = packet.get(offset + 4..offset + 4 + len)?;
            match kind {
                ATTR_USERNAME => username = std::str::from_utf8(value).ok(),
                ATTR_MESSAGE_INTEGRITY if len == 20 => integrity_offset = Some(offset),
                _ => {}
            }
            offset += 4 + len.next_multiple_of(4);
        }

        Some(Self {
            packet,
            username: username?,
            integrity_offset: integrity_offset?,
        })
    }

    /// The local ufrag: ICE usernames are `<receiver ufrag>:<sender ufrag>`.
    pub fn local_ufrag(&self) -> &'a str {
        self.username.split(':').next().unwrap_or_default()
    }

    pub fn verify(&self, password: &str) -> bool {
        let expected = &self.packet[self.integrity_offset + 4..self.integrity_offset + 24];
        integrity_mac(&self.packet[..self.integrity_offset], password)
            .verify_slice(expected)
            .is_ok()
    }
}

/// HMAC-SHA1 over everything before MESSAGE-INTEGRITY, with the header length
/// covering the MESSAGE-INTEGRITY attribute itself.
fn integrity_mac(before: &[u8], password: &str) -> Hmac<Sha1> {
    let mut header: [u8; HEADER_LEN] = before[..HEADER_LEN].try_into().unwrap();
    let length = (before.len() + 24 - HEADER_LEN) as u16;
    header[2..4].copy_from_slice(&length.to_be_bytes());

    let mut mac =
        Hmac::<Sha1>::new_from_slice(password.as_bytes()).expect("HMAC accepts any key length");
    mac.update(&header);
    mac.update(&before[HEADER_LEN..]);
    mac
}

fn be16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 section 2.1.
    const SAMPLE_REQUEST: [u8; 108] = [
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];
    const SAMPLE_PASSWORD: &str = "VOkJxbRl1RmTxUk/WvJxBt";

    #[test]
    fn parses_and_verifies_rfc5769_request() {
        assert!(is_stun(&SAMPLE_REQUEST));
        let request = BindingRequest::parse(&SAMPLE_REQUEST).unwrap();
        assert_eq!(request.username, "evtj:h6vY");
        assert_eq!(request.local_ufrag(), "evtj");
        assert!(request.verify(SAMPLE_PASSWORD));
        assert!(!request.verify("wrong"));
    }

    #[test]
    fn ip_discovery_is_not_stun() {
        let mut discovery = [0u8; 74];
        discovery[..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x46]);
        discovery[4..8].copy_from_slice(&12345u32.to_be_bytes());
        assert!(!is_stun(&discovery));
    }
}

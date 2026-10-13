//! Discord IP discovery: 74 bytes each way, type `1` request, type `2` reply.

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryRequest {
    pub ssrc: u32,
    pub protocol_version: ProtocolVersion,
}

pub struct Discovery;

impl Discovery {
    pub fn parse_request(packet: &[u8]) -> Option<DiscoveryRequest> {
        // [u16be(0x01), u16be(70)]
        if packet.len() == 74 && (packet[..4] == [0, 0x01, 0, 70]) {
            let ssrc = u32::from_be_bytes(packet[4..8].try_into().unwrap());

            return Some(DiscoveryRequest {
                ssrc,
                protocol_version: ProtocolVersion::V2,
            });
        }

        if packet.len() == 70 {
            let ssrc = u32::from_be_bytes(packet[0..4].try_into().unwrap());

            return Some(DiscoveryRequest {
                ssrc,
                protocol_version: ProtocolVersion::V1,
            });
        }

        return None;
    }

    pub fn make_response_v1(ssrc: u32, from: SocketAddr) -> [u8; 70] {
        let mut reply = [0; 70];
        reply[..4].copy_from_slice(&ssrc.to_be_bytes());

        let ip = from.ip().to_canonical().to_string();
        reply[4..4 + ip.len()].copy_from_slice(ip.as_bytes());

        reply[68..].copy_from_slice(&from.port().to_le_bytes());

        return reply;
    }

    pub fn make_response_v2(ssrc: u32, from: SocketAddr) -> [u8; 74] {
        let mut reply = [0; 74];
        // [u16be(0x02), u16be(70)]
        reply[..4].copy_from_slice(&[0, 0x02, 0, 70]);
        reply[4..8].copy_from_slice(&ssrc.to_be_bytes());

        let ip = from.ip().to_canonical().to_string();
        reply[8..8 + ip.len()].copy_from_slice(ip.as_bytes());

        reply[72..].copy_from_slice(&from.port().to_be_bytes());

        return reply;
    }
}

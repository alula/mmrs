//! Just enough RTP and RTCP header parsing to route and decrypt packets.

/// The clear part of an encrypted RTCP compound: the first packet's header
/// up to and including the sender SSRC.
pub const RTCP_HEADER_LEN: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    /// `header_len` covers the CSRCs and the extension preamble, which the
    /// rtpsize modes leave in the clear.
    Rtp {
        ssrc: u32,
        header_len: usize,
    },
    Rtcp {
        ssrc: u32,
    },
}

impl Packet {
    pub fn classify(packet: &[u8]) -> Option<Self> {
        if packet.len() < RTCP_HEADER_LEN || packet[0] >> 6 != 2 {
            return None;
        }
        if (192..=223).contains(&packet[1]) {
            return Some(Self::Rtcp {
                ssrc: be32(packet, 4),
            });
        }

        let csrc_count = usize::from(packet[0] & 0x0f);
        let extension = packet[0] & 0x10 != 0;
        let header_len = 12 + 4 * csrc_count + if extension { 4 } else { 0 };
        if packet.len() < header_len {
            return None;
        }

        Some(Self::Rtp {
            ssrc: be32(packet, 8),
            header_len,
        })
    }
}

fn be32(packet: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(packet[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_rtp_and_rtcp() {
        let mut rtp = [0u8; 20];
        rtp[..12].copy_from_slice(&[0x90, 0x78, 0, 1, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            Packet::classify(&rtp),
            Some(Packet::Rtp {
                ssrc: 0xdeadbeef,
                header_len: 16
            })
        );

        let rr = [0x80, 0xc9, 0x00, 0x01, 0, 0, 0x30, 0x39];
        assert_eq!(Packet::classify(&rr), Some(Packet::Rtcp { ssrc: 12345 }));

        let discovery = [0x00, 0x01, 0x00, 0x46, 0, 0, 0x30, 0x39];
        assert_eq!(Packet::classify(&discovery), None);
    }
}

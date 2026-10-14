//! Just enough RTP and RTCP header parsing to route and decrypt packets.

use super::PacketBuf;

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

/// Fixed on the native path (rtp-extensions.md).
pub const OPUS_PAYLOAD_TYPE: u8 = 120;
pub const AUDIO_LEVEL_EXTENSION: u8 = 1;

const ONE_BYTE_PROFILE: u16 = 0xbede;

/// A decrypted RTP packet.
pub struct Rtp<'a> {
    pub marker: bool,
    pub seq: u16,
    pub timestamp: u32,
    /// The body of a one-byte header extension block, if there is one.
    extensions: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Rtp<'a> {
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < 12 || packet[0] >> 6 != 2 {
            return None;
        }
        let padding = packet[0] & 0x20 != 0;
        let mut offset = 12 + 4 * usize::from(packet[0] & 0x0f);

        let mut extensions: &[u8] = &[];
        if packet[0] & 0x10 != 0 {
            let profile = u16::from_be_bytes(packet.get(offset..offset + 2)?.try_into().unwrap());
            let words = u16::from_be_bytes(packet.get(offset + 2..offset + 4)?.try_into().unwrap());
            let body = packet.get(offset + 4..offset + 4 + 4 * usize::from(words))?;
            if profile == ONE_BYTE_PROFILE {
                extensions = body;
            }
            offset += 4 + body.len();
        }

        let mut end = packet.len();
        if padding {
            end = end.checked_sub(usize::from(*packet.last()?))?;
        }

        Some(Self {
            marker: packet[1] & 0x80 != 0,
            seq: u16::from_be_bytes([packet[2], packet[3]]),
            timestamp: be32(packet, 4),
            extensions,
            payload: packet.get(offset..end)?,
        })
    }

    /// A one-byte header extension element (RFC 8285 section 4.2).
    pub fn extension(&self, id: u8) -> Option<&'a [u8]> {
        let mut rest = self.extensions;
        while let [first, tail @ ..] = rest {
            if *first == 0 {
                rest = tail;
                continue;
            }
            if first >> 4 == 15 {
                return None;
            }
            let len = usize::from(first & 0x0f) + 1;
            let value = tail.get(..len)?;
            if first >> 4 == id {
                return Some(value);
            }
            rest = &tail[len..];
        }
        None
    }
}

/// An Opus packet as native clients send it, with its clear header length
/// for the rtpsize modes. `audio_level` is the RFC 6464 byte.
pub fn audio_packet(
    ssrc: u32,
    seq: u16,
    timestamp: u32,
    marker: bool,
    audio_level: Option<u8>,
    payload: &[u8],
) -> Option<(PacketBuf, usize)> {
    let mut packet = PacketBuf::new();
    let extension = if audio_level.is_some() { 0x10 } else { 0 };
    packet
        .try_extend_from_slice(&[0x80 | extension, u8::from(marker) << 7 | OPUS_PAYLOAD_TYPE])
        .ok()?;
    packet.try_extend_from_slice(&seq.to_be_bytes()).ok()?;
    packet
        .try_extend_from_slice(&timestamp.to_be_bytes())
        .ok()?;
    packet.try_extend_from_slice(&ssrc.to_be_bytes()).ok()?;

    let mut header_len = 12;
    if let Some(level) = audio_level {
        packet
            .try_extend_from_slice(&[0xbe, 0xde, 0, 1, AUDIO_LEVEL_EXTENSION << 4, level, 0, 0])
            .ok()?;
        header_len += 4;
    }
    packet.try_extend_from_slice(payload).ok()?;
    Some((packet, header_len))
}

fn be32(packet: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(packet[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests;

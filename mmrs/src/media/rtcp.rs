//! RTCP compounds (RFC 3550 section 6, RFC 4585 section 6): splitting,
//! receiver statistics and the few packets MMRS writes itself.

use std::time::{Duration, Instant};

pub const SR: u8 = 200;
pub const RR: u8 = 201;
pub const APP: u8 = 204;
pub const RTPFB: u8 = 205;
pub const PSFB: u8 = 206;

pub const FMT_NACK: u8 = 1;
pub const FMT_PLI: u8 = 1;

/// Header, sender SSRC and sender info, without report blocks.
const SR_LEN: usize = 28;
const REPORT_BLOCK_LEN: usize = 24;
const MAX_REPORT_BLOCKS: usize = 31;
const DIS0_HEADER_LEN: usize = 12;
const DIS0_BLOCK_LEN: usize = 12;

/// The packets of a compound, up to the first malformed one.
pub fn packets(compound: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = compound;
    std::iter::from_fn(move || {
        if rest.len() < 4 || rest[0] >> 6 != 2 {
            return None;
        }
        let len = 4 * (usize::from(u16::from_be_bytes([rest[2], rest[3]])) + 1);
        if rest.len() < len {
            return None;
        }
        let (packet, tail) = rest.split_at(len);
        rest = tail;
        Some(packet)
    })
}

pub fn packet_type(packet: &[u8]) -> u8 {
    packet[1]
}

/// The report count or feedback message type.
pub fn count(packet: &[u8]) -> u8 {
    packet[0] & 0x1f
}

pub fn sender_ssrc(packet: &[u8]) -> Option<u32> {
    be32(packet, 4)
}

/// The SSRC a feedback message is about.
pub fn media_ssrc(packet: &[u8]) -> Option<u32> {
    be32(packet, 8)
}

/// The middle 32 bits of an SR's NTP timestamp, echoed back as LSR.
pub fn sr_ntp_middle(packet: &[u8]) -> Option<u32> {
    be32(packet, 10)
}

/// An SR without its report blocks, which only describe what the sender
/// receives from MMRS.
pub fn strip_report_blocks(sr: &[u8]) -> Option<[u8; SR_LEN]> {
    let mut stripped: [u8; SR_LEN] = sr.get(..SR_LEN)?.try_into().unwrap();
    stripped[0] = 0x80;
    stripped[2..4].copy_from_slice(&(SR_LEN as u16 / 4 - 1).to_be_bytes());
    Some(stripped)
}

pub fn write_rr(out: &mut Vec<u8>, sender_ssrc: u32, blocks: &[[u8; REPORT_BLOCK_LEN]]) {
    let packets = blocks.len().div_ceil(MAX_REPORT_BLOCKS);
    out.reserve(packets * 8 + blocks.len() * REPORT_BLOCK_LEN);
    for chunk in blocks.chunks(MAX_REPORT_BLOCKS) {
        let words = 1 + chunk.len() * REPORT_BLOCK_LEN / 4;
        out.extend_from_slice(&[0x80 | chunk.len() as u8, RR]);
        out.extend_from_slice(&(words as u16).to_be_bytes());
        out.extend_from_slice(&sender_ssrc.to_be_bytes());
        for block in chunk {
            out.extend_from_slice(block);
        }
    }
}

pub fn make_dis0_block(user_id: u64, bitrate: u32, fraction_lost: u8) -> [u8; DIS0_BLOCK_LEN] {
    let exp = (u32::BITS - bitrate.leading_zeros()).saturating_sub(18);
    let packed = (exp << 26) | ((bitrate >> exp) << 8) | u32::from(fraction_lost);

    let mut block = [0; DIS0_BLOCK_LEN];
    block[0..8].copy_from_slice(&user_id.to_be_bytes());
    block[8..12].copy_from_slice(&packed.to_be_bytes());
    block
}

pub fn write_dis0_blocks(
    out: &mut Vec<u8>,
    layer_ssrc: u32,
    blocks: impl IntoIterator<Item = [u8; DIS0_BLOCK_LEN]>,
) {
    let blocks = blocks.into_iter();
    let most = blocks.size_hint().1.unwrap_or(MAX_REPORT_BLOCKS);
    out.reserve(DIS0_HEADER_LEN + most.min(MAX_REPORT_BLOCKS) * DIS0_BLOCK_LEN);

    let start = out.len();
    out.extend_from_slice(&[0x80, APP, 0, 0]);
    out.extend_from_slice(&layer_ssrc.to_be_bytes());
    out.extend_from_slice(b"0SID");

    let mut count = 0;
    for block in blocks {
        if count == MAX_REPORT_BLOCKS {
            break;
        }
        let written = &out[start + DIS0_HEADER_LEN..];
        if written
            .chunks_exact(DIS0_BLOCK_LEN)
            .any(|other| other[..8] == block[..8])
        {
            continue;
        }
        out.extend_from_slice(&block);
        count += 1;
    }

    let words = 2 + count * DIS0_BLOCK_LEN / 4;
    out[start] |= count as u8;
    out[start + 2..start + 4].copy_from_slice(&(words as u16).to_be_bytes());
}

/// Reception statistics of one incoming SSRC (RFC 3550 appendix A.1, A.3,
/// A.8), without the probation and restart heuristics.
pub struct ReceiveStats {
    clock_rate: u32,
    start: Instant,
    base_seq: u32,
    /// Extended with the number of wraparounds.
    max_seq: u32,
    received: u32,
    expected_prior: u32,
    received_prior: u32,
    transit: u32,
    jitter: f64,
    last_sr: Option<(u32, Instant)>,
}

impl ReceiveStats {
    pub fn new(clock_rate: u32, seq: u16, timestamp: u32, now: Instant) -> Self {
        Self {
            clock_rate,
            start: now,
            base_seq: u32::from(seq),
            max_seq: u32::from(seq),
            received: 1,
            expected_prior: 0,
            received_prior: 0,
            transit: 0u32.wrapping_sub(timestamp),
            jitter: 0.0,
            last_sr: None,
        }
    }

    pub fn record(&mut self, seq: u16, timestamp: u32, now: Instant) {
        let delta = seq.wrapping_sub(self.max_seq as u16) as i16;
        if delta > 0 {
            self.max_seq = self.max_seq.wrapping_add(delta as u32);
        }
        self.received = self.received.wrapping_add(1);

        let arrival = (now.duration_since(self.start).as_secs_f64() * f64::from(self.clock_rate))
            as u64 as u32;
        let transit = arrival.wrapping_sub(timestamp);
        let d = transit.wrapping_sub(self.transit) as i32;
        self.transit = transit;
        self.jitter += (f64::from(d.unsigned_abs()) - self.jitter) / 16.0;
    }

    pub fn record_sr(&mut self, ntp_middle: u32, now: Instant) {
        self.last_sr = Some((ntp_middle, now));
    }

    pub fn report_block(&mut self, ssrc: u32, now: Instant) -> [u8; REPORT_BLOCK_LEN] {
        let expected = self.max_seq.wrapping_sub(self.base_seq).wrapping_add(1);
        let lost = (i64::from(expected) - i64::from(self.received)).clamp(-0x80_0000, 0x7f_ffff);

        let expected_interval = expected.wrapping_sub(self.expected_prior);
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = self.received;
        let lost_interval = i64::from(expected_interval) - i64::from(received_interval);
        let fraction = if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            ((lost_interval << 8) / i64::from(expected_interval)).min(255) as u8
        };

        let (lsr, dlsr) = self.last_sr.map_or((0, 0), |(lsr, at)| {
            (lsr, delay_units(now.duration_since(at)))
        });

        let mut block = [0; REPORT_BLOCK_LEN];
        block[0..4].copy_from_slice(&ssrc.to_be_bytes());
        block[4] = fraction;
        block[5..8].copy_from_slice(&(lost as i32).to_be_bytes()[1..]);
        block[8..12].copy_from_slice(&self.max_seq.to_be_bytes());
        block[12..16].copy_from_slice(&(self.jitter as u32).to_be_bytes());
        block[16..20].copy_from_slice(&lsr.to_be_bytes());
        block[20..24].copy_from_slice(&dlsr.to_be_bytes());
        block
    }
}

/// DLSR is in units of 1/65536 s.
fn delay_units(delay: Duration) -> u32 {
    (delay.as_secs_f64() * 65536.0).min(f64::from(u32::MAX)) as u32
}

fn be32(packet: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        packet.get(offset..offset + 4)?.try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_compounds() {
        let compound = [
            0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1, // empty RR
            0x81, 0xcd, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 5, 0, 0, // NACK
            0x80, 0xc8, 0x00, 0x09, // truncated SR
        ];
        let packets: Vec<_> = packets(&compound).collect();

        assert_eq!(packets.len(), 2);
        assert_eq!(packet_type(packets[0]), RR);
        assert_eq!(
            (packet_type(packets[1]), count(packets[1])),
            (RTPFB, FMT_NACK)
        );
        assert_eq!(media_ssrc(packets[1]), Some(2));
    }

    #[test]
    fn strips_sr_report_blocks() {
        let mut sr = vec![0x81, 0xc8, 0x00, 0x0c];
        sr.extend((4..52).map(|i| i as u8));
        let stripped = strip_report_blocks(&sr).unwrap();

        assert_eq!(stripped[..4], [0x80, 0xc8, 0x00, 0x06]);
        assert_eq!(stripped[4..], sr[4..SR_LEN]);
        assert_eq!(sr_ntp_middle(&sr), Some(0x0a0b0c0d));
    }

    #[test]
    fn reports_loss_across_wraparound() {
        let start = Instant::now();
        let mut stats = ReceiveStats::new(48_000, 65534, 0, start);
        stats.record(65535, 960, start);
        stats.record(1, 2880, start);
        stats.record_sr(0x1234_5678, start);

        let block = stats.report_block(7, start + Duration::from_millis(500));
        assert_eq!(block[0..4], 7u32.to_be_bytes());
        assert_eq!(block[4], 64);
        assert_eq!(block[5..8], [0, 0, 1]);
        assert_eq!(block[8..12], 0x0001_0001u32.to_be_bytes());
        assert_eq!(block[16..20], 0x1234_5678u32.to_be_bytes());
        assert_eq!(block[20..24], 32768u32.to_be_bytes());

        let block = stats.report_block(7, start);
        assert_eq!(block[4], 0);
        assert_eq!(block[5..8], [0, 0, 1]);
    }

    #[test]
    fn writes_receiver_reports() {
        let mut out = Vec::new();
        write_rr(&mut out, 9, &[[1; REPORT_BLOCK_LEN]]);

        assert_eq!(out[..8], [0x81, 0xc9, 0x00, 0x07, 0, 0, 0, 9]);
        assert_eq!(out.len(), 32);
        assert_eq!(packets(&out).count(), 1);
    }

    #[test]
    fn writes_video_receivers() {
        let blocks = [
            make_dis0_block(409988776655443322, 1_500_000, 0),
            make_dis0_block(302211009988776655, 1_500_000, 0),
        ];
        let mut out = Vec::new();
        write_dis0_blocks(&mut out, 44505, blocks);

        let header = [
            0x82, 0xcc, 0x00, 0x08, 0x00, 0x00, 0xad, 0xd9, 0x30, 0x53, 0x49, 0x44,
        ];
        assert_eq!(out[..12], header);
        let first = [
            0x05, 0xb0, 0x92, 0x9e, 0xc2, 0x71, 0xd5, 0x7a, 0x0e, 0xdc, 0x6c, 0x00,
        ];
        assert_eq!(out[12..24], first);
        let second = [
            0x04, 0x31, 0xab, 0x4f, 0xf9, 0x97, 0xd2, 0xcf, 0x0e, 0xdc, 0x6c, 0x00,
        ];
        assert_eq!(out[24..], second);
    }

    #[test]
    fn writes_empty_video_receivers() {
        let mut out = Vec::new();
        write_dis0_blocks(&mut out, 44505, []);

        let header = [
            0x80, 0xcc, 0x00, 0x02, 0x00, 0x00, 0xad, 0xd9, 0x30, 0x53, 0x49, 0x44,
        ];
        assert_eq!(out, header);
        assert_eq!(packets(&out).count(), 1);
    }
}

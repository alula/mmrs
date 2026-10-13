//! Transport encryption of the `udp` protocol: everything after the clear
//! header is sealed, followed by the 16 byte tag and the 4 byte counter
//! (N4). The nonce is N4 padded with zeros.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::array::Array;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit, Nonce, Tag};
use chacha20poly1305::XChaCha20Poly1305;

use super::PacketBuf;
use crate::encryption::EncryptionMode;

const TAG_LEN: usize = 16;
const N4_LEN: usize = 4;

pub enum Cipher {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha20Poly1305(Box<XChaCha20Poly1305>),
    Plain,
}

impl Cipher {
    pub fn new(mode: EncryptionMode, key: &[u8; 32]) -> Self {
        match mode {
            EncryptionMode::AeadAes256GcmRtpsize => {
                Self::Aes256Gcm(Box::new(Aes256Gcm::new(&Array::from(*key))))
            }
            EncryptionMode::AeadXChaCha20Poly1305Rtpsize => {
                Self::XChaCha20Poly1305(Box::new(XChaCha20Poly1305::new(&Array::from(*key))))
            }
            EncryptionMode::Plain => Self::Plain,
        }
    }

    /// Returns the packet with its body decrypted and the trailer removed.
    pub fn open(&self, packet: &[u8], header_len: usize) -> Option<PacketBuf> {
        match self {
            Self::Aes256Gcm(aead) => open(aead.as_ref(), packet, header_len),
            Self::XChaCha20Poly1305(aead) => open(aead.as_ref(), packet, header_len),
            Self::Plain => PacketBuf::try_from(packet).ok(),
        }
    }

    /// `None` if the sealed packet would not fit a [`PacketBuf`].
    pub fn seal(&self, packet: &[u8], header_len: usize, n4: u32) -> Option<PacketBuf> {
        match self {
            Self::Aes256Gcm(aead) => seal(aead.as_ref(), packet, header_len, n4),
            Self::XChaCha20Poly1305(aead) => seal(aead.as_ref(), packet, header_len, n4),
            Self::Plain => PacketBuf::try_from(packet).ok(),
        }
    }
}

fn nonce<A: AeadCore>(n4: [u8; N4_LEN]) -> Nonce<A> {
    let mut nonce = Nonce::<A>::default();
    nonce[..N4_LEN].copy_from_slice(&n4);
    nonce
}

fn open<A: AeadInOut>(aead: &A, packet: &[u8], header_len: usize) -> Option<PacketBuf> {
    let body_end = packet.len().checked_sub(TAG_LEN + N4_LEN)?;
    if body_end < header_len {
        return None;
    }

    let n4 = packet[packet.len() - N4_LEN..].try_into().unwrap();
    let tag = Tag::<A>::try_from(&packet[body_end..body_end + TAG_LEN]).ok()?;
    let mut plain = PacketBuf::try_from(&packet[..body_end]).ok()?;
    aead.decrypt_inout_detached(
        &nonce::<A>(n4),
        &packet[..header_len],
        (&mut plain[header_len..]).into(),
        &tag,
    )
    .ok()?;

    Some(plain)
}

fn seal<A: AeadInOut>(aead: &A, packet: &[u8], header_len: usize, n4: u32) -> Option<PacketBuf> {
    let n4 = n4.to_le_bytes();
    let mut sealed = PacketBuf::try_from(packet).ok()?;

    let (header, body) = sealed.split_at_mut(header_len);
    let tag = aead
        .encrypt_inout_detached(&nonce::<A>(n4), header, body.into())
        .ok()?;

    sealed.try_extend_from_slice(&tag).ok()?;
    sealed.try_extend_from_slice(&n4).ok()?;
    Some(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Koe's frame 1 vectors (udp-transport.md 5.5).
    const KEY: [u8; 32] = {
        let mut key = [0; 32];
        let mut i = 0;
        while i < 32 {
            key[i] = 0xA0 + i as u8;
            i += 1;
        }
        key
    };
    const PLAIN: [u8; 15] = [
        0x80, 0x78, 0xff, 0xff, 0x01, 0x02, 0x06, 0xc4, 0xde, 0xad, 0xbe, 0xef, 0x26, 0x31, 0x3c,
    ];
    const N4: u32 = 0xFFFF_FFFE;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn check(mode: EncryptionMode, expected: &str) {
        let cipher = Cipher::new(mode, &KEY);
        let sealed = cipher.seal(&PLAIN, 12, N4).unwrap();
        assert_eq!(sealed.as_slice(), hex(expected));
        assert_eq!(cipher.open(&sealed, 12).unwrap().as_slice(), PLAIN);

        let mut tampered = sealed.clone();
        tampered[12] ^= 1;
        assert!(cipher.open(&tampered, 12).is_none());
    }

    #[test]
    fn aes256_gcm_rtpsize_vector() {
        check(
            EncryptionMode::AeadAes256GcmRtpsize,
            "8078ffff010206c4deadbeef17ea434f41bae8c90f0f5dbd8ef56371e936d3feffffff",
        );
    }

    #[test]
    fn xchacha20_poly1305_rtpsize_vector() {
        check(
            EncryptionMode::AeadXChaCha20Poly1305Rtpsize,
            "8078ffff010206c4deadbeefa06a33599ca91d7229c3d2508f739e57ee45ebfeffffff",
        );
    }

    #[test]
    fn short_packets_are_rejected() {
        let cipher = Cipher::new(EncryptionMode::AeadAes256GcmRtpsize, &KEY);
        assert!(cipher.open(&PLAIN, 12).is_none());
    }
}

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    AeadAes256GcmRtpsize,
    AeadXChaCha20Poly1305Rtpsize,
    /// No transport encryption (debug only, only supported by very early Discord clients)
    Plain,
}

impl EncryptionMode {
    pub const DEFAULT: &[Self] = &[Self::AeadAes256GcmRtpsize, Self::AeadXChaCha20Poly1305Rtpsize];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AeadAes256GcmRtpsize => "aead_aes256_gcm_rtpsize",
            Self::AeadXChaCha20Poly1305Rtpsize => "aead_xchacha20_poly1305_rtpsize",
            Self::Plain => "plain",
        }
    }
}

impl FromStr for EncryptionMode {
    type Err = UnknownEncryptionMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::AeadAes256GcmRtpsize, Self::AeadXChaCha20Poly1305Rtpsize, Self::Plain]
            .into_iter()
            .find(|mode| mode.as_str() == s)
            .ok_or_else(|| UnknownEncryptionMode(s.to_owned()))
    }
}

impl Serialize for EncryptionMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct UnknownEncryptionMode(String);

impl fmt::Display for UnknownEncryptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown encryption mode {:?}", self.0)
    }
}

impl std::error::Error for UnknownEncryptionMode {}

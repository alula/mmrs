use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::encryption::EncryptionMode;

#[derive(Deserialize)]
pub struct Frame {
    pub op: u32,
    #[serde(default)]
    pub d: Value,
}

pub fn encode(op: u32, d: impl Serialize) -> String {
    serde_json::json!({ "op": op, "d": d }).to_string()
}

#[derive(Deserialize)]
pub struct Identify {
    #[serde(deserialize_with = "id")]
    pub server_id: String,
    #[serde(deserialize_with = "id")]
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    #[serde(default, deserialize_with = "optional_id")]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub streams: Vec<StreamRequest>,
}

#[derive(Deserialize)]
pub struct StreamRequest {
    pub rid: Option<String>,
    pub quality: Option<u8>,
}

#[derive(Serialize)]
pub struct Hello {
    pub v: u8,
    pub heartbeat_interval: u64,
}

#[derive(Serialize)]
pub struct Ready {
    pub ssrc: u32,
    pub ip: String,
    pub port: u16,
    pub modes: Vec<EncryptionMode>,
    pub streams: Vec<ReadyStream>,
    pub experiments: Vec<String>,
}

#[derive(Serialize)]
pub struct ReadyStream {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub ssrc: u32,
    pub rtx_ssrc: u32,
    pub rid: String,
    pub quality: u8,
    pub active: bool,
}

#[derive(Serialize)]
pub struct BackendVersion {
    pub voice: &'static str,
    pub rtc_worker: &'static str,
}

/// Android sends snowflakes as JSON numbers.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawId {
    String(String),
    Number(u64),
}

impl From<RawId> for String {
    fn from(raw: RawId) -> Self {
        match raw {
            RawId::String(s) => s,
            RawId::Number(n) => n.to_string(),
        }
    }
}

fn id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    RawId::deserialize(deserializer).map(String::from)
}

fn optional_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<RawId>::deserialize(deserializer)?.map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_accepts_numeric_ids() {
        let identify: Identify = serde_json::from_value(serde_json::json!({
            "server_id": "456789012345678901",
            "user_id": 123456789012345678u64,
            "session_id": "4c1f8a2e7b3d9065e2a7c4f1083b6d95",
            "token": "7f3a9c1e5b2d8046",
        }))
        .unwrap();
        assert_eq!(identify.user_id, "123456789012345678");
        assert_eq!(identify.channel_id, None);
        assert!(identify.streams.is_empty());
    }
}

use std::collections::HashMap;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::encryption::EncryptionMode;
use crate::room::{Resolution, VideoStream};

#[derive(Deserialize)]
pub struct Frame {
    pub op: u32,
    #[serde(default)]
    pub d: Value,
}

pub fn encode(op: u32, d: impl Serialize, seq: Option<u16>) -> String {
    match seq {
        Some(seq) => serde_json::json!({ "seq": seq, "op": op, "d": d }),
        None => serde_json::json!({ "op": op, "d": d }),
    }
    .to_string()
}

/// Server binary frames: `seq u16 BE` (v8 only), `op u8`, payload.
pub fn encode_binary(op: u8, payload: &[u8], seq: Option<u16>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(3 + payload.len());
    if let Some(seq) = seq {
        frame.extend_from_slice(&seq.to_be_bytes());
    }
    frame.push(op);
    frame.extend_from_slice(payload);
    frame
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
    #[serde(default)]
    pub max_dave_protocol_version: u8,
}

#[derive(Deserialize)]
pub struct Resume {
    #[serde(deserialize_with = "id")]
    pub server_id: String,
    pub session_id: String,
    pub token: String,
    /// -1 when nothing was received yet.
    #[serde(default)]
    pub seq_ack: Option<i64>,
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

#[derive(Deserialize)]
pub struct SelectProtocol {
    pub protocol: String,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub codecs: Vec<Codec>,
}

#[derive(Deserialize)]
pub struct Codec {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub priority: i64,
    pub payload_type: Option<u8>,
    pub rtx_payload_type: Option<u8>,
    #[serde(default = "bool_true")]
    pub encode: bool,
    #[serde(default = "bool_true")]
    pub decode: bool,
}

#[derive(Deserialize)]
pub struct UdpProtocolData {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub mode: String,
}

#[derive(Serialize)]
pub struct SessionDescription {
    pub audio_codec: &'static str,
    pub video_codec: &'static str,
    pub media_session_id: String,
    pub dave_protocol_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<EncryptionMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
}

#[derive(Serialize)]
pub struct SessionUpdate {
    pub audio_codec: &'static str,
    pub video_codec: &'static str,
}

/// Keys are `any` or an SSRC in decimal, values a quality from 0 to 100.
/// Other keys (`pixelCounts`) are ignored.
#[derive(Deserialize)]
pub struct MediaSinkWants {
    pub any: Option<u8>,
    #[serde(flatten)]
    pub ssrcs: HashMap<String, Value>,
}

#[derive(Serialize)]
pub struct BackendVersion {
    pub voice: &'static str,
    pub rtc_worker: &'static str,
}

/// A bool before v4, flags from v4 on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SpeakingState {
    Flags(u32),
    Bool(bool),
}

impl SpeakingState {
    pub fn for_version(version: u8, flags: u32) -> Self {
        if version >= 4 {
            Self::Flags(flags)
        } else {
            Self::Bool(flags != 0)
        }
    }

    pub fn flags(self) -> u32 {
        match self {
            Self::Flags(flags) => flags,
            Self::Bool(speaking) => u32::from(speaking),
        }
    }
}

#[derive(Deserialize)]
pub struct ClientSpeaking {
    pub speaking: SpeakingState,
}

#[derive(Serialize)]
pub struct Speaking<'a> {
    pub user_id: &'a str,
    pub ssrc: u32,
    pub speaking: SpeakingState,
}

#[derive(Deserialize)]
pub struct ClientVideo {
    /// Sent as 0 when every layer is off.
    #[serde(default, deserialize_with = "nonzero")]
    pub video_ssrc: Option<NonZeroU32>,
    #[serde(default)]
    pub streams: Vec<ClientVideoStream>,
}

#[derive(Deserialize)]
pub struct ClientVideoStream {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub rid: Option<String>,
    pub active: Option<bool>,
    pub quality: Option<u8>,
    pub max_bitrate: Option<u32>,
    pub max_framerate: Option<u32>,
    pub max_resolution: Option<Resolution>,
}

#[derive(Serialize)]
pub struct Video<'a> {
    pub user_id: &'a str,
    pub audio_ssrc: u32,
    pub video_ssrc: u32,
    pub rtx_ssrc: u32,
    pub streams: &'a [VideoStream],
}

#[derive(Serialize)]
pub struct ClientsConnect<'a> {
    pub user_ids: Vec<&'a str>,
}

#[derive(Serialize)]
pub struct ClientDisconnect<'a> {
    pub user_id: &'a str,
}

#[derive(Serialize)]
pub struct ClientFlags<'a> {
    pub user_id: &'a str,
    pub flags: Option<u32>,
}

#[derive(Serialize)]
pub struct Platform<'a> {
    pub user_id: &'a str,
    pub platform: Option<u32>,
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
    return RawId::deserialize(deserializer).map(String::from);
}

fn optional_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    return Ok(Option::<RawId>::deserialize(deserializer)?.map(String::from));
}

fn bool_true() -> bool {
    return true;
}

fn nonzero<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<NonZeroU32>, D::Error> {
    return Ok(NonZeroU32::new(u32::deserialize(deserializer)?));
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

    #[test]
    fn codecs_from_native() {
        let select: SelectProtocol = serde_json::from_value(serde_json::json!({
            "protocol": "udp",
            "codecs": [
                {"name": "opus", "type": "audio", "priority": 1000, "payload_type": 120},
                {"name": "AV1", "type": "video", "priority": 1000, "payload_type": 101,
                 "rtx_payload_type": 102, "encode": false, "decode": true},
            ],
        }))
        .unwrap();

        let [opus, av1] = &select.codecs[..] else {
            panic!("two codecs");
        };
        assert_eq!(
            (opus.payload_type, opus.rtx_payload_type),
            (Some(120), None)
        );
        assert_eq!(av1.kind, "video");
        assert_eq!(
            (av1.payload_type, av1.rtx_payload_type),
            (Some(101), Some(102))
        );
        assert_eq!((av1.encode, av1.decode), (false, true));
    }

    #[test]
    fn codecs_from_browser() {
        let select: SelectProtocol = serde_json::from_value(serde_json::json!({
            "protocol": "webrtc",
            "codecs": [
                {"name": "opus", "type": "audio", "priority": 1000, "payload_type": 111,
                 "rtx_payload_type": null},
                {"name": "H264", "type": "video", "priority": 1000, "payload_type": 103,
                 "rtx_payload_type": 104},
            ],
        }))
        .unwrap();

        let [opus, h264] = &select.codecs[..] else {
            panic!("two codecs");
        };
        assert_eq!(opus.rtx_payload_type, None);
        assert_eq!(h264.priority, 1000);
        assert_eq!(
            (h264.payload_type, h264.rtx_payload_type),
            (Some(103), Some(104))
        );
        assert!(h264.encode && h264.decode);
    }

    #[test]
    fn video_from_native() {
        let video: ClientVideo = serde_json::from_value(serde_json::json!({
            "audio_ssrc": 21562,
            "video_ssrc": 21563,
            "rtx_ssrc": 21564,
            "streams": [
                {"type": "video", "rid": "50", "ssrc": 21563, "active": true, "quality": 50,
                 "rtx_ssrc": 21564, "max_bitrate": 2500000, "max_framerate": 20,
                 "max_resolution": {"type": "fixed", "width": 1280, "height": 720}},
                {"type": "video", "rid": "100", "ssrc": 21565, "active": true, "quality": 100,
                 "rtx_ssrc": 21566, "max_bitrate": 2500000, "max_framerate": 20,
                 "max_resolution": {"type": "fixed", "width": 1280, "height": 720}},
            ],
        }))
        .unwrap();

        assert_eq!(video.video_ssrc, NonZeroU32::new(21563));
        assert_eq!(video.streams.len(), 2);
        let low = &video.streams[0];
        assert_eq!(low.kind.as_deref(), Some("video"));
        assert_eq!(low.rid.as_deref(), Some("50"));
        assert_eq!(low.active, Some(true));
        assert_eq!(low.quality, Some(50));
        assert_eq!(low.max_bitrate, Some(2_500_000));
        assert_eq!(low.max_framerate, Some(20));
        assert_eq!(
            low.max_resolution,
            Some(Resolution {
                kind: "fixed".into(),
                width: 1280,
                height: 720,
            })
        );
    }

    #[test]
    fn video_from_browser() {
        let video: ClientVideo = serde_json::from_value(serde_json::json!({
            "audio_ssrc": 0,
            "video_ssrc": 0,
            "rtx_ssrc": 0,
            "streams": [
                {"type": "video", "rid": "100", "ssrc": 44177483, "rtx_ssrc": 2445231536u32,
                 "active": false, "quality": 100, "max_bitrate": 2500000, "max_framerate": 20,
                 "max_resolution": {"type": "fixed", "width": 1280, "height": 720}},
            ],
        }))
        .unwrap();

        assert_eq!(video.video_ssrc, None);
        assert_eq!(video.streams.len(), 1);
        assert_eq!(video.streams[0].rid.as_deref(), Some("100"));
        assert_eq!(video.streams[0].active, Some(false));
    }

    #[test]
    fn video_without_streams() {
        let video: ClientVideo = serde_json::from_value(serde_json::json!({
            "audio_ssrc": 1234,
            "video_ssrc": 0,
            "rtx_ssrc": 0,
        }))
        .unwrap();

        assert_eq!(video.video_ssrc, None);
        assert!(video.streams.is_empty());
    }
}

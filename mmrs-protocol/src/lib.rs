//! Messages exchanged between an MMRS node and a tenant over NATS.
//!
//! The tenant hands out a [`VoiceToken`] in `VOICE_SERVER_UPDATE`. On voice
//! IDENTIFY the node sends a [`TicketRequest`] to [`subjects::ticket_resolve`]
//! and expects a [`TicketResponse`]. The node publishes [`Event`]s to
//! [`subjects::events`], and a [`NodeAnnounce`] to [`subjects::nodes_announce`]
//! periodically and whenever the tenant publishes to [`subjects::nodes_discover`].

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod subjects {
    pub const DEFAULT_PREFIX: &str = "mmrs";

    pub fn ticket_resolve(prefix: &str) -> String {
        format!("{prefix}.ticket.resolve")
    }

    pub fn events(prefix: &str, node_id: &str) -> String {
        format!("{prefix}.events.{node_id}")
    }

    pub fn nodes_announce(prefix: &str) -> String {
        format!("{prefix}.nodes.announce")
    }

    pub fn nodes_discover(prefix: &str) -> String {
        format!("{prefix}.nodes.discover")
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VoiceToken(String);

impl VoiceToken {
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self(format!("{:016x}", getrandom::u64()?)))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let valid = s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        valid.then(|| Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VoiceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for VoiceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VoiceToken(..)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRequest {
    pub token: VoiceToken,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TicketResponse {
    Granted(Ticket),
    Denied,
}

/// The node checks every field except `room` against the IDENTIFY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub user_id: String,
    pub session_id: String,
    pub server_id: String,
    pub channel_id: Option<String>,
    /// Opaque room key chosen by the tenant, e.g. `g/<guild>/c/<channel>`.
    pub room: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAnnounce {
    pub node_id: String,
    /// `host:port` the tenant puts in VOICE_SERVER_UPDATE.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub state: NodeState,
    /// Connected voice sessions on the node, across all tenants.
    pub participants: u32,
    /// No limit when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,
    /// How long the announcement is valid without a newer one.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u32,
}

fn default_ttl_secs() -> u32 {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Ready,
    /// Still serving, but guilds should move elsewhere where possible.
    Draining,
    /// Sent once on shutdown.
    Gone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    SessionStarted {
        node_id: String,
        session: SessionRef,
    },
    SessionEnded {
        node_id: String,
        session: SessionRef,
        reason: EndReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRef {
    pub user_id: String,
    pub session_id: String,
    pub server_id: String,
    pub channel_id: Option<String>,
    pub room: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    ClientDisconnected,
    HeartbeatTimeout,
    Replaced,
    ProtocolError,
    NodeShutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip() {
        let token = VoiceToken::generate().unwrap();
        assert_eq!(VoiceToken::parse(token.as_str()), Some(token));
    }

    #[test]
    fn token_rejects_non_canonical() {
        assert!(VoiceToken::parse("b93b69686c989101").is_some());
        assert!(VoiceToken::parse("B93B69686C989101").is_none());
        assert!(VoiceToken::parse("b93b69686c98910").is_none());
        assert!(VoiceToken::parse("b93b69686c98910g").is_none());
    }

    #[test]
    fn ticket_response_wire_format() {
        let json = serde_json::to_value(TicketResponse::Granted(Ticket {
            user_id: "1".into(),
            session_id: "s".into(),
            server_id: "2".into(),
            channel_id: None,
            room: "g/2/c/3".into(),
        }))
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "granted", "user_id": "1", "session_id": "s",
                "server_id": "2", "channel_id": null, "room": "g/2/c/3"
            })
        );
        assert_eq!(
            serde_json::to_value(TicketResponse::Denied).unwrap(),
            serde_json::json!({"type": "denied"})
        );
    }

    #[test]
    fn node_announce_wire_format() {
        let announce = NodeAnnounce {
            node_id: "n1".into(),
            endpoint: "kuroi.local:8080".into(),
            region: Some("local".into()),
            state: NodeState::Ready,
            participants: 3,
            capacity: None,
            ttl_secs: 30,
        };
        assert_eq!(
            serde_json::to_value(&announce).unwrap(),
            serde_json::json!({
                "node_id": "n1", "endpoint": "kuroi.local:8080", "region": "local",
                "state": "ready", "participants": 3, "ttl_secs": 30
            })
        );

        let minimal: NodeAnnounce = serde_json::from_value(serde_json::json!({
            "node_id": "n1", "endpoint": "kuroi.local:8080", "state": "gone", "participants": 0
        }))
        .unwrap();
        assert_eq!(minimal.ttl_secs, 30);
        assert_eq!(minimal.capacity, None);
    }
}

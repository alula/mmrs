use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use mmrs_protocol::{EndReason, Event, SessionRef, TicketResponse, VoiceToken};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until};

use super::close::CloseCode;
use super::payload::{self, Frame, Identify, StreamRequest};
use super::{close_message, opcode};
use crate::AppState;
use crate::session::SessionKey;
use crate::tenant::Tenant;

const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(13_750);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_millis(2 * 13_750 + 5_000);
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_STREAMS: usize = 4;

pub struct Connection {
    socket: WebSocket,
    state: Arc<AppState>,
    tenant: Arc<Tenant>,
    version: u8,
    client_addr: SocketAddr,
    session: Option<Session>,
}

struct Session {
    key: SessionKey,
    conn_id: u64,
    info: SessionRef,
    replaced: oneshot::Receiver<()>,
}

struct End {
    close: Option<CloseCode>,
    reason: EndReason,
}

impl End {
    fn new(close: CloseCode, reason: EndReason) -> Self {
        Self { close: Some(close), reason }
    }

    fn protocol(close: CloseCode) -> Self {
        Self::new(close, EndReason::ProtocolError)
    }

    fn disconnected() -> Self {
        Self { close: None, reason: EndReason::ClientDisconnected }
    }
}

impl Connection {
    pub fn new(
        socket: WebSocket,
        state: Arc<AppState>,
        tenant: Arc<Tenant>,
        version: u8,
        client_addr: SocketAddr,
    ) -> Self {
        Self { socket, state, tenant, version, client_addr, session: None }
    }

    pub async fn run(mut self) {
        let end = self.serve().await;

        if let Some(code) = end.close {
            let _ = self.socket.send(close_message(code)).await;
        }
        if let Some(session) = self.session.take() {
            self.state.sessions.unregister(&session.key, session.conn_id);
            self.tenant
                .publish(&Event::SessionEnded {
                    node_id: self.state.config.node_id.clone(),
                    session: session.info,
                    reason: end.reason,
                })
                .await;
        }
    }

    async fn serve(&mut self) -> End {
        let hello = payload::Hello { v: self.version, heartbeat_interval: HEARTBEAT_INTERVAL.as_millis() as u64 };
        if let Err(end) = self.send(opcode::HELLO, hello).await {
            return end;
        }

        let identify_deadline = Instant::now() + IDENTIFY_TIMEOUT;
        let mut heartbeat_deadline = Instant::now() + HEARTBEAT_TIMEOUT;
        let mut shutdown = self.state.shutdown.clone();

        loop {
            let identified = self.session.is_some();
            let message = tokio::select! {
                message = self.socket.recv() => message,
                _ = sleep_until(heartbeat_deadline) => {
                    return End::new(CloseCode::SessionTimeout, EndReason::HeartbeatTimeout);
                }
                _ = sleep_until(identify_deadline), if !identified => {
                    return End::protocol(CloseCode::NotAuthenticated);
                }
                _ = replaced(&mut self.session) => {
                    return End::new(CloseCode::Disconnected, EndReason::Replaced);
                }
                _ = shutdown.wait_for(|stop| *stop) => {
                    return End::new(CloseCode::ServerCrash, EndReason::NodeShutdown);
                }
            };

            let text = match message {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_)) | Err(_)) | None => return End::disconnected(),
            };
            let frame: Frame = match serde_json::from_str(&text) {
                Ok(frame) => frame,
                Err(_) => return End::protocol(CloseCode::DecodeError),
            };
            if frame.op == opcode::HEARTBEAT {
                heartbeat_deadline = Instant::now() + HEARTBEAT_TIMEOUT;
            }
            if let Err(end) = self.handle(frame).await {
                return end;
            }
        }
    }

    async fn handle(&mut self, frame: Frame) -> Result<(), End> {
        match frame.op {
            opcode::HEARTBEAT => self.send(opcode::HEARTBEAT_ACK, heartbeat_ack(self.version, frame.d)).await,
            opcode::IDENTIFY if self.session.is_some() => Err(End::protocol(CloseCode::AlreadyAuthenticated)),
            opcode::IDENTIFY => {
                let identify = serde_json::from_value(frame.d).map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.identify(identify).await
            }
            opcode::RESUME => Err(End::protocol(CloseCode::SessionNoLongerValid)),
            _ if self.session.is_none() => Err(End::protocol(CloseCode::NotAuthenticated)),
            opcode::VOICE_BACKEND_VERSION => {
                let version = concat!("mmrs ", env!("CARGO_PKG_VERSION"));
                let reply = payload::BackendVersion { voice: version, rtc_worker: version };
                self.send(opcode::VOICE_BACKEND_VERSION, reply).await
            }
            op => {
                tracing::trace!(op, "ignoring op");
                Ok(())
            }
        }
    }

    async fn identify(&mut self, identify: Identify) -> Result<(), End> {
        let auth_failed = || End::protocol(CloseCode::AuthenticationFailed);
        let token = VoiceToken::parse(&identify.token).ok_or_else(auth_failed)?;

        let ticket = match self.tenant.resolve(token).await {
            Ok(TicketResponse::Granted(ticket)) => ticket,
            Ok(TicketResponse::Denied) => return Err(auth_failed()),
            Err(error) => {
                tracing::warn!(%error, tenant = %self.tenant.name, "ticket resolve failed");
                return Err(End::protocol(CloseCode::ServerCrash));
            }
        };

        // Clients before gateway v9 do not send `channel_id`.
        let channel_matches = match (&ticket.channel_id, &identify.channel_id) {
            (Some(expected), Some(sent)) => expected == sent,
            _ => true,
        };
        if ticket.user_id != identify.user_id
            || ticket.session_id != identify.session_id
            || ticket.server_id != identify.server_id
            || !channel_matches
        {
            return Err(auth_failed());
        }
        if identify.streams.len() > MAX_STREAMS {
            return Err(End::protocol(CloseCode::BadRequest));
        }

        let key = SessionKey {
            tenant: self.tenant.name.clone(),
            user_id: ticket.user_id.clone(),
            session_id: ticket.session_id.clone(),
        };
        let registration = self.state.sessions.register(key.clone());
        let info = SessionRef {
            user_id: ticket.user_id,
            session_id: ticket.session_id,
            server_id: ticket.server_id,
            channel_id: identify.channel_id.or(ticket.channel_id),
            room: ticket.room,
        };
        self.session = Some(Session {
            key,
            conn_id: registration.conn_id,
            info: info.clone(),
            replaced: registration.replaced,
        });

        let ready = self.ready(identify.streams);
        self.send(opcode::READY, ready).await?;
        self.tenant
            .publish(&Event::SessionStarted { node_id: self.state.config.node_id.clone(), session: info })
            .await;
        Ok(())
    }

    fn ready(&self, mut streams: Vec<StreamRequest>) -> payload::Ready {
        let config = &self.state.config;
        let ssrc = self.state.ssrcs.allocate(1 + 2 * streams.len() as u32);

        // Discord assigns SSRCs to simulcast layers lowest quality first.
        streams.sort_by_key(|stream| stream.quality.unwrap_or(100));
        let streams = streams
            .into_iter()
            .zip((ssrc + 1..).step_by(2))
            .map(|(stream, video_ssrc)| payload::ReadyStream {
                kind: "video",
                ssrc: video_ssrc,
                rtx_ssrc: video_ssrc + 1,
                rid: stream.rid.unwrap_or_else(|| "100".to_owned()),
                quality: stream.quality.unwrap_or(100),
                active: false,
            })
            .collect();

        payload::Ready {
            ssrc,
            ip: self.media_ip().to_string(),
            port: config.media_port,
            modes: config.encryption_modes.clone(),
            streams,
            experiments: Vec::new(),
        }
    }

    fn media_ip(&self) -> IpAddr {
        let config = &self.state.config;
        let client_is_v6 = match self.client_addr.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none(),
            IpAddr::V4(_) => false,
        };
        match config.media_ipv6 {
            Some(ipv6) if config.enable_ipv6 && client_is_v6 => IpAddr::V6(ipv6),
            _ => IpAddr::V4(config.media_ipv4),
        }
    }

    async fn send(&mut self, op: u32, d: impl Serialize) -> Result<(), End> {
        self.socket.send(Message::Text(payload::encode(op, d).into())).await.map_err(|_| End::disconnected())
    }
}

async fn replaced(session: &mut Option<Session>) {
    if let Some(session) = session
        && (&mut session.replaced).await.is_ok()
    {
        return;
    }
    std::future::pending().await
}

/// v8 acks `{t}`; older versions echo the nonce. Every version gets op 6,
/// since clients answer a server op 3 with another heartbeat.
fn heartbeat_ack(version: u8, d: Value) -> Value {
    match d.get("t") {
        Some(t) if version >= 8 => serde_json::json!({ "t": t }),
        _ => d,
    }
}

#[cfg(test)]
mod tests {
    use super::heartbeat_ack;
    use serde_json::json;

    #[test]
    fn heartbeat_ack_per_version() {
        assert_eq!(heartbeat_ack(8, json!({"t": 1730000000000u64, "seq_ack": 7})), json!({"t": 1730000000000u64}));
        assert_eq!(heartbeat_ack(7, json!(1730000000000u64)), json!(1730000000000u64));
        assert_eq!(heartbeat_ack(5, json!("1730000000000")), json!("1730000000000"));
    }
}

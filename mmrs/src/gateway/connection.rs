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
use super::payload::{self, Frame, Identify, SelectProtocol, StreamRequest, UdpProtocolData};
use super::{close_message, opcode};
use crate::AppState;
use crate::encryption::EncryptionMode;
use crate::media::{IceLease, SsrcLease};
use crate::session::SessionKey;
use crate::tenant::Tenant;

const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(13_750);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_millis(2 * 13_750 + 5_000);
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_STREAMS: usize = 4;

const DTLS_FINGERPRINT_PLACEHOLDER: &str = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

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
    _ssrc: SsrcLease,
    transport: Option<Transport>,
}

enum Transport {
    Udp,
    WebRtc { _ice: IceLease },
}

struct End {
    close: Option<CloseCode>,
    reason: EndReason,
}

impl End {
    fn new(close: CloseCode, reason: EndReason) -> Self {
        Self {
            close: Some(close),
            reason,
        }
    }

    fn protocol(close: CloseCode) -> Self {
        Self::new(close, EndReason::ProtocolError)
    }

    fn disconnected() -> Self {
        Self {
            close: None,
            reason: EndReason::ClientDisconnected,
        }
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
        Self {
            socket,
            state,
            tenant,
            version,
            client_addr,
            session: None,
        }
    }

    pub async fn run(mut self) {
        let end = self.serve().await;

        if let Some(code) = end.close {
            let _ = self.socket.send(close_message(code)).await;
        }
        if let Some(session) = self.session.take() {
            self.state
                .sessions
                .unregister(&session.key, session.conn_id);
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
        let hello = payload::Hello {
            v: self.version,
            heartbeat_interval: HEARTBEAT_INTERVAL.as_millis() as u64,
        };
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
            opcode::HEARTBEAT => {
                self.send(opcode::HEARTBEAT_ACK, heartbeat_ack(self.version, frame.d))
                    .await
            }
            opcode::IDENTIFY if self.session.is_some() => {
                Err(End::protocol(CloseCode::AlreadyAuthenticated))
            }
            opcode::IDENTIFY => {
                let identify = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.identify(identify).await
            }
            opcode::RESUME => Err(End::protocol(CloseCode::SessionNoLongerValid)),
            _ if self.session.is_none() => Err(End::protocol(CloseCode::NotAuthenticated)),
            opcode::SELECT_PROTOCOL => {
                let select = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.select_protocol(select).await
            }
            opcode::VOICE_BACKEND_VERSION => {
                let version = concat!("mmrs ", env!("CARGO_PKG_VERSION"));
                let reply = payload::BackendVersion {
                    voice: version,
                    rtc_worker: version,
                };
                self.send(opcode::VOICE_BACKEND_VERSION, reply).await
            }
            op => {
                tracing::trace!(op, "ignoring op");
                Ok(())
            }
        }
    }

    async fn identify(&mut self, mut identify: Identify) -> Result<(), End> {
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

        if ticket.user_id != identify.user_id
            || ticket.session_id != identify.session_id
            || ticket.server_id != identify.server_id
        {
            return Err(auth_failed());
        }

        if identify.streams.len() > MAX_STREAMS {
            return Err(End::protocol(CloseCode::BadRequest));
        }

        // Discord hands out a placeholder video stream even with `video: false`.
        if identify.streams.is_empty() {
            identify.streams.push(StreamRequest {
                rid: Some(String::new()),
                quality: Some(0),
            });
        }

        let key = SessionKey {
            tenant: self.tenant.name.clone(),
            user_id: ticket.user_id.clone(),
            session_id: ticket.session_id.clone(),
        };
        let registration = self.state.sessions.register(key.clone());
        let ssrc = self
            .state
            .ssrcs
            .allocate(1 + 2 * identify.streams.len() as u32);

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
            _ssrc: self.state.media.lease_ssrc(ssrc),
            transport: None,
        });

        let ready = self.ready(ssrc, identify.streams);
        self.send(opcode::READY, ready).await?;
        self.tenant
            .publish(&Event::SessionStarted {
                node_id: self.state.config.node_id.clone(),
                session: info,
            })
            .await;

        return Ok(());
    }

    fn ready(&self, ssrc: u32, mut streams: Vec<StreamRequest>) -> payload::Ready {
        let config = &self.state.config;

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

        return payload::Ready {
            ssrc,
            ip: self.media_ip().to_string(),
            port: config.media_port,
            modes: config.encryption_modes.clone(),
            streams,
            experiments: Vec::new(),
        };
    }

    async fn select_protocol(&mut self, select: SelectProtocol) -> Result<(), End> {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.transport.is_some())
        {
            tracing::debug!("ignoring repeated select protocol");
            return Ok(());
        }

        let video_codec = select
            .codecs
            .iter()
            .filter(|codec| codec.kind == "video")
            .min_by_key(|codec| codec.priority)
            .map_or_else(|| "H264".to_owned(), |codec| codec.name.clone());

        let mut description = payload::SessionDescription {
            audio_codec: "opus",
            video_codec,
            media_session_id: hex(&random::<16>()),
            dave_protocol_version: 0,
            mode: None,
            secret_key: None,
            sdp: None,
        };

        let transport = match select.protocol.as_str() {
            "udp" => self.select_transport_udp(select, &mut description)?,
            "webrtc" => self.select_transport_webrtc(&mut description)?,
            _ => return Err(End::protocol(CloseCode::UnknownProtocol)),
        };
        if let Some(session) = &mut self.session {
            session.transport = Some(transport);
        }

        return self.send(opcode::SESSION_DESCRIPTION, description).await;
    }

    fn select_transport_udp(
        &self,
        select: SelectProtocol,
        description: &mut payload::SessionDescription,
    ) -> Result<Transport, End> {
        let data: UdpProtocolData = serde_json::from_value(select.data)
            .map_err(|_| End::protocol(CloseCode::DecodeError))?;
        let mode = data
            .mode
            .parse::<EncryptionMode>()
            .ok()
            .filter(|mode| self.state.config.encryption_modes.contains(mode))
            .ok_or_else(|| End::protocol(CloseCode::UnknownEncryptionMode))?;

        description.mode = Some(mode);
        description.secret_key = Some(random());

        return Ok(Transport::Udp);
    }

    fn select_transport_webrtc(
        &self,
        description: &mut payload::SessionDescription,
    ) -> Result<Transport, End> {
        let ice = self.state.media.lease_ice();

        description.sdp = Some(self.sdp_answer(&ice));

        return Ok(Transport::WebRtc { _ice: ice });
    }

    /// The transport-only template the web client builds its remote
    /// description from.
    fn sdp_answer(&self, ice: &IceLease) -> String {
        let ip = self.media_ip();
        let port = self.state.config.media_port;
        let family = match ip {
            IpAddr::V4(_) => "IP4",
            IpAddr::V6(_) => "IP6",
        };

        return format!(
            "m=audio {port} ICE/SDP\n\
             c=IN {family} {ip}\n\
             a=rtcp:{port}\n\
             a=ice-ufrag:{ufrag}\n\
             a=ice-pwd:{pwd}\n\
             a=fingerprint:sha-256 {DTLS_FINGERPRINT_PLACEHOLDER}\n\
             a=candidate:1 1 UDP 2130706431 {ip} {port} typ host\n",
            ufrag = ice.ufrag,
            pwd = ice.password,
        );
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
        return self
            .socket
            .send(Message::Text(payload::encode(op, d).into()))
            .await
            .map_err(|_| End::disconnected());
    }
}

async fn replaced(session: &mut Option<Session>) {
    if let Some(session) = session
        && (&mut session.replaced).await.is_ok()
    {
        return;
    }

    return std::future::pending().await;
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("system RNG");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        assert_eq!(
            heartbeat_ack(8, json!({"t": 1730000000000u64, "seq_ack": 7})),
            json!({"t": 1730000000000u64})
        );
        assert_eq!(
            heartbeat_ack(7, json!(1730000000000u64)),
            json!(1730000000000u64)
        );
        assert_eq!(
            heartbeat_ack(5, json!("1730000000000")),
            json!("1730000000000")
        );
    }
}

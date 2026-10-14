use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use mmrs_protocol::{EndReason, Event, SessionRef, TicketResponse, VoiceToken};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};

use super::close::CloseCode;
use super::payload::{
    self, ClientSpeaking, Frame, Identify, Resume, SelectProtocol, SpeakingState, StreamRequest,
    UdpProtocolData,
};
use super::resume::{ParkKey, Parking, Replay};
use super::{close_message, opcode};
use crate::AppState;
use crate::encryption::EncryptionMode;
use crate::media::{Leg, Offer, SinkWants};
use crate::room::{Membership, Push, RoomKey, Speaking};
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

/// Outlives its WebSocket while parked for a resume.
pub struct Session {
    key: SessionKey,
    conn_id: u64,
    pub info: SessionRef,
    /// The IDENTIFY token, which a RESUME must repeat.
    pub token: String,
    replaced: oneshot::Receiver<()>,
    membership: Membership,
    pushes: mpsc::UnboundedReceiver<Push>,
    leg: Leg,
    transport: Option<Transport>,
    replay: Replay,
}

enum Signal {
    Replaced,
    Push(Push),
}

enum Transport {
    Udp,
    WebRtc,
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

    fn resumable(&self) -> bool {
        matches!(
            self.reason,
            EndReason::ClientDisconnected | EndReason::HeartbeatTimeout
        )
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
        let Some(session) = self.session.take() else {
            return;
        };
        // Clients only resume once they have a SESSION_DESCRIPTION.
        if end.resumable() && session.transport.is_some() {
            Parking::park(&self.state, self.tenant.clone(), session, end.reason);
        } else {
            end_session(&self.state, &self.tenant, session, end.reason).await;
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
                signal = session_signal(&mut self.session) => match signal {
                    Signal::Replaced => {
                        return End::new(CloseCode::Disconnected, EndReason::Replaced);
                    }
                    Signal::Push(push) => {
                        if let Err(end) = self.push(push).await {
                            return end;
                        }
                        continue;
                    }
                },
                // Drops the watch guard, which is not Send, before an arm awaits.
                _ = async { shutdown.wait_for(|stop| *stop).await.is_ok() } => {
                    return End::new(CloseCode::ServerCrash, EndReason::NodeShutdown);
                }
            };

            if let Some(Ok(message)) = message.as_ref() {
                self.log_message("<~", message);
            }

            let text = match message {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(Message::Binary(data))) => {
                    if let Err(end) = self.handle_binary(&data) {
                        return end;
                    }
                    continue;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
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
                if let Some(session) = &mut self.session
                    && let Some(seq_ack) = frame.d.get("seq_ack").and_then(Value::as_i64)
                {
                    session.replay.ack(seq_ack);
                }
                self.send(opcode::HEARTBEAT_ACK, heartbeat_ack(self.version, frame.d))
                    .await
            }
            opcode::IDENTIFY | opcode::RESUME if self.session.is_some() => {
                Err(End::protocol(CloseCode::AlreadyAuthenticated))
            }
            opcode::IDENTIFY => {
                let identify = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.identify(identify).await
            }
            opcode::RESUME => {
                let resume = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.resume(resume).await
            }
            _ if self.session.is_none() => Err(End::protocol(CloseCode::NotAuthenticated)),
            opcode::SELECT_PROTOCOL => {
                let select = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                self.select_protocol(select).await
            }
            opcode::SPEAKING => {
                let speaking: ClientSpeaking = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                if let Some(session) = &self.session {
                    // Browsers name their own SSRC; MMRS forwards every
                    // client's audio from the leg's.
                    session.membership.set_speaking(Speaking {
                        ssrc: session.leg.first_ssrc(),
                        flags: speaking.speaking.flags(),
                    });
                }
                Ok(())
            }
            opcode::MEDIA_SINK_WANTS => {
                let wants: payload::MediaSinkWants = serde_json::from_value(frame.d)
                    .map_err(|_| End::protocol(CloseCode::DecodeError))?;
                if let Some(session) = &self.session {
                    session.leg.set_wants(sink_wants(wants));
                }
                Ok(())
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

    /// Client binary frames: `op u8`, payload. Only DAVE uses them.
    fn handle_binary(&mut self, data: &[u8]) -> Result<(), End> {
        let Some((&op, payload)) = data.split_first() else {
            return Err(End::protocol(CloseCode::DecodeError));
        };
        if self.session.is_none() {
            return Err(End::protocol(CloseCode::NotAuthenticated));
        }

        return Ok(());
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
        let parked = self.state.parking.take(&ParkKey {
            tenant: self.tenant.name.clone(),
            session_id: ticket.session_id.clone(),
        });
        let room = RoomKey {
            tenant: self.tenant.name.clone(),
            room: ticket.room.clone(),
        };
        let leg = self
            .state
            .media
            .open_leg(room.clone(), 1 + 2 * identify.streams.len() as u32);
        let ready = self.ready(leg.first_ssrc(), identify.streams);
        let (membership, pushes) =
            self.state
                .rooms
                .join(room, registration.conn_id, ticket.user_id.clone());
        // After the join, so peers never see this user leave.
        if let Some(old) = parked {
            end_session(&self.state, &self.tenant, old, EndReason::Replaced).await;
        }

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
            token: identify.token,
            replaced: registration.replaced,
            membership,
            pushes,
            leg,
            transport: None,
            replay: Replay::default(),
        });

        self.send(opcode::READY, ready).await?;
        self.tenant
            .publish(&Event::SessionStarted {
                node_id: self.state.config.node_id.clone(),
                session: info,
            })
            .await;

        return Ok(());
    }

    async fn resume(&mut self, resume: Resume) -> Result<(), End> {
        let key = ParkKey {
            tenant: self.tenant.name.clone(),
            session_id: resume.session_id,
        };
        let session = self
            .state
            .parking
            .claim(&key, &resume.token, &resume.server_id)
            .ok_or_else(|| End::protocol(CloseCode::SessionNoLongerValid))?;

        let missed = session.replay.after(resume.seq_ack.unwrap_or(-1));
        // Holding the session ends it through `run` if the replay fails.
        self.session = Some(session);
        let missed = missed.ok_or_else(|| End::protocol(CloseCode::SessionNoLongerValid))?;

        self.send(opcode::RESUMED, Value::Null).await?;
        for message in missed {
            self.socket
                .send(message)
                .await
                .map_err(|_| End::disconnected())?;
        }
        return Ok(());
    }

    fn ready(&self, ssrc: u32, mut streams: Vec<StreamRequest>) -> payload::Ready {
        let media = &self.state.media;

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
            ip: media.ip_for(self.client_addr).to_string(),
            port: media.port(),
            modes: self.state.config.encryption_modes.clone(),
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
            "webrtc" => self.select_transport_webrtc(select, &mut description)?,
            _ => return Err(End::protocol(CloseCode::UnknownProtocol)),
        };
        if let Some(session) = &mut self.session {
            session.transport = Some(transport);
        }

        self.send(opcode::SESSION_DESCRIPTION, description).await?;
        if self.version >= 5 {
            self.send(opcode::MEDIA_SINK_WANTS, serde_json::json!({ "any": 100 }))
                .await?;
        }
        return Ok(());
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

        let Some(session) = &self.session else {
            return Err(End::protocol(CloseCode::NotAuthenticated));
        };
        description.mode = Some(mode);
        description.secret_key = Some(session.leg.select_udp(mode));

        return Ok(Transport::Udp);
    }

    fn select_transport_webrtc(
        &self,
        select: SelectProtocol,
        description: &mut payload::SessionDescription,
    ) -> Result<Transport, End> {
        let offer = select
            .data
            .as_str()
            .and_then(Offer::parse)
            .ok_or_else(|| End::protocol(CloseCode::DecodeError))?;

        let Some(session) = &self.session else {
            return Err(End::protocol(CloseCode::NotAuthenticated));
        };
        let ip = self.state.media.ip_for(self.client_addr);
        let sdp = session.leg.select_webrtc(offer, ip).map_err(|error| {
            tracing::warn!(%error, "webrtc setup failed");
            End::protocol(CloseCode::ServerCrash)
        })?;
        description.sdp = Some(sdp);

        return Ok(Transport::WebRtc);
    }

    async fn push(&mut self, push: Push) -> Result<(), End> {
        match push {
            Push::Connected(peers) => {
                let user_ids = peers.iter().map(|peer| peer.user_id.as_str()).collect();
                self.send(
                    opcode::CLIENTS_CONNECT,
                    payload::ClientsConnect { user_ids },
                )
                .await?;

                for peer in &peers {
                    let user_id = peer.user_id.as_str();
                    if let Some(speaking) = peer.speaking {
                        self.send_speaking(user_id, speaking).await?;
                    }
                    self.send(
                        opcode::CLIENT_FLAGS,
                        payload::ClientFlags {
                            user_id,
                            flags: None,
                        },
                    )
                    .await?;
                    self.send(
                        opcode::PLATFORM,
                        payload::Platform {
                            user_id,
                            platform: None,
                        },
                    )
                    .await?;
                }
                Ok(())
            }
            Push::Disconnected { user_id } => {
                self.send(
                    opcode::CLIENT_DISCONNECT,
                    payload::ClientDisconnect { user_id: &user_id },
                )
                .await
            }
            Push::Speaking { user_id, speaking } => self.send_speaking(&user_id, speaking).await,
        }
    }

    async fn send_speaking(&mut self, user_id: &str, speaking: Speaking) -> Result<(), End> {
        let payload = payload::Speaking {
            user_id,
            ssrc: speaking.ssrc,
            speaking: SpeakingState::for_version(self.version, speaking.flags),
        };
        self.send(opcode::SPEAKING, payload).await
    }

    async fn send(&mut self, op: u32, d: impl Serialize) -> Result<(), End> {
        let session = self
            .session
            .as_mut()
            .filter(|_| self.version >= 8 && opcode::is_sequenced(op));
        let message = match session {
            Some(session) => session.replay.encode(op, d),
            None => Message::Text(payload::encode(op, d, None).into()),
        };
        self.log_message("~>", &message);

        return self
            .socket
            .send(message)
            .await
            .map_err(|_| End::disconnected());
    }

    async fn send_binary(&mut self, op: u8, data: &[u8]) -> Result<(), End> {
        let message = match self.session.as_mut().filter(|_| self.version >= 8) {
            Some(session) => session.replay.encode_binary(op, data),
            None => Message::Binary(payload::encode_binary(op, data, None).into()),
        };
        self.log_message("~>", &message);

        return self
            .socket
            .send(message)
            .await
            .map_err(|_| End::disconnected());
    }

    fn log_message(&self, prefix: &str, message: &Message) {
        match message {
            Message::Text(text) => {
                tracing::trace!("{} {}", prefix, text.as_str());
            }
            Message::Binary(data) => {
                tracing::trace!("{} binary {} bytes", prefix, data.len());
            }
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) => {}
        }
    }
}

pub async fn end_session(state: &AppState, tenant: &Tenant, session: Session, reason: EndReason) {
    state.sessions.unregister(&session.key, session.conn_id);
    tenant
        .publish(&Event::SessionEnded {
            node_id: state.config.node_id.clone(),
            session: session.info,
            reason,
        })
        .await;
}

async fn session_signal(session: &mut Option<Session>) -> Signal {
    let Some(session) = session else {
        return std::future::pending().await;
    };

    tokio::select! {
        Ok(()) = &mut session.replaced => Signal::Replaced,
        Some(push) = session.pushes.recv() => Signal::Push(push),
        else => std::future::pending().await,
    }
}

fn sink_wants(wants: payload::MediaSinkWants) -> SinkWants {
    let ssrcs = wants
        .ssrcs
        .iter()
        .filter_map(|(ssrc, quality)| {
            let quality = u8::try_from(quality.as_u64()?).ok()?;
            Some((ssrc.parse().ok()?, quality))
        })
        .collect();

    SinkWants {
        any: wants.any.unwrap_or(100),
        ssrcs,
    }
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
    use super::{heartbeat_ack, sink_wants};
    use serde_json::json;

    #[test]
    fn sink_wants_from_browser() {
        let wants = serde_json::from_value(json!({
            "44346": 100,
            "any": 0,
            "pixelCounts": {"20218": 0},
        }))
        .unwrap();
        let wants = sink_wants(wants);

        assert_eq!(wants.any, 0);
        assert_eq!(wants.ssrcs.len(), 1);
        assert_eq!(wants.ssrcs[&44346], 100);
    }

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

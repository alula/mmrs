mod cipher;
mod discovery;
mod rtcp;
mod rtp;
mod stun;
mod webrtc;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;
use str0m::config::Fingerprint;
use str0m::rtp::RtpPacket;
use str0m::{IceCreds, RtcError};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::encryption::EncryptionMode;
use crate::media::cipher::Cipher;
use crate::media::discovery::{Discovery, ProtocolVersion};
use crate::media::rtcp::ReceiveStats;
use crate::media::rtp::{Packet, RTCP_HEADER_LEN, Rtp};
use crate::media::webrtc::{Dtls, WebRtcLeg};
use crate::room::RoomKey;

pub use webrtc::Offer;

const MAX_PACKET: usize = 2048;

/// Discord sends its receiver reports every second.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

const AUDIO_CLOCK_RATE: u32 = 48_000;
const VIDEO_CLOCK_RATE: u32 = 90_000;

/// How often str0m timers are checked. They pace ICE, DTLS retransmits and
/// RTCP, none of which needs finer timing; media goes out as it is written.
const TIMER_TICK: Duration = Duration::from_millis(10);

type PacketBuf = ArrayVec<u8, MAX_PACKET>;

/// The media UDP socket. Native clients and browsers share it, as on Discord.
pub struct Media {
    socket: UdpSocket,
    /// IPv4 peers must be addressed as IPv4-mapped on a dual-stack socket.
    dual_stack: bool,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    port: u16,
    /// SSRCs are unique per node, across tenants.
    next_ssrc: AtomicU32,
    legs: Mutex<Legs>,
    dtls: Dtls,
}

#[derive(Default)]
struct Legs {
    next_id: u64,
    legs: HashMap<u64, LegState>,
    /// Every SSRC handed out in READY. IP discovery is answered only for these.
    by_ssrc: HashMap<u32, u64>,
    rooms: HashMap<RoomKey, HashSet<u64>>,
    /// Local ICE ufrag of each browser leg.
    ice: HashMap<String, u64>,
    /// Browser addresses that passed an ICE check. DTLS and SRTP from them
    /// go to str0m.
    peers: HashMap<SocketAddr, u64>,
}

/// One client's side of the media plane.
struct LegState {
    room: RoomKey,
    ssrcs: Range<u32>,
    /// Where media for this client goes. Learned from IP discovery, then
    /// moved by authenticated packets, since native clients rotate sockets.
    addr: Option<SocketAddr>,
    transport: Option<Transport>,
    wants: SinkWants,
    /// What MMRS received on the leg's media SSRCs, for receiver reports.
    received: HashMap<u32, ReceiveStats>,
}

impl LegState {
    /// The first SSRC is audio; streams follow as media and RTX pairs.
    fn is_rtx(&self, ssrc: u32) -> bool {
        let offset = ssrc - self.ssrcs.start;
        offset != 0 && offset.is_multiple_of(2)
    }

    fn record_rtp(&mut self, ssrc: u32, plain: &[u8], now: Instant) {
        if self.is_rtx(ssrc) {
            return;
        }
        let seq = u16::from_be_bytes([plain[2], plain[3]]);
        let timestamp = u32::from_be_bytes(plain[4..8].try_into().unwrap());
        let clock_rate = if ssrc == self.ssrcs.start {
            AUDIO_CLOCK_RATE
        } else {
            VIDEO_CLOCK_RATE
        };
        self.received
            .entry(ssrc)
            .and_modify(|stats| stats.record(seq, timestamp, now))
            .or_insert_with(|| ReceiveStats::new(clock_rate, seq, timestamp, now));
    }

    /// Discord reports audio with the client's audio SSRC as sender and
    /// video with the first video SSRC.
    fn receiver_reports(&mut self, now: Instant) -> Option<Vec<u8>> {
        let audio = self.ssrcs.start;
        let mut ssrcs: Vec<u32> = self.received.keys().copied().collect();
        ssrcs.sort_unstable();
        let (audio_blocks, video_blocks): (Vec<_>, Vec<_>) = ssrcs
            .into_iter()
            .map(|ssrc| {
                (
                    ssrc,
                    self.received
                        .get_mut(&ssrc)
                        .unwrap()
                        .report_block(ssrc, now),
                )
            })
            .partition(|&(ssrc, _)| ssrc == audio);

        let mut compound = Vec::new();
        for (sender, blocks) in [(audio, audio_blocks), (audio + 1, video_blocks)] {
            if !blocks.is_empty() {
                let blocks: Vec<_> = blocks.into_iter().map(|(_, block)| block).collect();
                rtcp::write_rr(&mut compound, sender, &blocks);
            }
        }
        (!compound.is_empty()).then_some(compound)
    }

    /// Encrypts `plain` for this leg's client, if it has a key and an
    /// address yet.
    fn seal(&mut self, plain: &[u8], header_len: usize) -> Option<(PacketBuf, SocketAddr)> {
        let (Some(addr), Some(Transport::Udp(udp))) = (self.addr, &mut self.transport) else {
            return None;
        };
        let sealed = udp.cipher.seal(plain, header_len, udp.n4)?;
        udp.n4 = udp.n4.wrapping_add(1);
        Some((sealed, addr))
    }
}

/// What a client wants to receive (op 15). A quality of 0 means "do not
/// forward"; browsers start from `any: 0` and list each stream they want.
pub struct SinkWants {
    pub any: u8,
    pub ssrcs: HashMap<u32, u8>,
}

impl Default for SinkWants {
    fn default() -> Self {
        Self {
            any: 100,
            ssrcs: HashMap::new(),
        }
    }
}

impl SinkWants {
    fn wants(&self, ssrc: u32) -> bool {
        self.ssrcs.get(&ssrc).copied().unwrap_or(self.any) > 0
    }
}

enum Transport {
    Udp(UdpLeg),
    WebRtc(Box<WebRtcLeg>),
}

struct UdpLeg {
    cipher: Cipher,
    /// Our send counter. Never reused under this key.
    n4: u32,
}

/// A packet on its way to the other members of a room, in the native
/// format: what UDP legs receive after encryption.
struct Forward<'a> {
    ssrc: u32,
    plain: &'a [u8],
    header_len: usize,
    kind: ForwardKind,
}

#[derive(PartialEq, Eq)]
enum ForwardKind {
    Audio,
    Video,
    Rtcp,
}

impl Media {
    pub async fn bind(config: &Config) -> anyhow::Result<Arc<Self>> {
        let port = config.media_port;
        // `[::]` is dual-stack unless net.ipv6.bindv6only is set.
        let socket = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)).await {
            Ok(socket) => socket,
            Err(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?,
        };
        let bound = socket.local_addr()?;
        tracing::info!(bind = %bound, "media socket listening");
        Ok(Arc::new(Self {
            socket,
            dual_stack: bound.is_ipv6(),
            ipv4: config.media_ipv4,
            ipv6: config.media_ipv6.filter(|_| config.enable_ipv6),
            port: bound.port(),
            next_ssrc: AtomicU32::new(100),
            legs: Mutex::default(),
            dtls: Dtls::generate(),
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address to hand a client that reached the gateway from `client`.
    pub fn ip_for(&self, client: SocketAddr) -> IpAddr {
        match (self.ipv6, client.ip().to_canonical()) {
            (Some(ipv6), IpAddr::V6(_)) => IpAddr::V6(ipv6),
            _ => IpAddr::V4(self.ipv4),
        }
    }

    pub async fn run(self: Arc<Self>) {
        let mut buf = [0; MAX_PACKET];
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(error) => {
                    tracing::debug!(%error, "media recv failed");
                    continue;
                }
            };
            self.handle(&buf[..len], from);
        }
    }

    fn handle(&self, packet: &[u8], from: SocketAddr) {
        // Dual-stack sockets report IPv4 peers as `::ffff:a.b.c.d`.
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());

        if self.receive_webrtc(packet, from) {
            return;
        }
        if let Some(request) = Discovery::parse_request(packet) {
            self.discovery(request.ssrc, request.protocol_version, from);
        } else if stun::is_stun(packet) {
            self.receive_stun(packet, from);
        } else if packet.len() == 8 {
            // Native and discord.js keepalives. Clients take any 8 byte
            // datagram as the reply, so media must never be 8 bytes long.
            self.send(packet, from);
        } else if let Some(Packet::Rtp { ssrc, header_len }) = Packet::classify(packet) {
            self.forward_rtp(ssrc, header_len, packet, from);
        } else if let Some(Packet::Rtcp { ssrc }) = Packet::classify(packet) {
            self.receive_rtcp(ssrc, packet, from);
        } else {
            tracing::trace!(len = packet.len(), %from, "dropping media packet");
        }
    }

    fn send(&self, packet: &[u8], to: SocketAddr) {
        let to = match to {
            SocketAddr::V4(v4) if self.dual_stack => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            to => to,
        };
        if let Err(error) = self.socket.try_send_to(packet, to) {
            tracing::trace!(%error, %to, "media send failed");
        }
    }

    fn discovery(&self, ssrc: u32, version: ProtocolVersion, from: SocketAddr) {
        {
            let mut legs = self.legs.lock().unwrap();
            let Some(&id) = legs.by_ssrc.get(&ssrc) else {
                return;
            };
            let leg = legs.legs.get_mut(&id).expect("indexed leg exists");
            leg.addr.get_or_insert(from);
        }

        tracing::debug!(ssrc, %from, "ip discovery");
        match version {
            ProtocolVersion::V1 => self.send(&Discovery::make_response_v1(ssrc, from), from),
            ProtocolVersion::V2 => self.send(&Discovery::make_response_v2(ssrc, from), from),
        }
    }

    fn forward_rtp(&self, ssrc: u32, header_len: usize, packet: &[u8], from: SocketAddr) {
        let mut guard = self.legs.lock().unwrap();
        let Legs {
            legs,
            by_ssrc,
            rooms,
            ..
        } = &mut *guard;

        let Some(&sender_id) = by_ssrc.get(&ssrc) else {
            return;
        };
        let Some(plain) = authenticate(legs, sender_id, packet, header_len, from) else {
            return;
        };
        let now = Instant::now();
        let sender = legs.get_mut(&sender_id).expect("indexed leg exists");
        sender.record_rtp(ssrc, &plain, now);
        let kind = if ssrc == sender.ssrcs.start {
            ForwardKind::Audio
        } else {
            ForwardKind::Video
        };
        let Some(members) = rooms.get(&sender.room) else {
            return;
        };

        let forward = Forward {
            ssrc,
            plain: &plain,
            header_len,
            kind,
        };
        let mut received = Vec::new();
        self.fan_out(legs, members, sender_id, &forward, &mut received);
        self.forward_browser_rtp(&mut guard, received);
    }

    /// Sends a packet to every other member of the room that wants its
    /// SSRC. Browser legs only get audio so far. Opus their browsers sent
    /// meanwhile lands in `received`.
    fn fan_out(
        &self,
        legs: &mut HashMap<u64, LegState>,
        members: &HashSet<u64>,
        sender_id: u64,
        forward: &Forward,
        received: &mut Vec<(u64, RtpPacket)>,
    ) {
        let audio = match forward.kind {
            ForwardKind::Audio => Rtp::parse(forward.plain),
            _ => None,
        };
        for &id in members.iter().filter(|&&id| id != sender_id) {
            let leg = legs.get_mut(&id).expect("room member exists");
            if !leg.wants.wants(forward.ssrc) {
                continue;
            }
            if let Some(Transport::WebRtc(webrtc)) = &mut leg.transport {
                if let Some(rtp) = &audio {
                    webrtc.send_audio(forward.ssrc, rtp, Instant::now());
                    self.poll_webrtc(webrtc, id, received);
                }
            } else if let Some((sealed, addr)) = leg.seal(forward.plain, forward.header_len) {
                self.send(&sealed, addr);
            }
        }
    }

    /// Runs str0m for a browser leg: sends what it wants sent and collects
    /// the Opus its browser sent.
    fn poll_webrtc(&self, webrtc: &mut WebRtcLeg, id: u64, received: &mut Vec<(u64, RtpPacket)>) {
        webrtc.poll(
            |datagram, to| self.send(datagram, to),
            |packet| received.push((id, packet)),
        );
    }

    /// Forwards browser audio as native Opus from the leg's own SSRC, so
    /// every SSRC in a room is one MMRS handed out.
    fn forward_browser_rtp(&self, legs: &mut Legs, mut received: Vec<(u64, RtpPacket)>) {
        let Legs { legs, rooms, .. } = legs;
        while let Some((sender_id, packet)) = received.pop() {
            let Some(sender) = legs.get(&sender_id) else {
                continue;
            };
            let ssrc = sender.ssrcs.start;
            let Some((plain, header_len)) = rtp::audio_packet(
                ssrc,
                packet.header.sequence_number,
                packet.header.timestamp,
                packet.header.marker,
                webrtc::native_audio_level(&packet),
                &packet.payload,
            ) else {
                continue;
            };
            let Some(members) = rooms.get(&sender.room) else {
                continue;
            };

            let forward = Forward {
                ssrc,
                plain: &plain,
                header_len,
                kind: ForwardKind::Audio,
            };
            self.fan_out(legs, members, sender_id, &forward, &mut received);
        }
    }

    /// Browsers ICE-check with the ufrag MMRS handed out. Once one proves
    /// the password, everything from its address goes to its leg.
    fn receive_stun(&self, packet: &[u8], from: SocketAddr) {
        let Some(request) = stun::BindingRequest::parse(packet) else {
            return;
        };
        let mut guard = self.legs.lock().unwrap();
        let Some(&id) = guard.ice.get(request.local_ufrag()) else {
            return;
        };
        let Some(LegState {
            transport: Some(Transport::WebRtc(webrtc)),
            ..
        }) = guard.legs.get_mut(&id)
        else {
            return;
        };
        if !request.verify(&webrtc.local_ice.pass) {
            tracing::debug!(%from, "ice check with bad credentials");
            return;
        }

        tracing::debug!(ufrag = request.local_ufrag(), %from, "ice peer");
        webrtc.peers.push(from);
        guard.peers.insert(from, id);
        drop(guard);
        self.receive_webrtc(packet, from);
    }

    fn receive_webrtc(&self, packet: &[u8], from: SocketAddr) -> bool {
        let mut guard = self.legs.lock().unwrap();
        let Some(&id) = guard.peers.get(&from) else {
            return false;
        };
        let Some(LegState {
            transport: Some(Transport::WebRtc(webrtc)),
            ..
        }) = guard.legs.get_mut(&id)
        else {
            return false;
        };

        let now = Instant::now();
        webrtc.receive(packet, from, now);
        let mut received = Vec::new();
        self.poll_webrtc(webrtc, id, &mut received);
        self.forward_browser_rtp(&mut guard, received);
        true
    }

    pub async fn tick(self: Arc<Self>) {
        let mut interval = tokio::time::interval(TIMER_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.expire_timers(Instant::now());
        }
    }

    fn expire_timers(&self, now: Instant) {
        let mut guard = self.legs.lock().unwrap();
        let mut received = Vec::new();
        for (&id, leg) in &mut guard.legs {
            let Some(Transport::WebRtc(webrtc)) = &mut leg.transport else {
                continue;
            };
            if webrtc.is_alive() && webrtc.timeout <= now {
                webrtc.handle_timeout(now);
                self.poll_webrtc(webrtc, id, &mut received);
            }
        }
        self.forward_browser_rtp(&mut guard, received);
    }

    /// RTCP is terminated per leg: sender reports go on to receivers
    /// without their report blocks, NACK and PLI go to the leg that owns
    /// the media SSRC, everything else stops here.
    fn receive_rtcp(&self, ssrc: u32, packet: &[u8], from: SocketAddr) {
        let mut guard = self.legs.lock().unwrap();
        let Legs {
            legs,
            by_ssrc,
            rooms,
            ..
        } = &mut *guard;

        let Some(&sender_id) = by_ssrc.get(&ssrc) else {
            return;
        };
        let Some(plain) = authenticate(legs, sender_id, packet, RTCP_HEADER_LEN, from) else {
            return;
        };
        let room = legs[&sender_id].room.clone();
        let now = Instant::now();

        for packet in rtcp::packets(&plain) {
            match (rtcp::packet_type(packet), rtcp::count(packet)) {
                (rtcp::SR, _) => {
                    let Some(ssrc) = rtcp::sender_ssrc(packet)
                        .filter(|ssrc| by_ssrc.get(ssrc) == Some(&sender_id))
                    else {
                        continue;
                    };
                    let (Some(ntp_middle), Some(stripped)) = (
                        rtcp::sr_ntp_middle(packet),
                        rtcp::strip_report_blocks(packet),
                    ) else {
                        continue;
                    };
                    let sender = legs.get_mut(&sender_id).expect("indexed leg exists");
                    if let Some(stats) = sender.received.get_mut(&ssrc) {
                        stats.record_sr(ntp_middle, now);
                    }
                    if let Some(members) = rooms.get(&room) {
                        let forward = Forward {
                            ssrc,
                            plain: &stripped,
                            header_len: RTCP_HEADER_LEN,
                            kind: ForwardKind::Rtcp,
                        };
                        self.fan_out(legs, members, sender_id, &forward, &mut Vec::new());
                    }
                }
                (rtcp::RTPFB, rtcp::FMT_NACK) | (rtcp::PSFB, rtcp::FMT_PLI) => {
                    let Some(&owner_id) =
                        rtcp::media_ssrc(packet).and_then(|ssrc| by_ssrc.get(&ssrc))
                    else {
                        continue;
                    };
                    let owner = legs.get_mut(&owner_id).expect("indexed leg exists");
                    if owner_id == sender_id || owner.room != room {
                        continue;
                    }
                    if let Some((sealed, addr)) = owner.seal(packet, RTCP_HEADER_LEN) {
                        self.send(&sealed, addr);
                    }
                }
                _ => {}
            }
        }
    }

    pub async fn report(self: Arc<Self>) {
        let mut interval = tokio::time::interval(REPORT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.send_reports(Instant::now());
        }
    }

    fn send_reports(&self, now: Instant) {
        let mut legs = self.legs.lock().unwrap();
        for leg in legs.legs.values_mut() {
            let Some(compound) = leg.receiver_reports(now) else {
                continue;
            };
            if let Some((sealed, addr)) = leg.seal(&compound, RTCP_HEADER_LEN) {
                self.send(&sealed, addr);
            }
        }
    }

    /// Allocates `count` consecutive SSRCs, none of them 0, for a client in
    /// `room`.
    pub fn open_leg(self: &Arc<Self>, room: RoomKey, count: u32) -> Leg {
        let first = allocate(&self.next_ssrc, count);
        let ssrcs = first..first + count;

        let mut legs = self.legs.lock().unwrap();
        let id = legs.next_id;
        legs.next_id += 1;

        legs.by_ssrc.extend(ssrcs.clone().map(|ssrc| (ssrc, id)));
        legs.rooms.entry(room.clone()).or_default().insert(id);
        legs.legs.insert(
            id,
            LegState {
                room,
                ssrcs: ssrcs.clone(),
                addr: None,
                transport: None,
                wants: SinkWants::default(),
                received: HashMap::new(),
            },
        );

        Leg {
            media: self.clone(),
            id,
            first_ssrc: first,
        }
    }
}

/// Decrypts a packet from the leg's client and moves the leg's address to
/// the sender, which only someone holding the key can do.
fn authenticate(
    legs: &mut HashMap<u64, LegState>,
    id: u64,
    packet: &[u8],
    header_len: usize,
    from: SocketAddr,
) -> Option<PacketBuf> {
    let leg = legs.get_mut(&id).expect("indexed leg exists");
    let Some(Transport::Udp(udp)) = &leg.transport else {
        return None;
    };
    let plain = udp.cipher.open(packet, header_len)?;

    if leg.addr != Some(from) {
        tracing::debug!(old = ?leg.addr, new = %from, "media address moved");
        leg.addr = Some(from);
    }
    Some(plain)
}

/// Removes the leg from the media plane when dropped.
pub struct Leg {
    media: Arc<Media>,
    id: u64,
    first_ssrc: u32,
}

impl Leg {
    pub fn first_ssrc(&self) -> u32 {
        self.first_ssrc
    }

    /// Switches the leg to the `udp` protocol and returns the new key.
    pub fn select_udp(&self, mode: EncryptionMode) -> [u8; 32] {
        let mut key = [0; 32];
        getrandom::fill(&mut key).expect("system RNG");

        let mut legs = self.media.legs.lock().unwrap();
        let leg = legs.legs.get_mut(&self.id).expect("open leg exists");
        leg.transport = Some(Transport::Udp(UdpLeg {
            cipher: Cipher::new(mode, &key),
            n4: 0,
        }));
        key
    }
}

impl Leg {
    /// Switches the leg to the `webrtc` protocol, reachable at `ip`, and
    /// returns the SDP for op 4.
    pub fn select_webrtc(&self, offer: Offer, ip: IpAddr) -> Result<String, RtcError> {
        let local = SocketAddr::new(ip, self.media.port);
        let mut legs = self.media.legs.lock().unwrap();
        let ufrag = loop {
            let ufrag = ice_chars(4);
            if !legs.ice.contains_key(&ufrag) {
                break ufrag;
            }
        };
        let ice = IceCreds {
            ufrag,
            pass: ice_chars(22),
        };

        let webrtc = WebRtcLeg::new(&self.media.dtls, local, ice.clone(), offer, Instant::now())?;
        legs.ice.insert(ice.ufrag.clone(), self.id);
        let leg = legs.legs.get_mut(&self.id).expect("open leg exists");
        leg.transport = Some(Transport::WebRtc(Box::new(webrtc)));

        Ok(sdp_answer(local, &ice, &self.media.dtls.fingerprint))
    }

    pub fn set_wants(&self, wants: SinkWants) {
        let mut legs = self.media.legs.lock().unwrap();
        legs.legs.get_mut(&self.id).expect("open leg exists").wants = wants;
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        let mut guard = self.media.legs.lock().unwrap();
        let legs = &mut *guard;
        let Some(leg) = legs.legs.remove(&self.id) else {
            return;
        };

        if let Some(Transport::WebRtc(webrtc)) = &leg.transport {
            legs.ice.remove(&webrtc.local_ice.ufrag);
            for peer in &webrtc.peers {
                legs.peers.remove(peer);
            }
        }
        for ssrc in leg.ssrcs.clone() {
            legs.by_ssrc.remove(&ssrc);
        }
        if let Some(members) = legs.rooms.get_mut(&leg.room) {
            members.remove(&self.id);
            for id in members.iter() {
                let member = legs.legs.get_mut(id).expect("room member exists");
                if let Some(Transport::WebRtc(webrtc)) = &mut member.transport {
                    webrtc.forget(leg.ssrcs.clone());
                }
            }
            if members.is_empty() {
                legs.rooms.remove(&leg.room);
            }
        }
    }
}

/// The transport-only template the web client builds its remote description
/// from (webrtc.md 4.1).
fn sdp_answer(local: SocketAddr, ice: &IceCreds, fingerprint: &Fingerprint) -> String {
    let (ip, port) = (local.ip(), local.port());
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
         a=fingerprint:{fingerprint}\n\
         a=candidate:1 1 UDP 2130706431 {ip} {port} typ host\n",
        ufrag = ice.ufrag,
        pwd = ice.pass,
    );
}

/// Random `ice-char`s (RFC 8839: ALPHA / DIGIT / "+" / "/").
fn ice_chars(count: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = vec![0; count];
    getrandom::fill(&mut bytes).expect("system RNG");
    bytes
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(b % 64)]))
        .collect()
}

fn allocate(next: &AtomicU32, count: u32) -> u32 {
    loop {
        let first = next.fetch_add(count, Ordering::Relaxed);

        if first != 0 && first.checked_add(count).is_some() {
            return first;
        }
    }
}

#[cfg(test)]
mod tests;

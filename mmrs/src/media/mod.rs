mod cipher;
mod discovery;
mod rtp;
mod stun;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use arrayvec::ArrayVec;
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::encryption::EncryptionMode;
use crate::media::cipher::Cipher;
use crate::media::discovery::{Discovery, ProtocolVersion};
use crate::media::rtp::{Packet, RTCP_HEADER_LEN};
use crate::room::RoomKey;

const MAX_PACKET: usize = 2048;

type PacketBuf = ArrayVec<u8, MAX_PACKET>;

const DTLS_FINGERPRINT_PLACEHOLDER: &str = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

/// The media UDP socket. Native clients and browsers share it, as on Discord.
pub struct Media {
    socket: UdpSocket,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    port: u16,
    /// SSRCs are unique per node, across tenants.
    next_ssrc: AtomicU32,
    legs: Mutex<Legs>,
    /// Local ICE ufrag to credentials of a webrtc session.
    ice: Mutex<HashMap<String, IceEntry>>,
}

#[derive(Default)]
struct Legs {
    next_id: u64,
    legs: HashMap<u64, LegState>,
    /// Every SSRC handed out in READY. IP discovery is answered only for these.
    by_ssrc: HashMap<u32, u64>,
    rooms: HashMap<RoomKey, HashSet<u64>>,
}

/// One client's side of the media plane.
struct LegState {
    room: RoomKey,
    ssrcs: Range<u32>,
    /// Where media for this client goes. Learned from IP discovery, then
    /// moved by authenticated packets, since native clients rotate sockets.
    addr: Option<SocketAddr>,
    udp: Option<UdpLeg>,
    wants: SinkWants,
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

struct UdpLeg {
    cipher: Cipher,
    /// Our send counter. Never reused under this key.
    n4: u32,
}

struct IceEntry {
    password: String,
    peer: Option<SocketAddr>,
}

impl Media {
    pub async fn bind(config: &Config) -> anyhow::Result<Arc<Self>> {
        let port = config.media_port;
        // `[::]` is dual-stack unless net.ipv6.bindv6only is set.
        let socket = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)).await {
            Ok(socket) => socket,
            Err(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?,
        };
        tracing::info!(bind = %socket.local_addr()?, "media socket listening");
        Ok(Arc::new(Self {
            socket,
            ipv4: config.media_ipv4,
            ipv6: config.media_ipv6.filter(|_| config.enable_ipv6),
            port,
            next_ssrc: AtomicU32::new(100),
            legs: Mutex::default(),
            ice: Mutex::default(),
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
        if let Some(request) = Discovery::parse_request(packet) {
            self.discovery(request.ssrc, request.protocol_version, from);
        } else if stun::is_stun(packet) {
            if let Some(reply) = self.ice_binding(packet, from) {
                self.send(&reply, from);
            }
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
        let Some(members) = rooms.get(&legs[&sender_id].room) else {
            return;
        };

        for &id in members.iter().filter(|&&id| id != sender_id) {
            let leg = legs.get_mut(&id).expect("room member exists");
            if !leg.wants.wants(ssrc) {
                continue;
            }
            let (Some(addr), Some(udp)) = (leg.addr, &mut leg.udp) else {
                continue;
            };
            let Some(sealed) = udp.cipher.seal(&plain, header_len, udp.n4) else {
                continue;
            };
            udp.n4 = udp.n4.wrapping_add(1);
            self.send(&sealed, addr);
        }
    }

    fn receive_rtcp(&self, ssrc: u32, packet: &[u8], from: SocketAddr) {
        let mut legs = self.legs.lock().unwrap();
        let Some(&id) = legs.by_ssrc.get(&ssrc) else {
            return;
        };
        authenticate(&mut legs.legs, id, packet, RTCP_HEADER_LEN, from);
    }

    fn ice_binding(&self, packet: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let request = stun::BindingRequest::parse(packet)?;
        let mut ice = self.ice.lock().unwrap();
        let entry = ice.get_mut(request.local_ufrag())?;
        if !request.verify(&entry.password) {
            tracing::debug!(%from, "ice binding with bad credentials");
            return None;
        }
        if entry.peer != Some(from) {
            tracing::info!(ufrag = request.local_ufrag(), %from, "ice connected");
            entry.peer = Some(from);
        }
        Some(stun::binding_success(
            &request.transaction_id,
            from,
            &entry.password,
        ))
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
                udp: None,
                wants: SinkWants::default(),
            },
        );

        Leg {
            media: self.clone(),
            id,
            first_ssrc: first,
        }
    }

    pub fn lease_ice(self: &Arc<Self>) -> IceLease {
        let mut ice = self.ice.lock().unwrap();
        let ufrag = loop {
            let ufrag = ice_chars(4);
            if !ice.contains_key(&ufrag) {
                break ufrag;
            }
        };
        let password = ice_chars(22);
        ice.insert(
            ufrag.clone(),
            IceEntry {
                password: password.clone(),
                peer: None,
            },
        );
        IceLease {
            media: self.clone(),
            ufrag,
            password,
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
    let plain = leg.udp.as_ref()?.cipher.open(packet, header_len)?;

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
        leg.udp = Some(UdpLeg {
            cipher: Cipher::new(mode, &key),
            n4: 0,
        });
        key
    }
}

impl Leg {
    pub fn set_wants(&self, wants: SinkWants) {
        let mut legs = self.media.legs.lock().unwrap();
        legs.legs.get_mut(&self.id).expect("open leg exists").wants = wants;
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        let mut legs = self.media.legs.lock().unwrap();
        let Some(leg) = legs.legs.remove(&self.id) else {
            return;
        };

        for ssrc in leg.ssrcs {
            legs.by_ssrc.remove(&ssrc);
        }
        if let Some(members) = legs.rooms.get_mut(&leg.room) {
            members.remove(&self.id);
            if members.is_empty() {
                legs.rooms.remove(&leg.room);
            }
        }
    }
}

pub struct IceLease {
    media: Arc<Media>,
    pub ufrag: String,
    pub password: String,
}

impl IceLease {
    /// The transport-only template the web client builds its remote
    /// description from.
    pub fn sdp_answer(&self, ip: IpAddr) -> String {
        let port = self.media.port;
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
            ufrag = self.ufrag,
            pwd = self.password,
        );
    }
}

impl Drop for IceLease {
    fn drop(&mut self) {
        self.media.ice.lock().unwrap().remove(&self.ufrag);
    }
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
mod tests {
    use super::*;

    #[test]
    fn sink_wants_default_to_any() {
        let wants = SinkWants {
            any: 0,
            ssrcs: HashMap::from([(7, 100), (8, 0)]),
        };
        assert!(wants.wants(7));
        assert!(!wants.wants(8));
        assert!(!wants.wants(9));
        assert!(SinkWants::default().wants(9));
    }

    #[test]
    fn ssrc_blocks_skip_zero() {
        let next = AtomicU32::new(u32::MAX - 1);
        let first = allocate(&next, 3);

        assert!(first >= 1 && first.checked_add(3).is_some());
    }

    fn config() -> Config {
        Config {
            node_id: "n".into(),
            voice_bind: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            media_ipv4: Ipv4Addr::LOCALHOST,
            media_ipv6: None,
            media_port: 0,
            enable_ipv6: false,
            min_gateway_version: 1,
            encryption_modes: EncryptionMode::DEFAULT.to_vec(),
            region: None,
            capacity: None,
            tenants: Vec::new(),
        }
    }

    async fn recv(socket: &UdpSocket) -> Vec<u8> {
        let mut buf = [0; MAX_PACKET];
        let len = tokio::time::timeout(std::time::Duration::from_secs(1), socket.recv(&mut buf))
            .await
            .expect("datagram within a second")
            .unwrap();
        buf[..len].to_vec()
    }

    #[tokio::test]
    async fn forwards_rtp_between_udp_legs() {
        let media = Media::bind(&config()).await.unwrap();
        let port = media.socket.local_addr().unwrap().port();
        tokio::spawn(media.clone().run());

        let room = RoomKey {
            tenant: "t".into(),
            room: "r".into(),
        };
        let a = media.open_leg(room.clone(), 3);
        let b = media.open_leg(room, 3);
        let mode = EncryptionMode::AeadAes256GcmRtpsize;
        let a_cipher = Cipher::new(mode, &a.select_udp(mode));
        let b_cipher = Cipher::new(mode, &b.select_udp(mode));

        let mut sockets = Vec::new();
        for leg in [&a, &b] {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            socket.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();

            let mut request = [0; 74];
            request[..4].copy_from_slice(&[0, 1, 0, 70]);
            request[4..8].copy_from_slice(&leg.first_ssrc().to_be_bytes());
            socket.send(&request).await.unwrap();
            assert_eq!(recv(&socket).await[..2], [0, 2]);
            sockets.push(socket);
        }

        let ping = [0x13, 0x37, 0xca, 0xfe, 1, 0, 0, 0];
        sockets[0].send(&ping).await.unwrap();
        assert_eq!(recv(&sockets[0]).await, ping);

        let mut rtp = vec![0x80, 0x78, 0, 1, 0, 0, 0x03, 0xc0];
        rtp.extend_from_slice(&a.first_ssrc().to_be_bytes());
        rtp.extend_from_slice(&[0xf8, 0xff, 0xfe]);
        let sealed = a_cipher.seal(&rtp, 12, 7).unwrap();
        sockets[0].send(&sealed).await.unwrap();

        let forwarded = recv(&sockets[1]).await;
        assert_eq!(forwarded[forwarded.len() - 4..], [0, 0, 0, 0]);
        assert_eq!(b_cipher.open(&forwarded, 12).unwrap().as_slice(), rtp);
    }
}

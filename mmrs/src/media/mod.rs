mod discovery;
mod stun;

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;

use crate::media::discovery::{Discovery, ProtocolVersion};

/// The media UDP socket. Native clients and browsers share it, as on Discord.
pub struct Media {
    socket: UdpSocket,
    /// SSRCs are unique per node, across tenants.
    next_ssrc: AtomicU32,
    /// SSRCs handed out in READY; IP discovery is answered only for these.
    ssrcs: Mutex<HashSet<u32>>,
    /// Local ICE ufrag to credentials of a webrtc session.
    ice: Mutex<HashMap<String, IceEntry>>,
}

struct IceEntry {
    password: String,
    peer: Option<SocketAddr>,
}

impl Media {
    pub async fn bind(port: u16) -> anyhow::Result<Arc<Self>> {
        // `[::]` is dual-stack unless net.ipv6.bindv6only is set.
        let socket = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)).await {
            Ok(socket) => socket,
            Err(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?,
        };
        tracing::info!(bind = %socket.local_addr()?, "media socket listening");
        Ok(Arc::new(Self {
            socket,
            next_ssrc: AtomicU32::new(100),
            ssrcs: Mutex::default(),
            ice: Mutex::default(),
        }))
    }

    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0; 2048];
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(error) => {
                    tracing::debug!(%error, "media recv failed");
                    continue;
                }
            };
            if let Some(reply) = self.handle(&buf[..len], from)
                && let Err(error) = self.socket.send_to(&reply, from).await
            {
                tracing::debug!(%error, %from, "media send failed");
            }
        }
    }

    fn handle(&self, packet: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        if let Some(request) = Discovery::parse_request(packet) {
            if !self.ssrcs.lock().unwrap().contains(&request.ssrc) {
                return None;
            }

            tracing::debug!(request.ssrc, %from, "ip discovery");
            let data = match request.protocol_version {
                ProtocolVersion::V1 => Discovery::make_response_v1(request.ssrc, from).to_vec(),
                ProtocolVersion::V2 => Discovery::make_response_v2(request.ssrc, from).to_vec(),
            };

            return Some(data);
        }
        if stun::is_stun(packet) {
            return self.ice_binding(packet, from);
        }
        tracing::trace!(len = packet.len(), %from, "dropping media packet");
        None
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

    pub fn lease_ssrcs(self: &Arc<Self>, count: u32) -> SsrcLease {
        let first = allocate(&self.next_ssrc, count);
        let range = first..first + count;
        self.ssrcs.lock().unwrap().extend(range.clone());
        SsrcLease {
            media: self.clone(),
            range,
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

pub struct SsrcLease {
    media: Arc<Media>,
    range: Range<u32>,
}

impl SsrcLease {
    pub fn first(&self) -> u32 {
        self.range.start
    }
}

impl Drop for SsrcLease {
    fn drop(&mut self) {
        let mut ssrcs = self.media.ssrcs.lock().unwrap();
        for ssrc in self.range.clone() {
            ssrcs.remove(&ssrc);
        }
    }
}

pub struct IceLease {
    media: Arc<Media>,
    pub ufrag: String,
    pub password: String,
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
    fn ssrc_blocks_skip_zero() {
        let next = AtomicU32::new(u32::MAX - 1);
        let first = allocate(&next, 3);

        assert!(first >= 1 && first.checked_add(3).is_some());
    }
}

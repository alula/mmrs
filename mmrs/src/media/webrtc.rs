use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};
use str0m::config::{CryptoProvider, DtlsCert, Fingerprint};
use str0m::format::{Codec, FormatParams};
use str0m::media::{Frequency, MediaKind, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{Extension, ExtensionValues, RtpPacket, RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcError};

use crate::media::rtp::{AUDIO_LEVEL_EXTENSION, Packet, Rtp};

const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

/// The browser builds its own SDP answer, so mids never reach the wire and
/// one media holds every stream.
fn audio_mid() -> Mid {
    Mid::from("0")
}

/// The node's DTLS identity. Discord uses one certificate per media server.
pub struct Dtls {
    provider: Arc<CryptoProvider>,
    cert: DtlsCert,
    pub fingerprint: Fingerprint,
}

impl Dtls {
    pub fn generate() -> Self {
        let provider = str0m::crypto::from_feature_flags();
        let cert = provider
            .dtls_provider
            .generate_certificate()
            .expect("crypto provider generates certificates");
        let fingerprint = Fingerprint {
            hash_func: "sha-256".into(),
            bytes: Sha256::digest(&cert.certificate).to_vec(),
        };
        Self {
            provider: Arc::new(provider),
            cert,
            fingerprint,
        }
    }
}

/// What MMRS needs from the SDP fragment of a webrtc SELECT_PROTOCOL.
pub struct Offer {
    ice: IceCreds,
    fingerprint: Fingerprint,
    opus: Pt,
    audio_level: Option<u8>,
    transport_cc: Option<u8>,
}

impl Offer {
    pub fn parse(fragment: &str) -> Option<Self> {
        let (mut ufrag, mut pass, mut fingerprint, mut opus) = (None, None, None, None);
        let (mut audio_level, mut transport_cc) = (None, None);

        for line in fragment.lines() {
            let Some(attribute) = line.trim().strip_prefix("a=") else {
                continue;
            };
            let Some((name, value)) = attribute.split_once(':') else {
                continue;
            };
            match name {
                "ice-ufrag" => ufrag = Some(value),
                "ice-pwd" => pass = Some(value),
                "fingerprint" => fingerprint = value.parse::<Fingerprint>().ok(),
                "rtpmap" => {
                    let Some((pt, codec)) = value.split_once(' ') else {
                        continue;
                    };
                    if codec.to_ascii_lowercase().starts_with("opus/") {
                        opus = pt.parse::<u8>().ok();
                    }
                }
                "extmap" => {
                    let Some((id, uri)) = value.split_once(' ') else {
                        continue;
                    };
                    // `<id>[/<direction>]`
                    let Some(id) = id.split('/').next().and_then(|id| id.parse().ok()) else {
                        continue;
                    };
                    match uri.split_whitespace().next() {
                        Some(AUDIO_LEVEL_URI) => audio_level = Some(id),
                        Some(TRANSPORT_CC_URI) => transport_cc = Some(id),
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        Some(Self {
            ice: IceCreds {
                ufrag: ufrag?.to_owned(),
                pass: pass?.to_owned(),
            },
            fingerprint: fingerprint.filter(|f| f.hash_func == "sha-256")?,
            opus: Pt::new_with_value(opus?),
            audio_level,
            transport_cc,
        })
    }
}

pub struct WebRtcLeg {
    rtc: Rtc,
    /// The host candidate; str0m matches it against each datagram's
    /// destination.
    local: SocketAddr,
    pub local_ice: IceCreds,
    opus: Pt,
    /// The browser picks its own audio SSRC.
    audio_rx: Option<Ssrc>,
    /// Extended sequence number last sent per forwarded SSRC.
    tx: HashMap<u32, u64>,
    pub timeout: Instant,
    /// Addresses that proved the ICE password, routed to this leg.
    pub peers: Vec<SocketAddr>,
}

impl WebRtcLeg {
    /// An ICE-lite, DTLS-passive endpoint, as the browser's fabricated
    /// answer (`a=setup:passive`) expects.
    pub fn new(
        dtls: &Dtls,
        local: SocketAddr,
        local_ice: IceCreds,
        offer: Offer,
        now: Instant,
    ) -> Result<Self, RtcError> {
        let mut config = Rtc::builder()
            .set_crypto_provider(dtls.provider.clone())
            .set_dtls_cert(dtls.cert.clone())
            .set_local_ice_credentials(local_ice.clone())
            .set_ice_lite(true)
            .set_rtp_mode(true)
            .clear_codecs()
            .clear_extension_map();

        config.codec_config().add_config(
            offer.opus,
            None,
            Codec::Opus,
            Frequency::FORTY_EIGHT_KHZ,
            Some(2),
            FormatParams {
                min_p_time: Some(10),
                use_inband_fec: Some(true),
                ..Default::default()
            },
        );

        if let Some(id) = offer.audio_level {
            config = config.set_extension(id, Extension::AudioLevel);
        }
        if let Some(id) = offer.transport_cc {
            config = config.set_extension(id, Extension::TransportSequenceNumber);
        }

        let mut rtc = config.build(now);
        rtc.add_local_candidate(Candidate::host(local, "udp")?);

        let mut api = rtc.direct_api();
        api.set_remote_ice_credentials(offer.ice);
        api.set_remote_fingerprint(offer.fingerprint);
        api.start_dtls(false)?;
        api.declare_media(audio_mid(), MediaKind::Audio);

        if offer.transport_cc.is_some() {
            api.enable_twcc_feedback();
        }

        Ok(Self {
            rtc,
            local,
            local_ice,
            opus: offer.opus,
            audio_rx: None,
            tx: HashMap::new(),
            timeout: now,
            peers: Vec::new(),
        })
    }

    pub fn is_alive(&self) -> bool {
        self.rtc.is_alive()
    }

    pub fn receive(&mut self, datagram: &[u8], source: SocketAddr, now: Instant) {
        if let Some(Packet::Rtp { ssrc, .. }) = Packet::classify(datagram) {
            self.expect_audio(ssrc.into(), datagram[1] & 0x7f);
        }

        let Ok(receive) = Receive::new(Protocol::Udp, source, self.local, datagram) else {
            return;
        };

        if let Err(error) = self.rtc.handle_input(Input::Receive(now, receive)) {
            tracing::debug!(%error, %source, "webrtc input failed");
        }
    }

    fn expect_audio(&mut self, ssrc: Ssrc, payload_type: u8) {
        if payload_type != *self.opus || self.audio_rx == Some(ssrc) {
            return;
        }
        let mut api = self.rtc.direct_api();
        if let Some(old) = self.audio_rx.replace(ssrc) {
            api.remove_stream_rx(old);
        }
        api.expect_stream_rx(ssrc, None, audio_mid(), None);
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if let Err(error) = self.rtc.handle_input(Input::Timeout(now)) {
            tracing::debug!(%error, "webrtc timeout failed");
        }
    }

    pub fn poll(
        &mut self,
        mut transmit: impl FnMut(&[u8], SocketAddr),
        mut receive: impl FnMut(RtpPacket),
    ) {
        while self.rtc.is_alive() {
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => {
                    self.timeout = at;
                    return;
                }
                Ok(Output::Transmit(datagram)) => {
                    transmit(&datagram.contents, datagram.destination);
                }
                Ok(Output::Event(Event::RtpPacket(packet))) => {
                    if packet.header.payload_type == self.opus {
                        receive(packet);
                    }
                }
                Ok(Output::Event(Event::IceConnectionStateChange(state))) => {
                    tracing::debug!(?state, "webrtc ice state");
                }
                Ok(Output::Event(Event::Connected)) => tracing::info!("webrtc connected"),
                Ok(Output::Event(_)) => {}
                Err(error) => {
                    tracing::debug!(%error, "webrtc failed");
                    self.rtc.disconnect();
                }
            }
        }
    }

    /// Forwards a native-format Opus packet under `ssrc`.
    pub fn send_audio(&mut self, ssrc: u32, rtp: &Rtp, now: Instant) {
        let last = self.tx.entry(ssrc).or_insert(u64::from(rtp.seq));
        let seq = extend_seq(*last, rtp.seq);
        *last = (*last).max(seq);

        let level = rtp.extension(AUDIO_LEVEL_EXTENSION).map(|level| level[0]);
        let ext_vals = ExtensionValues {
            audio_level: level.map(|level| -((level & 0x7f) as i8)),
            voice_activity: level.map(|level| level & 0x80 != 0),
            ..Default::default()
        };
        let write = RtpWrite::new(
            self.opus,
            seq.into(),
            rtp.timestamp,
            now,
            rtp.payload.to_vec(),
        )
        .marker(rtp.marker)
        .ext_vals(ext_vals);

        let mut api = self.rtc.direct_api();
        let ssrc = Ssrc::from(ssrc);
        if api.stream_tx(&ssrc).is_none() {
            api.declare_stream_tx(ssrc, None, audio_mid(), None);
        }
        if let Some(stream) = api.stream_tx(&ssrc) {
            stream.write_rtp(write);
        }
    }

    /// Stops the streams of a peer that left.
    pub fn forget(&mut self, ssrcs: impl Iterator<Item = u32>) {
        let mut api = self.rtc.direct_api();
        for ssrc in ssrcs {
            if self.tx.remove(&ssrc).is_some() {
                api.remove_stream_tx(ssrc.into());
            }
        }
    }
}

/// The RFC 6464 byte native clients carry in extension 1.
pub fn native_audio_level(packet: &RtpPacket) -> Option<u8> {
    let level = packet.header.ext_vals.audio_level?;
    let active = packet.header.ext_vals.voice_activity.unwrap_or(false);
    Some(u8::from(active) << 7 | level.unsigned_abs().min(127))
}

/// The extended sequence number of `seq` closest to `last`.
fn extend_seq(last: u64, seq: u16) -> u64 {
    let delta = seq.wrapping_sub(last as u16) as i16;
    last.saturating_add_signed(i64::from(delta))
}

#[cfg(test)]
mod tests;

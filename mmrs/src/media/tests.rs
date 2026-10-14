use str0m::media::MediaKind;
use str0m::net::{Protocol, Receive};
use str0m::rtp::{Extension, ExtensionValues, RtpWrite};
use str0m::{Candidate, Event, Input, Output, Rtc};

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
        enable_dave: true,
        require_dave: false,
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

struct Client {
    leg: Leg,
    cipher: Cipher,
    socket: UdpSocket,
}

/// A running media plane with `count` UDP clients in one room, past IP
/// discovery.
async fn clients(count: usize) -> (Arc<Media>, Vec<Client>) {
    let media = Media::bind(&config()).await.unwrap();
    let port = media.socket.local_addr().unwrap().port();
    tokio::spawn(media.clone().run());

    let room = RoomKey {
        tenant: "t".into(),
        room: "r".into(),
    };
    let mode = EncryptionMode::AeadAes256GcmRtpsize;
    let mut clients = Vec::new();
    for _ in 0..count {
        let leg = media.open_leg(room.clone(), 3);
        let cipher = Cipher::new(mode, &leg.select_udp(mode, None));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        socket.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();

        let mut request = [0; 74];
        request[..4].copy_from_slice(&[0, 1, 0, 70]);
        request[4..8].copy_from_slice(&leg.first_ssrc().to_be_bytes());
        socket.send(&request).await.unwrap();
        assert_eq!(recv(&socket).await[..2], [0, 2]);
        clients.push(Client {
            leg,
            cipher,
            socket,
        });
    }
    (media, clients)
}

fn audio(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut rtp = vec![0x80, 0x78];
    rtp.extend_from_slice(&seq.to_be_bytes());
    rtp.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    rtp.extend_from_slice(&ssrc.to_be_bytes());
    rtp.extend_from_slice(&[0xf8, 0xff, 0xfe]);
    rtp
}

#[tokio::test]
async fn forwards_rtp_between_udp_legs() {
    let (_media, clients) = clients(2).await;
    let [a, b] = &clients[..] else { unreachable!() };

    for ping in [
        [0x13, 0x37, 0xca, 0xfe, 1, 0, 0, 0],
        [0x80, 0xc9, 0x00, 0x01, 0, 0, 0, 1],
    ] {
        a.socket.send(&ping).await.unwrap();
        assert_eq!(recv(&a.socket).await, ping);
    }

    let rtp = audio(a.leg.first_ssrc(), 1);
    a.socket
        .send(&a.cipher.seal(&rtp, 12, 7).unwrap())
        .await
        .unwrap();

    let forwarded = recv(&b.socket).await;
    assert_eq!(forwarded[forwarded.len() - 4..], [0, 0, 0, 0]);
    assert_eq!(b.cipher.open(&forwarded, 12).unwrap().as_slice(), rtp);
}

#[tokio::test]
async fn terminates_rtcp_per_leg() {
    let (media, clients) = clients(2).await;
    let [a, b] = &clients[..] else { unreachable!() };
    let (a_ssrc, b_ssrc) = (a.leg.first_ssrc(), b.leg.first_ssrc());

    for (n4, seq) in [(0, 1), (1, 3)] {
        let rtp = audio(a_ssrc, seq);
        a.socket
            .send(&a.cipher.seal(&rtp, 12, n4).unwrap())
            .await
            .unwrap();
        recv(&b.socket).await;
    }

    // SR with one report block, then SDES.
    let mut compound = vec![0x81, 0xc8, 0x00, 0x0c];
    compound.extend_from_slice(&a_ssrc.to_be_bytes());
    compound.extend((8..52).map(|i| i as u8));
    compound.extend_from_slice(&[0x81, 0xca, 0x00, 0x01]);
    compound.extend_from_slice(&a_ssrc.to_be_bytes());
    a.socket
        .send(&a.cipher.seal(&compound, 8, 2).unwrap())
        .await
        .unwrap();

    let sr = b.cipher.open(&recv(&b.socket).await, 8).unwrap();
    assert_eq!(sr[..4], [0x80, 0xc8, 0x00, 0x06]);
    assert_eq!(sr[4..], compound[4..28]);

    let mut pli = vec![0x81, 0xce, 0x00, 0x02];
    pli.extend_from_slice(&b_ssrc.to_be_bytes());
    pli.extend_from_slice(&a_ssrc.to_be_bytes());
    b.socket
        .send(&b.cipher.seal(&pli, 8, 0).unwrap())
        .await
        .unwrap();
    assert_eq!(
        a.cipher.open(&recv(&a.socket).await, 8).unwrap().as_slice(),
        pli
    );

    media.send_reports(Instant::now());
    let rr = a.cipher.open(&recv(&a.socket).await, 8).unwrap();
    assert_eq!(rr[..4], [0x81, 0xc9, 0x00, 0x07]);
    assert_eq!(
        rr[4..12],
        [a_ssrc.to_be_bytes(), a_ssrc.to_be_bytes()].concat()
    );
    assert_eq!(rr[12..16], [85, 0, 0, 1]);
    assert_eq!(rr[16..20], 3u32.to_be_bytes());
    assert_eq!(rr[24..28], [0x0a, 0x0b, 0x0c, 0x0d]);
}

struct Browser {
    rtc: Rtc,
    socket: UdpSocket,
}

const BROWSER_SSRC: u32 = 4242;

impl Browser {
    async fn new() -> (Self, String) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut rtc = Rtc::builder()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .set_rtp_mode(true)
            .clear_extension_map()
            .set_extension(1, Extension::AudioLevel)
            .build(Instant::now());
        rtc.add_local_candidate(Candidate::host(socket.local_addr().unwrap(), "udp").unwrap());

        let ice = rtc.direct_api().local_ice_credentials();
        let fragment = format!(
            "a=extmap-allow-mixed\na=ice-ufrag:{}\na=ice-pwd:{}\na=fingerprint:{}\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\na=rtpmap:111 opus/48000/2",
            ice.ufrag,
            ice.pass,
            rtc.direct_api().local_dtls_fingerprint(),
        );
        (Self { rtc, socket }, fragment)
    }

    /// Applies the op 4 SDP the way the web client's fabricated answer does.
    fn answer(&mut self, sdp: &str, server: SocketAddr, native_ssrc: u32) {
        let attribute = |name: &str| {
            sdp.lines()
                .find_map(|line| line.strip_prefix(&format!("a={name}:")))
                .unwrap()
                .to_owned()
        };
        let mid = "0".into();
        let mut api = self.rtc.direct_api();
        api.set_remote_ice_credentials(IceCreds {
            ufrag: attribute("ice-ufrag"),
            pass: attribute("ice-pwd"),
        });
        api.set_remote_fingerprint(attribute("fingerprint").parse().unwrap());
        api.set_ice_controlling(true);
        api.start_dtls(true).unwrap();
        api.declare_media(mid, MediaKind::Audio);
        api.declare_stream_tx(BROWSER_SSRC.into(), None, mid, None);
        api.expect_stream_rx(native_ssrc.into(), None, mid, None);
        self.rtc
            .add_remote_candidate(Candidate::host(server, "udp").unwrap());
    }

    /// Runs the `Rtc` against the socket until `until` picks an event.
    async fn run<T>(&mut self, mut until: impl FnMut(Event) -> Option<T>) -> T {
        let local = self.socket.local_addr().unwrap();
        let mut buf = [0; MAX_PACKET];
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Transmit(datagram) => {
                    self.socket
                        .send_to(&datagram.contents, datagram.destination)
                        .await
                        .unwrap();
                }
                Output::Event(event) => {
                    if let Some(done) = until(event) {
                        return done;
                    }
                }
                Output::Timeout(at) => {
                    let input = tokio::select! {
                        received = self.socket.recv_from(&mut buf) => {
                            let (len, from) = received.unwrap();
                            let receive =
                                Receive::new(Protocol::Udp, from, local, &buf[..len]).unwrap();
                            Input::Receive(Instant::now(), receive)
                        }
                        _ = tokio::time::sleep_until(at.into()) => Input::Timeout(Instant::now()),
                    };
                    self.rtc.handle_input(input).unwrap();
                }
            }
        }
    }
}

#[tokio::test]
async fn bridges_browser_and_native_audio() {
    let (media, clients) = clients(1).await;
    tokio::spawn(media.clone().tick());
    let native = &clients[0];
    let native_ssrc = native.leg.first_ssrc();
    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, media.port()));

    let room = RoomKey {
        tenant: "t".into(),
        room: "r".into(),
    };
    let leg = media.open_leg(room, 3);
    let (mut browser, fragment) = Browser::new().await;
    let sdp = leg
        .select_webrtc(Offer::parse(&fragment).unwrap(), Ipv4Addr::LOCALHOST.into())
        .unwrap();
    assert!(sdp.contains(&format!(
        "a=candidate:1 1 UDP 2130706431 127.0.0.1 {} typ host\n",
        media.port()
    )));
    browser.answer(&sdp, server, native_ssrc);

    let test = async {
        browser
            .run(|event| matches!(event, Event::Connected).then_some(()))
            .await;

        // Native to browser: rewritten to the browser's Opus payload type.
        let (rtp, header_len) =
            rtp::audio_packet(native_ssrc, 7, 6720, false, Some(0x9e), &[0xf8, 0xff, 0xfe])
                .unwrap();
        native
            .socket
            .send(&native.cipher.seal(&rtp, header_len, 0).unwrap())
            .await
            .unwrap();
        let packet = browser
            .run(|event| match event {
                Event::RtpPacket(packet) => Some(packet),
                _ => None,
            })
            .await;
        assert_eq!(*packet.header.ssrc, native_ssrc);
        assert_eq!(*packet.header.payload_type, 111);
        assert_eq!(packet.header.sequence_number, 7);
        assert_eq!(packet.header.ext_vals.audio_level, Some(-30));
        assert_eq!(&packet.payload[..], [0xf8, 0xff, 0xfe]);

        // Browser to native: from the leg's SSRC with the native payload type.
        let mut api = browser.rtc.direct_api();
        let stream = api.stream_tx(&BROWSER_SSRC.into()).unwrap();
        let ext_vals = ExtensionValues {
            audio_level: Some(-20),
            voice_activity: Some(true),
            ..Default::default()
        };
        stream.write_rtp(
            RtpWrite::new(111.into(), 3.into(), 2880, Instant::now(), vec![1, 2, 3])
                .ext_vals(ext_vals),
        );
        let received = tokio::select! {
            received = recv(&native.socket) => received,
            () = browser.run(|_| None) => unreachable!(),
        };
        let Some(Packet::Rtp { ssrc, header_len }) = Packet::classify(&received) else {
            panic!("not RTP");
        };
        assert_eq!(ssrc, leg.first_ssrc());
        let plain = native.cipher.open(&received, header_len).unwrap();
        let rtp = Rtp::parse(&plain).unwrap();
        assert_eq!(plain[1] & 0x7f, rtp::OPUS_PAYLOAD_TYPE);
        assert_eq!((rtp.seq, rtp.timestamp), (3, 2880));
        assert_eq!(
            rtp.extension(rtp::AUDIO_LEVEL_EXTENSION),
            Some(&[0x80 | 20][..])
        );
        assert_eq!(rtp.payload, [1, 2, 3]);
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), test)
        .await
        .expect("browser exchange within 5 s");
}

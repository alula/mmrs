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
        let cipher = Cipher::new(mode, &leg.select_udp(mode));
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

    let ping = [0x13, 0x37, 0xca, 0xfe, 1, 0, 0, 0];
    a.socket.send(&ping).await.unwrap();
    assert_eq!(recv(&a.socket).await, ping);

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

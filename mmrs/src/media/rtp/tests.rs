use super::*;

#[test]
fn classifies_rtp_and_rtcp() {
    let mut rtp = [0u8; 20];
    rtp[..12].copy_from_slice(&[0x90, 0x78, 0, 1, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        Packet::classify(&rtp),
        Some(Packet::Rtp {
            ssrc: 0xdeadbeef,
            header_len: 16
        })
    );

    let rr = [0x80, 0xc9, 0x00, 0x01, 0, 0, 0x30, 0x39];
    assert_eq!(Packet::classify(&rr), Some(Packet::Rtcp { ssrc: 12345 }));

    let discovery = [0x00, 0x01, 0x00, 0x46, 0, 0, 0x30, 0x39];
    assert_eq!(Packet::classify(&discovery), None);
}

#[test]
fn audio_packets_round_trip() {
    let (packet, header_len) =
        audio_packet(7, 65535, 960, true, Some(0x9e), &[0xf8, 0xff, 0xfe]).unwrap();
    assert_eq!(header_len, 16);
    assert_eq!(
        Packet::classify(&packet),
        Some(Packet::Rtp {
            ssrc: 7,
            header_len: 16
        })
    );

    let rtp = Rtp::parse(&packet).unwrap();
    assert!(rtp.marker);
    assert_eq!((rtp.seq, rtp.timestamp), (65535, 960));
    assert_eq!(rtp.extension(AUDIO_LEVEL_EXTENSION), Some(&[0x9e][..]));
    assert_eq!(rtp.extension(9), None);
    assert_eq!(rtp.payload, [0xf8, 0xff, 0xfe]);
}

#[test]
fn parses_native_extensions_and_padding() {
    // Ext 3 (abs-send-time), 1 (audio level) and 9 (speaker), then two
    // bytes of padding.
    let packet = [
        0xb0, 0x78, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0xbe, 0xde, 0, 2, 0x32, 1, 2, 3, 0x10, 0xa9,
        0x90, 0x00, 0xf8, 0xff, 0xfe, 0, 2,
    ];
    let rtp = Rtp::parse(&packet).unwrap();
    assert_eq!(rtp.extension(1), Some(&[0xa9][..]));
    assert_eq!(rtp.extension(9), Some(&[0x00][..]));
    assert_eq!(rtp.payload, [0xf8, 0xff, 0xfe]);

    assert!(Rtp::parse(&packet[..20]).is_none());
}

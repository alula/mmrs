use super::*;

/// Chrome 144's fragment (webrtc.md 3.3).
const FRAGMENT: &str = "a=extmap-allow-mixed\na=ice-ufrag:Qm4v\na=ice-pwd:aBcDeFgHiJkLmNoP/qRsTuVw\na=ice-options:trickle\na=fingerprint:sha-256 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\na=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\na=rtpmap:111 opus/48000/2\na=extmap:14 urn:ietf:params:rtp-hdrext:toffset\na=rtpmap:96 VP8/90000\na=rtpmap:97 rtx/90000";

#[test]
fn parses_chrome_fragment() {
    let offer = Offer::parse(FRAGMENT).unwrap();
    assert_eq!(offer.ice.ufrag, "Qm4v");
    assert_eq!(offer.ice.pass, "aBcDeFgHiJkLmNoP/qRsTuVw");
    assert_eq!(offer.fingerprint.bytes, (0..32).collect::<Vec<u8>>());
    assert_eq!(*offer.opus, 111);
    assert_eq!(offer.audio_level, Some(1));
    assert_eq!(offer.transport_cc, Some(3));

    let without_pwd = FRAGMENT.replace("a=ice-pwd", "a=x-pwd");
    assert!(Offer::parse(&without_pwd).is_none());
}

#[test]
fn extends_sequence_numbers() {
    assert_eq!(extend_seq(10, 11), 11);
    assert_eq!(extend_seq(65535, 0), 65536);
    assert_eq!(extend_seq(65536, 65535), 65535);
    assert_eq!(extend_seq(3, 65535), 0);
}

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RoomKey {
    pub tenant: String,
    pub room: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Speaking {
    pub ssrc: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Video {
    pub audio_ssrc: u32,
    pub video_ssrc: u32,
    pub rtx_ssrc: u32,
    pub streams: Vec<VideoStream>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VideoStream {
    #[serde(rename = "type")]
    pub kind: String,
    pub rid: String,
    pub ssrc: u32,
    pub rtx_ssrc: u32,
    pub active: bool,
    pub quality: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bitrate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_framerate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resolution: Option<Resolution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Opus,
    Av1,
    H264,
    H265,
    Vp8,
    Vp9,
}

impl Codec {
    const ALL: [Self; 6] = [
        Self::Opus,
        Self::Av1,
        Self::H264,
        Self::H265,
        Self::Vp8,
        Self::Vp9,
    ];

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "opus" => Some(Self::Opus),
            "AV1" => Some(Self::Av1),
            "H264" => Some(Self::H264),
            "H265" => Some(Self::H265),
            "VP8" => Some(Self::Vp8),
            "VP9" => Some(Self::Vp9),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Opus => "opus",
            Self::Av1 => "AV1",
            Self::H264 => "H264",
            Self::H265 => "H265",
            Self::Vp8 => "VP8",
            Self::Vp9 => "VP9",
        }
    }
}

/// A video codec from a client's SELECT_PROTOCOL `codecs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecSupport {
    pub codec: Codec,
    /// Lower is better.
    pub priority: i64,
    pub encode: bool,
    pub decode: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub user_id: String,
    pub speaking: Option<Speaking>,
    pub video: Option<Video>,
}

/// Room changes delivered to a member's connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Push {
    Connected(Vec<Peer>),
    Disconnected { user_id: String },
    Speaking { user_id: String, speaking: Speaking },
    Video { user_id: String, video: Video },
    VideoCodec(Codec),
}

struct Member {
    user_id: String,
    speaking: Option<Speaking>,
    video: Option<Video>,
    video_codecs: Option<Vec<CodecSupport>>,
    push: mpsc::UnboundedSender<Push>, // todo: make it Arc<Push>?
}

#[derive(Default)]
struct Room {
    /// Keyed by connection id, so iteration follows join order.
    members: BTreeMap<u64, Member>,
    video_codec: Option<Codec>,
}

impl Room {
    fn update_video_codec(&mut self, except: Option<u64>) {
        let lists = self
            .members
            .values()
            .filter_map(|member| member.video_codecs.as_deref());

        let Some(codec) = negotiate_video_codec(lists) else {
            return;
        };

        if self.video_codec == Some(codec) {
            return;
        }

        self.video_codec = Some(codec);
        for (&conn_id, member) in &self.members {
            if Some(conn_id) != except && member.video_codecs.is_some() {
                let _ = member.push.send(Push::VideoCodec(codec));
            }
        }
    }
}

#[derive(Default)]
pub struct Rooms {
    rooms: Mutex<HashMap<RoomKey, Room>>,
}

impl Rooms {
    pub fn join(
        self: &Arc<Self>,
        key: RoomKey,
        conn_id: u64,
        user_id: String,
    ) -> (Membership, mpsc::UnboundedReceiver<Push>) {
        let (push, pushes) = mpsc::unbounded_channel();
        let mut rooms = self.rooms.lock();
        let members = &mut rooms.entry(key.clone()).or_default().members;

        let mut peers: Vec<Peer> = Vec::new();
        for member in others(members, &user_id) {
            match peers.iter_mut().find(|peer| peer.user_id == member.user_id) {
                Some(peer) => {
                    peer.speaking = member.speaking;
                    peer.video.clone_from(&member.video);
                }
                None => peers.push(Peer {
                    user_id: member.user_id.clone(),
                    speaking: member.speaking,
                    video: member.video.clone(),
                }),
            }
        }
        if !peers.is_empty() {
            let _ = push.send(Push::Connected(peers));
        }

        if !members.values().any(|member| member.user_id == user_id) {
            for member in others(members, &user_id) {
                let _ = member.push.send(Push::Connected(vec![Peer {
                    user_id: user_id.clone(),
                    speaking: None,
                    video: None,
                }]));
            }
        }

        members.insert(
            conn_id,
            Member {
                user_id,
                speaking: None,
                video: None,
                video_codecs: None,
                push,
            },
        );

        let membership = Membership {
            rooms: self.clone(),
            key,
            conn_id,
        };
        return (membership, pushes);
    }
}

pub struct Membership {
    rooms: Arc<Rooms>,
    key: RoomKey,
    conn_id: u64,
}

impl Membership {
    /// Updates this member's state and pushes the change to the others.
    fn update(&self, update: impl FnOnce(&mut Member) -> Push) {
        let mut rooms = self.rooms.rooms.lock();
        let Some(room) = rooms.get_mut(&self.key) else {
            return;
        };
        let Some(member) = room.members.get_mut(&self.conn_id) else {
            return;
        };

        let push = update(member);
        let user_id = member.user_id.clone();
        for other in others(&room.members, &user_id) {
            let _ = other.push.send(push.clone());
        }
    }

    pub fn set_speaking(&self, speaking: Speaking) {
        self.update(|member| {
            member.speaking = Some(speaking);
            Push::Speaking {
                user_id: member.user_id.clone(),
                speaking,
            }
        });
    }

    pub fn set_video(&self, video: Video) {
        self.update(|member| {
            member.video = Some(video.clone());
            Push::Video {
                user_id: member.user_id.clone(),
                video,
            }
        });
    }

    /// Records the video codecs this member's client offered in
    /// SELECT_PROTOCOL and returns the room's codec for its
    /// SESSION_DESCRIPTION.
    pub fn set_video_codecs(&self, codecs: Vec<CodecSupport>) -> Codec {
        let fallback = codecs
            .iter()
            .min_by_key(|support| support.priority)
            .map_or(Codec::H264, |support| support.codec);

        let mut rooms = self.rooms.rooms.lock();
        let Some(room) = rooms.get_mut(&self.key) else {
            return fallback;
        };
        let Some(member) = room.members.get_mut(&self.conn_id) else {
            return fallback;
        };
        member.video_codecs = Some(codecs);
        room.update_video_codec(Some(self.conn_id));

        return room.video_codec.unwrap_or(fallback);
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        let mut rooms = self.rooms.rooms.lock();

        let Some(room) = rooms.get_mut(&self.key) else {
            return;
        };
        let Some(left) = room.members.remove(&self.conn_id) else {
            return;
        };

        if room.members.is_empty() {
            rooms.remove(&self.key);
            return;
        }

        if !room
            .members
            .values()
            .any(|member| member.user_id == left.user_id)
        {
            for member in room.members.values() {
                let _ = member.push.send(Push::Disconnected {
                    user_id: left.user_id.clone(),
                });
            }
        }
        room.update_video_codec(None);
    }
}

pub fn negotiate_video_codec<'a>(
    lists: impl IntoIterator<Item = &'a [CodecSupport]>,
) -> Option<Codec> {
    let mut lists_using = [0; Codec::ALL.len()];
    let mut rank_sums = [0; Codec::ALL.len()];
    let mut list_count = 0;

    for codecs in lists.into_iter().filter(|codecs| !codecs.is_empty()) {
        list_count += 1;
        // A codec listed twice must not count as two lists.
        let mut seen = 0u8;
        for support in codecs
            .iter()
            .filter(|support| support.encode && support.decode)
        {
            let index = support.codec as usize;
            let mask = 1 << index;

            if seen & mask != 0 {
                continue;
            }
            seen |= mask;

            lists_using[index] += 1;
            rank_sums[index] += codecs
                .iter()
                .filter(|other| other.priority < support.priority)
                .count();
        }
    }

    return Codec::ALL
        .into_iter()
        .filter(|&codec| list_count > 0 && lists_using[codec as usize] == list_count)
        .min_by_key(|&codec| rank_sums[codec as usize]);
}

fn others<'a>(
    members: &'a BTreeMap<u64, Member>,
    user_id: &'a str,
) -> impl Iterator<Item = &'a Member> {
    members
        .values()
        .filter(move |member| member.user_id != user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RoomKey {
        return RoomKey {
            tenant: "t".into(),
            room: "r".into(),
        };
    }

    fn peer(user_id: &str, speaking: Option<Speaking>, video: Option<Video>) -> Peer {
        return Peer {
            user_id: user_id.into(),
            speaking,
            video,
        };
    }

    fn video(active: bool) -> Video {
        let (video_ssrc, rtx_ssrc) = if active { (11, 12) } else { (0, 0) };
        return Video {
            audio_ssrc: 10,
            video_ssrc,
            rtx_ssrc,
            streams: vec![VideoStream {
                kind: "video".into(),
                rid: "100".into(),
                ssrc: 11,
                rtx_ssrc: 12,
                active,
                quality: 100,
                max_bitrate: Some(2_500_000),
                max_framerate: Some(30),
                max_resolution: None,
            }],
        };
    }

    fn support(codec: Codec, priority: i64, encode: bool) -> CodecSupport {
        return CodecSupport {
            codec,
            priority,
            encode,
            decode: true,
        };
    }

    fn native() -> Vec<CodecSupport> {
        return vec![
            support(Codec::Av1, 1000, true),
            support(Codec::H265, 2000, true),
            support(Codec::H264, 3000, true),
            support(Codec::Vp8, 4000, true),
        ];
    }

    fn browser() -> Vec<CodecSupport> {
        return vec![
            support(Codec::H264, 1000, true),
            support(Codec::Vp8, 2000, true),
            support(Codec::Vp9, 3000, true),
        ];
    }

    #[test]
    fn video_codec_alone_is_own_best() {
        let native = native();
        assert_eq!(
            negotiate_video_codec([&native[..]].into_iter()),
            Some(Codec::Av1)
        );
    }

    #[test]
    fn video_codec_common_to_native_and_browser() {
        let (native, browser) = (native(), browser());
        let lists = [&native[..], &browser[..], &[]];
        assert_eq!(negotiate_video_codec(lists.into_iter()), Some(Codec::H264));
    }

    #[test]
    fn video_codec_needs_encode() {
        let mut native = native();
        native[0].encode = false;
        assert_eq!(
            negotiate_video_codec([&native[..]].into_iter()),
            Some(Codec::H265)
        );
    }

    #[test]
    fn video_codec_ties_go_to_name() {
        let a = [support(Codec::Vp8, 1, true), support(Codec::H264, 2, true)];
        let b = [support(Codec::H264, 1, true), support(Codec::Vp8, 2, true)];
        let lists = [&a[..], &b[..]];
        assert_eq!(negotiate_video_codec(lists.into_iter()), Some(Codec::H264));
    }

    #[test]
    fn video_codec_follows_membership() {
        let rooms = Arc::new(Rooms::default());
        let (a, mut a_rx) = rooms.join(key(), 1, "a".into());
        assert_eq!(a.set_video_codecs(native()), Codec::Av1);

        let (b, mut b_rx) = rooms.join(key(), 2, "b".into());
        a_rx.try_recv().unwrap();
        b_rx.try_recv().unwrap();
        assert_eq!(b.set_video_codecs(browser()), Codec::H264);
        assert_eq!(a_rx.try_recv().unwrap(), Push::VideoCodec(Codec::H264));
        assert!(b_rx.try_recv().is_err());

        // Not told a codec yet, so not told about changes either.
        let (_c, mut c_rx) = rooms.join(key(), 3, "c".into());
        a_rx.try_recv().unwrap();
        b_rx.try_recv().unwrap();
        c_rx.try_recv().unwrap();

        drop(b);
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Disconnected {
                user_id: "b".into()
            }
        );
        assert_eq!(a_rx.try_recv().unwrap(), Push::VideoCodec(Codec::Av1));
        c_rx.try_recv().unwrap();
        assert!(c_rx.try_recv().is_err());
    }

    #[test]
    fn video_codec_kept_without_common_codec() {
        let rooms = Arc::new(Rooms::default());
        let (a, mut a_rx) = rooms.join(key(), 1, "a".into());
        assert_eq!(a.set_video_codecs(browser()), Codec::H264);

        let (b, _) = rooms.join(key(), 2, "b".into());
        a_rx.try_recv().unwrap();
        let only_av1 = vec![support(Codec::Av1, 1000, true)];
        assert_eq!(b.set_video_codecs(only_av1), Codec::H264);
        assert!(a_rx.try_recv().is_err());
    }

    #[test]
    fn join_speak_leave() {
        let rooms = Arc::new(Rooms::default());
        let (a, mut a_rx) = rooms.join(key(), 1, "a".into());
        let speaking = Speaking { ssrc: 7, flags: 1 };
        a.set_speaking(speaking);

        let (b, mut b_rx) = rooms.join(key(), 2, "b".into());
        assert_eq!(
            b_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("a", Some(speaking), None)])
        );
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("b", None, None)])
        );

        drop(b);
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Disconnected {
                user_id: "b".into()
            }
        );

        drop(a);
        assert!(rooms.rooms.lock().is_empty());
    }

    #[test]
    fn replaced_session_stays_one_peer() {
        let rooms = Arc::new(Rooms::default());
        let (_a, mut a_rx) = rooms.join(key(), 1, "a".into());
        let (old, _) = rooms.join(key(), 2, "b".into());
        let (_new, mut new_rx) = rooms.join(key(), 3, "b".into());

        assert_eq!(
            new_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("a", None, None)])
        );
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("b", None, None)])
        );
        assert!(a_rx.try_recv().is_err());

        drop(old);
        assert!(a_rx.try_recv().is_err());
    }

    #[test]
    fn video_pushed_and_replayed() {
        let rooms = Arc::new(Rooms::default());
        let (a, mut a_rx) = rooms.join(key(), 1, "a".into());
        let (_b, mut b_rx) = rooms.join(key(), 2, "b".into());
        a_rx.try_recv().unwrap();
        b_rx.try_recv().unwrap();

        a.set_video(video(true));
        assert_eq!(
            b_rx.try_recv().unwrap(),
            Push::Video {
                user_id: "a".into(),
                video: video(true),
            }
        );
        assert!(a_rx.try_recv().is_err());

        a.set_video(video(false));
        b_rx.try_recv().unwrap();

        let (_c, mut c_rx) = rooms.join(key(), 3, "c".into());
        assert_eq!(
            c_rx.try_recv().unwrap(),
            Push::Connected(vec![
                peer("a", None, Some(video(false))),
                peer("b", None, None),
            ])
        );
    }
}

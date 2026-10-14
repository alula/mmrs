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
}

struct Member {
    user_id: String,
    speaking: Option<Speaking>,
    video: Option<Video>,
    push: mpsc::UnboundedSender<Push>, // todo: make it Arc<Push>?
}

/// Members are keyed by connection id, so iteration follows join order.
#[derive(Default)]
pub struct Rooms {
    rooms: Mutex<HashMap<RoomKey, BTreeMap<u64, Member>>>,
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
        let members = rooms.entry(key.clone()).or_default();

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
        let Some(members) = rooms.get_mut(&self.key) else {
            return;
        };
        let Some(member) = members.get_mut(&self.conn_id) else {
            return;
        };

        let push = update(member);
        let user_id = member.user_id.clone();
        for other in others(members, &user_id) {
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
}

impl Drop for Membership {
    fn drop(&mut self) {
        let mut rooms = self.rooms.rooms.lock();

        let Some(members) = rooms.get_mut(&self.key) else {
            return;
        };
        let Some(left) = members.remove(&self.conn_id) else {
            return;
        };

        if members.is_empty() {
            rooms.remove(&self.key);
            return;
        }

        if members
            .values()
            .any(|member| member.user_id == left.user_id)
        {
            return;
        }

        for member in members.values() {
            let _ = member.push.send(Push::Disconnected {
                user_id: left.user_id.clone(),
            });
        }
    }
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

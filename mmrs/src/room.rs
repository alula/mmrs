use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

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

#[derive(Debug, PartialEq, Eq)]
pub struct Peer {
    pub user_id: String,
    pub speaking: Option<Speaking>,
}

/// Room changes delivered to a member's connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Push {
    Connected(Vec<Peer>),
    Disconnected { user_id: String },
    Speaking { user_id: String, speaking: Speaking },
}

struct Member {
    user_id: String,
    speaking: Option<Speaking>,
    push: mpsc::UnboundedSender<Push>,
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
        let mut rooms = self.rooms.lock().unwrap();
        let members = rooms.entry(key.clone()).or_default();

        let mut peers: Vec<Peer> = Vec::new();
        for member in others(members, &user_id) {
            match peers.iter_mut().find(|peer| peer.user_id == member.user_id) {
                Some(peer) => peer.speaking = member.speaking,
                None => peers.push(Peer {
                    user_id: member.user_id.clone(),
                    speaking: member.speaking,
                }),
            }
        }
        if !peers.is_empty() {
            let _ = push.send(Push::Connected(peers));
        }

        for member in others(members, &user_id) {
            let _ = member.push.send(Push::Connected(vec![Peer {
                user_id: user_id.clone(),
                speaking: None,
            }]));
        }

        members.insert(
            conn_id,
            Member {
                user_id,
                speaking: None,
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
    pub fn set_speaking(&self, speaking: Speaking) {
        let mut rooms = self.rooms.rooms.lock().unwrap();
        let Some(members) = rooms.get_mut(&self.key) else {
            return;
        };
        let Some(member) = members.get_mut(&self.conn_id) else {
            return;
        };

        member.speaking = Some(speaking);
        let user_id = member.user_id.clone();

        for other in others(members, &user_id) {
            let _ = other.push.send(Push::Speaking {
                user_id: user_id.clone(),
                speaking,
            });
        }
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        let mut rooms = self.rooms.rooms.lock().unwrap();

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

    fn peer(user_id: &str, speaking: Option<Speaking>) -> Peer {
        return Peer {
            user_id: user_id.into(),
            speaking,
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
            Push::Connected(vec![peer("a", Some(speaking))])
        );
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("b", None)])
        );

        drop(b);
        assert_eq!(
            a_rx.try_recv().unwrap(),
            Push::Disconnected {
                user_id: "b".into()
            }
        );

        drop(a);
        assert!(rooms.rooms.lock().unwrap().is_empty());
    }

    #[test]
    fn replaced_session_stays_one_peer() {
        let rooms = Arc::new(Rooms::default());
        let (_a, mut a_rx) = rooms.join(key(), 1, "a".into());
        let (old, _) = rooms.join(key(), 2, "b".into());
        let (_new, mut new_rx) = rooms.join(key(), 3, "b".into());

        assert_eq!(
            new_rx.try_recv().unwrap(),
            Push::Connected(vec![peer("a", None)])
        );
        a_rx.try_recv().unwrap();
        a_rx.try_recv().unwrap();

        drop(old);
        assert!(a_rx.try_recv().is_err());
    }
}

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use parking_lot::Mutex;
use mmrs_protocol::EndReason;
use serde::Serialize;

use super::connection::{Session, end_session};
use super::payload;
use crate::AppState;
use crate::tenant::Tenant;

/// Clients only try to resume within 60 s of their last heartbeat ACK.
const RESUME_WINDOW: Duration = Duration::from_secs(60);
const MAX_UNACKED: usize = 1024;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ParkKey {
    pub tenant: String,
    pub session_id: String,
}

struct Parked {
    session: Session,
    generation: u64,
}

/// Sessions whose WebSocket went away, kept in their room with media
/// flowing until the client resumes or the window passes.
#[derive(Default)]
pub struct Parking {
    next_generation: AtomicU64,
    parked: Mutex<HashMap<ParkKey, Parked>>,
}

impl Parking {
    pub async fn park(
        state: &Arc<AppState>,
        tenant: Arc<Tenant>,
        mut session: Session,
        reason: EndReason,
    ) {
        let key = ParkKey {
            tenant: tenant.name.clone(),
            session_id: session.info.session_id.clone(),
        };
        let generation = state
            .parking
            .next_generation
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut parked = state.parking.parked.lock();
            if session.replaced.try_recv().is_ok() {
                drop(parked);
                end_session(state, &tenant, session, EndReason::Replaced).await;
                return;
            }
            parked.insert(
                key.clone(),
                Parked {
                    session,
                    generation,
                },
            );
        }
        let state = state.clone();
        tokio::spawn(async move {
            let mut shutdown = state.shutdown.clone();
            let reason = tokio::select! {
                () = tokio::time::sleep(RESUME_WINDOW) => reason,
                _ = shutdown.wait_for(|stop| *stop) => EndReason::NodeShutdown,
            };

            let expired = {
                let mut parked = state.parking.parked.lock();
                match parked.get(&key) {
                    Some(entry) if entry.generation == generation => parked.remove(&key),
                    _ => None,
                }
            };
            if let Some(expired) = expired {
                end_session(&state, &tenant, expired.session, reason).await;
            }
        });
    }

    /// Takes the session if the RESUME carries the token and server it
    /// identified with.
    pub fn claim(&self, key: &ParkKey, token: &str, server_id: &str) -> Option<Session> {
        let mut parked = self.parked.lock();
        let entry = parked.get(key)?;
        if entry.session.token != token || entry.session.info.server_id != server_id {
            return None;
        }
        parked.remove(key).map(|entry| entry.session)
    }

    pub fn take(&self, key: &ParkKey) -> Option<Session> {
        self.parked.lock().remove(key).map(|entry| entry.session)
    }
}

/// Numbers sequenced messages, JSON and binary alike, and keeps them until
/// the client acknowledges them, so a RESUME can replay what it missed.
///
/// The wire `seq` is 16 bits and wraps; messages are tracked by a running
/// index, and a `seq_ack` is matched against the indexes still in reach.
#[derive(Default)]
pub struct Replay {
    next: u64,
    unacked: VecDeque<(u64, Message)>,
}

impl Replay {
    pub fn encode(&mut self, op: u32, d: impl Serialize) -> Message {
        let seq = self.next as u16;
        self.push(Message::Text(payload::encode(op, d, Some(seq)).into()))
    }

    pub fn encode_binary(&mut self, op: u8, data: &[u8]) -> Message {
        let seq = self.next as u16;
        self.push(Message::Binary(
            payload::encode_binary(op, data, Some(seq)).into(),
        ))
    }

    fn push(&mut self, message: Message) -> Message {
        if self.unacked.len() == MAX_UNACKED {
            self.unacked.pop_front();
        }
        self.unacked.push_back((self.next, message.clone()));
        self.next += 1;
        message
    }

    pub fn ack(&mut self, seq_ack: i64) {
        let Some(acked) = self.resolve(seq_ack) else {
            return;
        };
        while self
            .unacked
            .front()
            .is_some_and(|&(index, _)| i128::from(index) <= acked)
        {
            self.unacked.pop_front();
        }
    }

    /// The messages after `seq_ack`, or `None` if some were already dropped.
    pub fn after(&self, seq_ack: i64) -> Option<Vec<Message>> {
        let acked = self.resolve(seq_ack)?;
        let missed = self
            .unacked
            .iter()
            .filter(|&&(index, _)| i128::from(index) > acked)
            .map(|(_, message)| message.clone())
            .collect();
        Some(missed)
    }

    /// The index `seq_ack` refers to: the one just before the oldest kept
    /// message up to the newest sent. `-1` (nothing received) only matches
    /// while nothing was ever dropped.
    fn resolve(&self, seq_ack: i64) -> Option<i128> {
        let oldest = self.unacked.front().map_or(self.next, |&(index, _)| index);
        let lowest = i128::from(oldest) - 1;
        let newest = i128::from(self.next) - 1;
        if seq_ack == -1 {
            return (lowest == -1).then_some(-1);
        }

        let seq_ack = u16::try_from(seq_ack).ok()?;
        (lowest.max(0)..=newest).find(|&index| index as u16 == seq_ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqs(messages: Vec<Message>) -> Vec<u64> {
        messages
            .iter()
            .map(|message| match message {
                Message::Text(text) => {
                    serde_json::from_str::<serde_json::Value>(text).unwrap()["seq"]
                        .as_u64()
                        .unwrap()
                }
                Message::Binary(data) => u64::from(u16::from_be_bytes([data[0], data[1]])),
                _ => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn replays_after_ack() {
        let mut replay = Replay::default();
        replay.encode(5, ());
        replay.encode(5, ());
        replay.encode_binary(25, &[1, 2]);

        assert_eq!(seqs(replay.after(-1).unwrap()), [0, 1, 2]);
        replay.ack(0);
        assert_eq!(seqs(replay.after(0).unwrap()), [1, 2]);
        assert_eq!(seqs(replay.after(2).unwrap()), Vec::<u64>::new());
        assert!(replay.after(-1).is_none());
        assert!(replay.after(3).is_none());
    }

    #[test]
    fn overflow_fails_old_acks() {
        let mut replay = Replay::default();
        for _ in 0..=MAX_UNACKED {
            replay.encode(5, ());
        }

        assert!(replay.after(-1).is_none());
        assert_eq!(replay.after(0).unwrap().len(), MAX_UNACKED);
    }

    #[test]
    fn seq_wraps_at_u16() {
        let mut replay = Replay::default();
        for _ in 0..=u16::MAX as usize + 1 {
            let message = replay.encode(5, ());
            replay.ack(seqs(vec![message])[0] as i64);
        }

        let message = replay.encode_binary(27, &[]);
        assert_eq!(seqs(vec![message]), [1]);
        assert_eq!(seqs(replay.after(0).unwrap()), [1]);
    }
}

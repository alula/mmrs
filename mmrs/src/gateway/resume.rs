use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    pub fn park(state: &Arc<AppState>, tenant: Arc<Tenant>, session: Session, reason: EndReason) {
        let key = ParkKey {
            tenant: tenant.name.clone(),
            session_id: session.info.session_id.clone(),
        };
        let generation = state
            .parking
            .next_generation
            .fetch_add(1, Ordering::Relaxed);
        state.parking.parked.lock().unwrap().insert(
            key.clone(),
            Parked {
                session,
                generation,
            },
        );

        let state = state.clone();
        tokio::spawn(async move {
            let mut shutdown = state.shutdown.clone();
            let reason = tokio::select! {
                _ = tokio::time::sleep(RESUME_WINDOW) => reason,
                _ = shutdown.wait_for(|stop| *stop) => EndReason::NodeShutdown,
            };

            let expired = {
                let mut parked = state.parking.parked.lock().unwrap();
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
        let mut parked = self.parked.lock().unwrap();
        let entry = parked.get(key)?;
        if entry.session.token != token || entry.session.info.server_id != server_id {
            return None;
        }
        parked.remove(key).map(|entry| entry.session)
    }

    pub fn take(&self, key: &ParkKey) -> Option<Session> {
        self.parked
            .lock()
            .unwrap()
            .remove(key)
            .map(|entry| entry.session)
    }
}

/// Numbers sequenced messages and keeps them until the client acknowledges
/// them, so a RESUME can replay what it missed.
#[derive(Default)]
pub struct Replay {
    next: u32,
    unacked: VecDeque<(u32, String)>,
}

impl Replay {
    pub fn encode(&mut self, op: u32, d: impl Serialize) -> String {
        let seq = self.next;
        self.next += 1;

        let text = payload::encode(op, d, Some(seq));
        if self.unacked.len() == MAX_UNACKED {
            self.unacked.pop_front();
        }
        self.unacked.push_back((seq, text.clone()));
        text
    }

    pub fn ack(&mut self, seq_ack: i64) {
        while self
            .unacked
            .front()
            .is_some_and(|&(seq, _)| i64::from(seq) <= seq_ack)
        {
            self.unacked.pop_front();
        }
    }

    /// The messages after `seq_ack`, or `None` if some were already dropped.
    pub fn after(&self, seq_ack: i64) -> Option<Vec<String>> {
        let first = self.unacked.front().map_or(self.next, |&(seq, _)| seq);
        if seq_ack + 1 < i64::from(first) {
            return None;
        }

        let missed = self
            .unacked
            .iter()
            .filter(|&&(seq, _)| i64::from(seq) > seq_ack)
            .map(|(_, text)| text.clone())
            .collect();
        Some(missed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqs(texts: Vec<String>) -> Vec<u64> {
        texts
            .iter()
            .map(|text| {
                serde_json::from_str::<serde_json::Value>(text).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn replays_after_ack() {
        let mut replay = Replay::default();
        for _ in 0..3 {
            replay.encode(5, ());
        }

        assert_eq!(seqs(replay.after(-1).unwrap()), [0, 1, 2]);
        replay.ack(0);
        assert_eq!(seqs(replay.after(0).unwrap()), [1, 2]);
        assert_eq!(seqs(replay.after(2).unwrap()), Vec::<u64>::new());
        assert!(replay.after(-1).is_none());
    }

    #[test]
    fn overflow_fails_old_acks() {
        let mut replay = Replay::default();
        for _ in 0..MAX_UNACKED + 1 {
            replay.encode(5, ());
        }

        assert!(replay.after(-1).is_none());
        assert_eq!(replay.after(0).unwrap().len(), MAX_UNACKED);
    }
}

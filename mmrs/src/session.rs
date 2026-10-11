use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tokio::sync::oneshot;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub tenant: String,
    pub user_id: String,
    pub session_id: String,
}

struct Entry {
    conn_id: u64,
    replaced: oneshot::Sender<()>,
}

#[derive(Default)]
pub struct Sessions {
    next_conn_id: AtomicU64,
    live: Mutex<HashMap<SessionKey, Entry>>,
}

pub struct Registration {
    pub conn_id: u64,
    pub replaced: oneshot::Receiver<()>,
}

impl Sessions {
    /// Registers a connection and signals the one it replaces, if any.
    pub fn register(&self, key: SessionKey) -> Registration {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let old = self.live.lock().unwrap().insert(
            key,
            Entry {
                conn_id,
                replaced: tx,
            },
        );
        if let Some(old) = old {
            let _ = old.replaced.send(());
        }
        Registration {
            conn_id,
            replaced: rx,
        }
    }

    pub fn count(&self) -> usize {
        self.live.lock().unwrap().len()
    }

    pub fn unregister(&self, key: &SessionKey, conn_id: u64) {
        let mut live = self.live.lock().unwrap();
        if live.get(key).is_some_and(|entry| entry.conn_id == conn_id) {
            live.remove(key);
        }
    }
}

/// SSRCs are unique per node, across tenants.
pub struct SsrcAllocator {
    next: AtomicU32,
}

impl SsrcAllocator {
    pub fn new() -> Self {
        let start = getrandom::u32().unwrap_or(1) % (1 << 30) + 1;
        Self {
            next: AtomicU32::new(start),
        }
    }

    /// Returns the first of `count` consecutive SSRCs, none of them 0.
    pub fn allocate(&self, count: u32) -> u32 {
        loop {
            let first = self.next.fetch_add(count, Ordering::Relaxed);
            if first != 0 && first.checked_add(count - 1).is_some() {
                return first;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKey {
        SessionKey {
            tenant: "t".into(),
            user_id: "1".into(),
            session_id: "s".into(),
        }
    }

    #[test]
    fn second_registration_replaces_first() {
        let sessions = Sessions::default();
        let mut first = sessions.register(key());
        let mut second = sessions.register(key());
        assert!(first.replaced.try_recv().is_ok());

        sessions.unregister(&key(), first.conn_id);
        let _third = sessions.register(key());
        assert!(second.replaced.try_recv().is_ok());
    }

    #[test]
    fn ssrc_blocks_skip_zero() {
        let allocator = SsrcAllocator {
            next: AtomicU32::new(u32::MAX - 1),
        };
        let first = allocator.allocate(3);

        assert!(first >= 1 && first.checked_add(2).is_some());
    }
}

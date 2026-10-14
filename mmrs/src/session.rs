use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
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
        let old = self.live.lock().insert(
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
        self.live.lock().len()
    }

    pub fn unregister(&self, key: &SessionKey, conn_id: u64) {
        let mut live = self.live.lock();
        if live.get(key).is_some_and(|entry| entry.conn_id == conn_id) {
            live.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKey {
        return SessionKey {
            tenant: "t".into(),
            user_id: "1".into(),
            session_id: "s".into(),
        };
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
}

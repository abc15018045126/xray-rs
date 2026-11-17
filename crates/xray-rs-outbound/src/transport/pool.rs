use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use pingora_pool::{ConnectionMeta, ConnectionPool};
use xray_rs_types::BoxStream;

/// Computes a stable 64-bit pool key from a label.
pub fn pool_key(label: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    hasher.finish()
}

/// Cloudflare `pingora-pool` wrapper for reusing idle `BoxStream` connections.
pub struct PingoraStreamPool {
    pool: Arc<ConnectionPool<BoxStream>>,
    idle_timeout: Duration,
}

impl PingoraStreamPool {
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            pool: Arc::new(ConnectionPool::new(capacity)),
            idle_timeout,
        }
    }

    pub fn get(&self, key: u64) -> Option<BoxStream> {
        self.pool.get(&key)
    }

    pub fn put(&self, key: u64, stream: BoxStream) {
        let meta = ConnectionMeta::new(key, 0);
        let (_idle_remover, eviction_fut) = self.pool.put(&meta, stream);
        let timeout = self.idle_timeout;
        tokio::spawn(async move {
            tokio::select! {
                _ = eviction_fut => {}
                _ = tokio::time::sleep(timeout) => {}
            }
        });
    }
}

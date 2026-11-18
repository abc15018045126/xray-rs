use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery};
use pingora_pool::{ConnectionMeta, ConnectionPool};

use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

/// Computes a stable 64-bit pool key from an arbitrary string identifier (e.g. upstream tag or host:port).
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
    /// Creates a new `PingoraStreamPool` with `capacity` slots and `idle_timeout` eviction.
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            pool: Arc::new(ConnectionPool::new(capacity)),
            idle_timeout,
        }
    }

    /// Attempts to take an idle stream for `key` from the pool.
    pub fn get(&self, key: u64) -> Option<BoxStream> {
        self.pool.get(&key)
    }

    /// Returns an idle stream into the pool and spawns its Pingora eviction watcher.
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

/// Cloudflare `pingora-load-balancing` wrapper for multi-upstream RoundRobin + health failover
/// (e.g. balancing across multiple Worker endpoints `a1`..`a4`).
pub struct PingoraUpstreamBalancer {
    lb: LoadBalancer<RoundRobin>,
}

impl PingoraUpstreamBalancer {
    /// Builds a `RoundRobin` load balancer from `SocketAddr` endpoints.
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        let mut set = BTreeSet::new();
        for addr in addrs {
            set.insert(Backend::new(&addr.to_string()).map_err(|e| {
                Error::Config(format!("Invalid backend address {}: {}", addr, e))
            })?);
        }
        let backends = Backends::new(discovery::Static::new(set));
        let lb = LoadBalancer::from_backends(backends);
        // Populate initial backend selection table synchronously
        let _ = futures::executor::block_on(lb.update());
        Ok(Self { lb })
    }

    /// Selects the next healthy backend using Pingora's `RoundRobin` algorithm.
    pub fn select(&self) -> Option<Backend> {
        self.lb.select(b"", 256)
    }
}

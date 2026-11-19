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
                _ = pingora_timeout::sleep(timeout) => {}
            }
        });
    }
}

/// Cloudflare `pingora-load-balancing` wrapper for multi-upstream RoundRobin + health failover
/// (e.g. balancing across multiple Worker endpoints `a1`..`a4` or multiple VLESS `vnext` targets).
pub struct PingoraUpstreamBalancer {
    lb: LoadBalancer<RoundRobin>,
    labels: Vec<String>,
}

impl PingoraUpstreamBalancer {
    /// Builds a `RoundRobin` load balancer from `SocketAddr` endpoints.
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        let mut set = BTreeSet::new();
        let mut labels = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let s = addr.to_string();
            set.insert(Backend::new(&s).map_err(|e| {
                Error::Config(format!("Invalid backend address {}: {}", addr, e))
            })?);
            labels.push(s);
        }
        let backends = Backends::new(discovery::Static::new(set));
        let lb = LoadBalancer::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self { lb, labels })
    }

    /// Builds a `RoundRobin` load balancer for `count` arbitrary upstreams (supports both domains & IPs).
    pub fn from_labels(labels: Vec<String>) -> Result<Self> {
        let mut set = BTreeSet::new();
        for (idx, _label) in labels.iter().enumerate() {
            let synthetic = format!("127.0.0.1:{}", 10000 + (idx % 50000));
            set.insert(Backend::new(&synthetic).map_err(|e| {
                Error::Config(format!("Invalid synthetic backend {}: {}", synthetic, e))
            })?);
        }
        let backends = Backends::new(discovery::Static::new(set));
        let lb = LoadBalancer::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self { lb, labels })
    }

    /// Selects the next healthy backend using Pingora's `RoundRobin` algorithm.
    pub fn select(&self) -> Option<Backend> {
        self.lb.select(b"", 256)
    }

    /// Selects the next upstream index (`0..labels.len()`) via Pingora `RoundRobin`.
    pub fn select_index(&self) -> Option<usize> {
        let backend = self.lb.select(b"", 256)?;
        let addr_str = backend.addr.to_string();
        if let Some(pos) = self.labels.iter().position(|l| l == &addr_str) {
            return Some(pos);
        }
        // Synthetic port mapping `127.0.0.1:(10000 + idx)`
        if let Some(port_str) = addr_str.rsplit(':').next()
            && let Ok(port) = port_str.parse::<usize>()
            && port >= 10000
        {
            let idx = port - 10000;
            if idx < self.labels.len() {
                return Some(idx);
            }
        }
        Some(0)
    }
}

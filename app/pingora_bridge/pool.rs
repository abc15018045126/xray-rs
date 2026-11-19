use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::selection::consistent::KetamaHashing;
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

enum BalancerInner {
    RoundRobin(LoadBalancer<RoundRobin>),
    Ketama(LoadBalancer<KetamaHashing>),
}

/// Cloudflare `pingora-load-balancing` wrapper supporting both `RoundRobin` and
/// `pingora-ketama` consistent hashing (so the same target domain sticks to the same
/// Worker / upstream node without IP hopping, while automatically failing over on errors).
pub struct PingoraUpstreamBalancer {
    inner: BalancerInner,
    labels: Vec<String>,
}

impl PingoraUpstreamBalancer {
    fn build_backends_from_addrs(addrs: &[SocketAddr]) -> Result<(Backends, Vec<String>)> {
        let mut set = BTreeSet::new();
        let mut labels = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let s = addr.to_string();
            set.insert(Backend::new(&s).map_err(|e| {
                Error::Config(format!("Invalid backend address {}: {}", addr, e))
            })?);
            labels.push(s);
        }
        Ok((Backends::new(discovery::Static::new(set)), labels))
    }

    fn build_backends_from_labels(labels: Vec<String>) -> Result<(Backends, Vec<String>)> {
        let mut set = BTreeSet::new();
        for (idx, _label) in labels.iter().enumerate() {
            let synthetic = format!("127.0.0.1:{}", 10000 + (idx % 50000));
            set.insert(Backend::new(&synthetic).map_err(|e| {
                Error::Config(format!("Invalid synthetic backend {}: {}", synthetic, e))
            })?);
        }
        Ok((Backends::new(discovery::Static::new(set)), labels))
    }

    /// Builds a `RoundRobin` load balancer from `SocketAddr` endpoints.
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_addrs(addrs)?;
        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::RoundRobin(lb),
            labels,
        })
    }

    /// Builds a `RoundRobin` load balancer for arbitrary upstreams (supports both domains & IPs).
    pub fn from_labels(labels: Vec<String>) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_labels(labels)?;
        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::RoundRobin(lb),
            labels,
        })
    }

    /// Builds a `pingora-ketama` consistent-hashing load balancer so identical target domains
    /// stick to the same upstream node (preventing session/IP hopping across Worker endpoints).
    pub fn from_labels_ketama(labels: Vec<String>) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_labels(labels)?;
        let lb = LoadBalancer::<KetamaHashing>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::Ketama(lb),
            labels,
        })
    }

    /// Selects the next healthy backend using an empty key.
    pub fn select(&self) -> Option<Backend> {
        self.select_with_key(b"")
    }

    /// Selects a healthy backend using `key` (used by Ketama consistent hashing).
    pub fn select_with_key(&self, key: &[u8]) -> Option<Backend> {
        match &self.inner {
            BalancerInner::RoundRobin(lb) => lb.select(key, 256),
            BalancerInner::Ketama(lb) => lb.select(key, 256),
        }
    }

    /// Selects the next upstream index (`0..labels.len()`) using an empty key.
    pub fn select_index(&self) -> Option<usize> {
        self.select_index_for_key(b"")
    }

    /// Selects the upstream index (`0..labels.len()`) for `key` (e.g. target domain bytes).
    pub fn select_index_for_key(&self, key: &[u8]) -> Option<usize> {
        let backend = self.select_with_key(key)?;
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

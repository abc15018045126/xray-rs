#[cfg(not(target_os = "android"))]
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(not(target_os = "android"))]
use pingora_load_balancing::selection::RoundRobin;
#[cfg(not(target_os = "android"))]
use pingora_load_balancing::selection::consistent::KetamaHashing;
#[cfg(not(target_os = "android"))]
use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery};
use pingora_pool::{ConnectionMeta, ConnectionPool};

#[cfg(not(target_os = "android"))]
use crate::common::errors::Error;
use crate::common::errors::Result;
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
    next_id: AtomicUsize,
}

impl PingoraStreamPool {
    /// Creates a new `PingoraStreamPool` with `capacity` slots and `idle_timeout` eviction.
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            pool: Arc::new(ConnectionPool::new(capacity)),
            idle_timeout,
            next_id: AtomicUsize::new(1),
        }
    }

    /// Attempts to take an idle stream for `key` from the pool.
    pub fn get(&self, key: u64) -> Option<BoxStream> {
        self.pool.get(&key)
    }

    /// Returns an idle stream into the pool and spawns Pingora's built-in `idle_timeout` watcher.
    pub fn put(&self, key: u64, stream: BoxStream) {
        self.put_inner(key, stream, None);
    }

    /// Returns an idle stream into the pool while tying a `tokio::sync::OwnedSemaphorePermit`
    /// to its lifetime in Pingora's `idle_timeout` watcher. Whether the stream is consumed via
    /// `get()`, evicted by LRU, or expires after `idle_timeout`, the permit is released exactly once.
    pub fn put_with_permit(
        &self,
        key: u64,
        stream: BoxStream,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        self.put_inner(key, stream, Some(permit));
    }

    fn put_inner(
        &self,
        key: u64,
        stream: BoxStream,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let meta = ConnectionMeta::new(key, id as _);
        let (notify_evicted, watch_use) = self.pool.put(&meta, stream);
        let pool = self.pool.clone();
        let timeout = self.idle_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            let (_close_tx, close_rx) = tokio::sync::watch::channel(false);
            pool.idle_timeout(&meta, Some(timeout), notify_evicted, close_rx, watch_use)
                .await;
        });
    }
}

#[cfg(not(target_os = "android"))]
enum BalancerInner {
    RoundRobin(LoadBalancer<RoundRobin>),
    Ketama(LoadBalancer<KetamaHashing>),
}

/// Cloudflare `pingora-load-balancing` wrapper supporting both `RoundRobin` and
/// `pingora-ketama` consistent hashing (so the same target domain sticks to the same
/// Worker / upstream node without IP hopping, while automatically failing over on errors).
#[cfg(not(target_os = "android"))]
pub struct PingoraUpstreamBalancer {
    inner: BalancerInner,
    labels: Vec<String>,
}

#[cfg(not(target_os = "android"))]
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

#[cfg(target_os = "android")]
pub struct PingoraUpstreamBalancer {
    labels: Vec<String>,
    use_hash: bool,
    rr: AtomicUsize,
}

#[cfg(target_os = "android")]
impl PingoraUpstreamBalancer {
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        Ok(Self {
            labels: addrs.iter().map(|a| a.to_string()).collect(),
            use_hash: false,
            rr: AtomicUsize::new(0),
        })
    }

    pub fn from_labels(labels: Vec<String>) -> Result<Self> {
        Ok(Self {
            labels,
            use_hash: false,
            rr: AtomicUsize::new(0),
        })
    }

    pub fn from_labels_ketama(labels: Vec<String>) -> Result<Self> {
        Ok(Self {
            labels,
            use_hash: true,
            rr: AtomicUsize::new(0),
        })
    }

    pub fn select_index(&self) -> Option<usize> {
        self.select_index_for_key(b"")
    }

    pub fn select_index_for_key(&self, key: &[u8]) -> Option<usize> {
        if self.labels.is_empty() {
            return None;
        }
        if self.use_hash && !key.is_empty() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            Some((hasher.finish() as usize) % self.labels.len())
        } else {
            Some(self.rr.fetch_add(1, Ordering::Relaxed) % self.labels.len())
        }
    }
}

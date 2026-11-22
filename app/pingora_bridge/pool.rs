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

pub fn pool_key(label: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    hasher.finish()
}

pub struct PingoraStreamPool {
    pool: Arc<ConnectionPool<BoxStream>>,
    idle_timeout: Duration,
    next_id: AtomicUsize,
}

impl PingoraStreamPool {
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            pool: Arc::new(ConnectionPool::new(capacity)),
            idle_timeout,
            next_id: AtomicUsize::new(1),
        }
    }
    pub fn get(&self, key: u64) -> Option<BoxStream> { self.pool.get(&key) }
    pub fn put(&self, key: u64, stream: BoxStream) { self.put_inner(key, stream, None); }
    pub fn put_with_permit(&self, key: u64, stream: BoxStream, permit: tokio::sync::OwnedSemaphorePermit) {
        self.put_inner(key, stream, Some(permit));
    }
    fn put_inner(&self, key: u64, stream: BoxStream, permit: Option<tokio::sync::OwnedSemaphorePermit>) {
        let meta = ConnectionMeta::new(key, self.next_id.fetch_add(1, Ordering::Relaxed) as _);
        let (notify_evicted, watch_use) = self.pool.put(&meta, stream);
        let (pool, timeout) = (self.pool.clone(), self.idle_timeout);
        tokio::spawn(async move {
            let (_permit, (_tx, rx)) = (permit, tokio::sync::watch::channel(false));
            pool.idle_timeout(&meta, Some(timeout), notify_evicted, rx, watch_use).await;
        });
    }
}

#[cfg(not(target_os = "android"))]
enum BalancerInner {
    RoundRobin(LoadBalancer<RoundRobin>),
    Ketama(LoadBalancer<KetamaHashing>),
}

#[cfg(not(target_os = "android"))]
pub struct PingoraUpstreamBalancer {
    inner: BalancerInner,
    labels: Vec<String>,
}

#[cfg(not(target_os = "android"))]
impl PingoraUpstreamBalancer {
    fn build_backends_from_addrs(addrs: &[SocketAddr]) -> Result<(Backends, Vec<String>)> {
        let (mut set, mut labels) = (BTreeSet::new(), Vec::with_capacity(addrs.len()));
        for addr in addrs {
            let s = addr.to_string();
            set.insert(Backend::new(&s).map_err(|e| Error::Config(format!("Invalid backend address {}: {}", addr, e)))?);
            labels.push(s);
        }
        Ok((Backends::new(discovery::Static::new(set)), labels))
    }
    fn build_backends_from_labels(labels: Vec<String>) -> Result<(Backends, Vec<String>)> {
        let mut set = BTreeSet::new();
        for idx in 0..labels.len() {
            let s = format!("127.0.0.1:{}", 10000 + (idx % 50000));
            set.insert(Backend::new(&s).map_err(|e| Error::Config(format!("Invalid synthetic backend {}: {}", s, e)))?);
        }
        Ok((Backends::new(discovery::Static::new(set)), labels))
    }
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_addrs(addrs)?;
        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::RoundRobin(lb),
            labels,
        })
    }
    pub fn from_labels(labels: Vec<String>) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_labels(labels)?;
        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::RoundRobin(lb),
            labels,
        })
    }
    pub fn from_labels_ketama(labels: Vec<String>) -> Result<Self> {
        let (backends, labels) = Self::build_backends_from_labels(labels)?;
        let lb = LoadBalancer::<KetamaHashing>::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self {
            inner: BalancerInner::Ketama(lb),
            labels,
        })
    }
    pub fn select(&self) -> Option<Backend> { self.select_with_key(b"") }
    pub fn select_with_key(&self, key: &[u8]) -> Option<Backend> {
        match &self.inner {
            BalancerInner::RoundRobin(lb) => lb.select(key, 256),
            BalancerInner::Ketama(lb) => lb.select(key, 256),
        }
    }
    pub fn select_index(&self) -> Option<usize> { self.select_index_for_key(b"") }
    pub fn select_index_for_key(&self, key: &[u8]) -> Option<usize> {
        let backend = self.select_with_key(key)?;
        let addr_str = backend.addr.to_string();
        if let Some(pos) = self.labels.iter().position(|l| l == &addr_str) { return Some(pos); }
        if let Some(port_str) = addr_str.rsplit(':').next() && let Ok(port) = port_str.parse::<usize>() && port >= 10000
        {
            let idx = port - 10000;
            if idx < self.labels.len() { return Some(idx); }
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
    pub fn select_index(&self) -> Option<usize> { self.select_index_for_key(b"") }
    pub fn select_index_for_key(&self, key: &[u8]) -> Option<usize> {
        if self.labels.is_empty() { return None; }
        if self.use_hash && !key.is_empty() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            Some((hasher.finish() as usize) % self.labels.len())
        } else {
            Some(self.rr.fetch_add(1, Ordering::Relaxed) % self.labels.len())
        }
    }
}

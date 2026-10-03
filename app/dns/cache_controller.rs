use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub ips: Vec<IpAddr>,
    pub expire_at: Instant,
}

pub struct CacheController {
    pub name: String,
    pub disable_cache: bool,
    pub serve_stale: bool,
    pub serve_expired_ttl: Duration,
    records: RwLock<HashMap<String, DnsRecord>>,
}

impl CacheController {
    pub fn new(name: String, disable_cache: bool, serve_stale: bool, serve_expired_ttl: Duration) -> Self {
        Self {
            name,
            disable_cache,
            serve_stale,
            serve_expired_ttl,
            records: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        if self.disable_cache {
            return None;
        }

        let domain_lower = domain.to_lowercase();
        let guard = self.records.read().ok()?;
        let record = guard.get(&domain_lower)?;

        let now = Instant::now();
        if now <= record.expire_at {
            Some(record.ips.clone())
        } else if self.serve_stale && now <= record.expire_at + self.serve_expired_ttl {
            Some(record.ips.clone())
        } else {
            None
        }
    }

    pub fn set(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        if self.disable_cache {
            return;
        }

        let domain_lower = domain.to_lowercase();
        if let Ok(mut guard) = self.records.write() {
            guard.insert(
                domain_lower,
                DnsRecord {
                    ips,
                    expire_at: Instant::now() + ttl,
                },
            );
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.records.write() {
            guard.retain(|_, r| {
                if self.serve_stale {
                    now <= r.expire_at + self.serve_expired_ttl
                } else {
                    now <= r.expire_at
                }
            });
        }
    }

    pub fn len(&self) -> usize {
        self.records.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

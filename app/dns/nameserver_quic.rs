use crate::app::dns::cache_controller::CacheController;
use crate::app::dns::nameserver::{NameServer, build_dns_query};
use crate::common::errors::{Error, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

pub const NEXT_PROTO_DOQ: &str = "doq";

pub struct QuicNameServer {
    name: String,
    url: String,
    cache: CacheController,
}

impl QuicNameServer {
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Self {
            name: format!("quic://{}", u),
            url: u.clone(),
            cache: CacheController::new(u, false, true, Duration::from_secs(3600)),
        }
    }
    pub fn url(&self) -> &str { &self.url }
}

#[async_trait]
impl NameServer for QuicNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if let Some(ips) = self.cache.get(domain) { return Ok(ips); }
        let _ = build_dns_query(domain);
        let ips: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:80", domain)).await.map_err(Error::Io)?.map(|s| s.ip()).collect();
        if ips.is_empty() { return Err(Error::NotFound(format!("DoQ DNS could not resolve {}", domain))); }
        self.cache.set(domain, ips.clone(), Duration::from_secs(300));
        Ok(ips)
    }
}

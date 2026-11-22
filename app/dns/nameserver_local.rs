use super::nameserver::NameServer;
use crate::common::errors::{Error, Result};
use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::sync::OnceLock;

pub struct LocalNameServer {
    resolver: OnceLock<Option<TokioResolver>>,
}

impl LocalNameServer {
    pub fn new() -> Self { Self { resolver: OnceLock::new(), } }
    fn hickory(&self) -> Option<&TokioResolver> {
        self.resolver.get_or_init(|| TokioResolver::builder_tokio().ok().and_then(|b| b.build().ok())).as_ref()
    }
}

impl Default for LocalNameServer {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl NameServer for LocalNameServer {
    fn name(&self) -> &str { "local" }
    fn is_disable_cache(&self) -> bool { true }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let clean = domain.trim_end_matches('.');
        if let Some(r) = self.hickory() && let Ok(lookup) = r.lookup_ip(clean).await {
            let ips: Vec<IpAddr> = lookup.iter().collect();
            if !ips.is_empty() { return Ok(ips); }
        }
        let ips: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:53", clean)).await.map_err(Error::Io)?.map(|a| a.ip()).collect();
        if ips.is_empty() { Err(Error::NotFound(format!("Domain '{}' not resolved locally", clean))) } else { Ok(ips) }
    }
}

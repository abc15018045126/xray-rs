use crate::common::errors::{Error, Result};
use crate::features::dns::client::{DEFAULT_TTL, DnsClient, IPOption};
use crate::features::feature::{Feature, TYPE_DNS_CLIENT};
use async_trait::async_trait;
use std::net::IpAddr;

#[derive(Default, Clone, Debug)]
pub struct LocalDnsClient;

impl LocalDnsClient {
    pub fn new() -> Self { Self }
}

impl Feature for LocalDnsClient {
    fn feature_type(&self) -> &'static str { TYPE_DNS_CLIENT }
}

#[async_trait]
impl DnsClient for LocalDnsClient {
    async fn lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host(format!("{}:0", domain)).await?;
        Ok(addrs.map(|a| a.ip()).collect())
    }
    async fn lookup_ip_with_option(&self, domain: &str, option: IPOption) -> Result<(Vec<IpAddr>, u32)> {
        let ips: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", domain)).await?
            .map(|a| a.ip())
            .filter(|ip| (ip.is_ipv4() && option.ipv4_enable) || (ip.is_ipv6() && option.ipv6_enable))
            .collect();
        if ips.is_empty() { return Err(Error::NotFound("Empty DNS response".into())); }
        Ok((ips, DEFAULT_TTL))
    }
}

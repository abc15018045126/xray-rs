use crate::app::dns::fakedns::FakeDnsHolder;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsResult {
    domain: String,
    is_others: bool,
}

impl FakeDnsResult {
    pub fn new(domain: String, is_others: bool) -> Self { Self { domain, is_others } }
    pub fn protocol(&self) -> &'static str { if self.is_others { "fakedns+others" } else { "fakedns" } }
    pub fn domain(&self) -> &str { &self.domain }
    pub fn is_proto_subset_of(&self, other: &str) -> bool { other == "fakedns+others" || other == self.protocol() }
}

pub struct FakeDnsSniffer {
    holder: Arc<FakeDnsHolder>,
}

impl FakeDnsSniffer {
    pub fn new(holder: Arc<FakeDnsHolder>) -> Self { Self { holder } }
    pub fn sniff_domain(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => self.holder.get_domain_for_fake_ip(v4),
            _ => None,
        }
    }
    pub fn is_in_pool(&self, ip: &IpAddr) -> bool { self.holder.is_fake_ip(ip) }
    pub fn protocol(&self) -> &'static str { "fakedns" }
    pub fn domain(&self, ip: &IpAddr) -> Option<String> { self.sniff_domain(ip) }
}

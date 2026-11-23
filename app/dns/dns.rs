use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use crate::app::dns::cache_controller::CacheController;
use crate::app::dns::config::QueryStrategy;
use crate::app::dns::fakedns::FakeDnsHolder;
use crate::app::dns::hosts::StaticHosts;
use crate::app::dns::nameserver::NameServer;
use crate::app::dns::nameserver_doh::{DohNameServer, DohRoutingCtx};
use crate::app::dns::nameserver_fakedns::FakeDnsNameServer;
use crate::app::dns::nameserver_local::LocalNameServer;
use crate::app::dns::nameserver_tcp::TcpNameServer;
use crate::app::dns::nameserver_udp::UdpNameServer;
use crate::app::router::Router;
use crate::app::router::condition::{DomainMatcher, IpMatcher};
use crate::common::errors::{Error, Result};
use crate::features::dns::client::{DnsClient as DnsClientTrait, IPOption};
use crate::features::feature::{Feature, TYPE_DNS_CLIENT};
use crate::features::outbound::OutboundHandler;

#[derive(Debug, Clone, Default)]
pub struct DnsServerConfig {
    pub address: String,
    pub domains: Vec<String>,
    pub expect_ips: Vec<String>,
    pub skip_fallback: bool,
    pub query_strategy: Option<QueryStrategy>,
    pub tag: Option<String>,
    pub client_ip: Option<IpAddr>,
}

struct ServerEntry {
    ns: Arc<dyn NameServer>,
    domain_matchers: Vec<DomainMatcher>,
    expect_ip_matchers: Vec<IpMatcher>,
    skip_fallback: bool,
    query_strategy: Option<QueryStrategy>,
    is_fakedns: bool,
}

pub struct DnsClient {
    hosts: Arc<StaticHosts>,
    cache: Arc<CacheController>,
    servers: Vec<DnsServerConfig>,
    entries: Vec<ServerEntry>,
    nameservers: Vec<Arc<dyn NameServer>>,
    query_strategy: QueryStrategy,
    disable_cache: bool,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    fakedns_holder: Option<Arc<FakeDnsHolder>>,
    routing_ctx: Arc<OnceLock<DohRoutingCtx>>,
}

impl Default for DnsClient {
    fn default() -> Self { Self::new() }
}

impl DnsClient {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(StaticHosts::new()),
            cache: Arc::new(CacheController::new("default".into(), false, false, Duration::from_secs(0))),
            servers: Vec::new(), entries: Vec::new(), nameservers: Vec::new(), query_strategy: QueryStrategy::UseIP,
            disable_cache: false, disable_fallback: false, disable_fallback_if_match: false,
            fakedns_holder: None, routing_ctx: Arc::new(OnceLock::new()),
        }
    }
    pub fn attach_routing(&self, router: Router, outbounds: HashMap<String, Arc<dyn OutboundHandler>>) {
        let _ = self.routing_ctx.set(DohRoutingCtx {
            router,
            outbounds,
            hosts: self.hosts.clone(),
        });
    }
    pub fn with_hosts(hosts_map: HashMap<String, Vec<IpAddr>>) -> Self {
        let client = Self::new();
        for (domain, ips) in hosts_map { client.hosts.add_exact(&domain, ips); }
        client
    }
    pub fn set_query_strategy(&mut self, strategy: QueryStrategy) { self.query_strategy = strategy; }
    pub fn set_disable_cache(&mut self, disable: bool) { self.disable_cache = disable; }
    pub fn set_disable_fallback(&mut self, disable: bool) { self.disable_fallback = disable; }
    pub fn set_disable_fallback_if_match(&mut self, disable: bool) { self.disable_fallback_if_match = disable; }
    pub fn set_fakedns_holder(&mut self, holder: Arc<FakeDnsHolder>) { self.fakedns_holder = Some(holder); }
    pub fn query_strategy(&self) -> QueryStrategy { self.query_strategy }
    pub fn add_host(&self, domain: &str, ips: Vec<IpAddr>) {
        if let Some(d) = domain.strip_prefix("domain:") {
            self.hosts.add_domain_suffix(d, ips);
        } else if let Some(d) = domain.strip_prefix("full:") {
            self.hosts.add_exact(d, ips);
        } else if let Some(k) = domain.strip_prefix("keyword:") {
            self.hosts.add_keyword(k, ips);
        } else {
            self.hosts.add_exact(domain, ips);
        }
    }
    pub fn add_nameserver(&mut self, ns: Arc<dyn NameServer>) {
        self.entries.push(ServerEntry {
            ns: ns.clone(),
            domain_matchers: Vec::new(),
            expect_ip_matchers: Vec::new(),
            skip_fallback: false,
            query_strategy: None,
            is_fakedns: false,
        });
        self.nameservers.push(ns);
    }
    pub fn add_server(&mut self, server: DnsServerConfig) {
        let addr = server.address.trim();
        let mut is_fakedns = false;
        let parse_sa = |s: &str| {
            s.parse::<SocketAddr>().ok().or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
        };
        let ns: Option<Arc<dyn NameServer>> = if addr.eq_ignore_ascii_case("fakedns") {
            is_fakedns = true;
            let holder = self.fakedns_holder.get_or_insert_with(|| {
                Arc::new(FakeDnsHolder::new("198.18.0.0/15").expect("valid default FakeDNS CIDR"))
            });
            Some(Arc::new(FakeDnsNameServer::new(holder.clone())))
        } else if let Some(rest) = addr.strip_prefix("https+local://") {
            Some(Arc::new(DohNameServer::new_local_with_ecs(format!("https://{}", rest), server.client_ip)))
        } else if addr.starts_with("https://") || addr.starts_with("http://") {
            Some(Arc::new(DohNameServer::new_routed(
                addr,
                server.tag.clone(),
                self.routing_ctx.clone(),
                server.client_ip,
            )))
        } else if addr.eq_ignore_ascii_case("local") || addr.eq_ignore_ascii_case("localhost") {
            Some(Arc::new(LocalNameServer::new()))
        } else if let Some(s) = addr.strip_prefix("tcp+local://") {
            parse_sa(s).map(|sa| Arc::new(TcpNameServer::new_local_with_ecs(sa, server.client_ip)) as _)
        } else if let Some(s) = addr.strip_prefix("tcp://") {
            parse_sa(s).map(|sa| {
                Arc::new(TcpNameServer::new_routed(
                    sa,
                    server.tag.clone(),
                    self.routing_ctx.clone(),
                    server.client_ip,
                )) as _
            })
        } else if let Some(s) = addr.strip_prefix("udp+local://") {
            parse_sa(s).map(|sa| Arc::new(UdpNameServer::new_local_with_ecs(sa, server.client_ip)) as _)
        } else {
            parse_sa(addr.strip_prefix("udp://").unwrap_or(addr)).map(|sa| {
                Arc::new(UdpNameServer::new_routed(
                    sa,
                    server.tag.clone(),
                    self.routing_ctx.clone(),
                    server.client_ip,
                )) as _
            })
        };
        if let Some(ns) = ns {
            self.entries.push(ServerEntry {
                ns: ns.clone(),
                domain_matchers: server.domains.iter().map(|d| DomainMatcher::parse(d)).collect(),
                expect_ip_matchers: server.expect_ips.iter().filter_map(|ip| IpMatcher::parse(ip)).collect(),
                skip_fallback: server.skip_fallback,
                query_strategy: server.query_strategy,
                is_fakedns,
            });
            self.nameservers.push(ns);
        }
        self.servers.push(server);
    }
    fn resolve_ip_flags(strategy: QueryStrategy, option: &IPOption) -> (bool, bool) {
        match strategy {
            QueryStrategy::UseIPv4 => (option.ipv4_enable, false),
            QueryStrategy::UseIPv6 => (false, option.ipv6_enable),
            QueryStrategy::UseIP => (option.ipv4_enable, option.ipv6_enable),
        }
    }
    fn cache_key(clean: &str, v4: bool, v6: bool) -> String {
        format!("{}|{}{}", clean, u8::from(v4), u8::from(v6))
    }
    fn filter_ips_with_strategy(strategy: QueryStrategy, ips: &[IpAddr], option: &IPOption) -> Vec<IpAddr> {
        let (v4, v6) = Self::resolve_ip_flags(strategy, option);
        ips.iter().copied().filter(|ip| if ip.is_ipv4() { v4 } else { v6 }).collect()
    }
    fn filter_ips(&self, ips: &[IpAddr], option: &IPOption) -> Vec<IpAddr> {
        Self::filter_ips_with_strategy(self.query_strategy, ips, option)
    }
    async fn query_entry(&self, entry: &ServerEntry, clean: &str, option: &IPOption) -> Option<(Vec<IpAddr>, u32)> {
        if entry.is_fakedns && !option.fake_enable { return None; }
        let strategy = entry.query_strategy.unwrap_or(self.query_strategy);
        let (v4, v6) = Self::resolve_ip_flags(strategy, option);
        if !v4 && !v6 { return None; }
        let (ips, ttl) = match entry.ns.query_ip_with_opt(clean, v4, v6).await {
            Ok((ips, ttl)) if !ips.is_empty() => (ips, ttl),
            Ok(_) => return None,
            Err(e) => { tracing::warn!("DNS nameserver '{}' failed for '{}': {}", entry.ns.name(), clean, e); return None; }
        };
        let mut filtered = Self::filter_ips_with_strategy(strategy, &ips, option);
        if !entry.expect_ip_matchers.is_empty() {
            filtered.retain(|ip| entry.expect_ip_matchers.iter().any(|m| m.matches(ip)));
        }
        if filtered.is_empty() {
            tracing::debug!("DNS nameserver '{}' returned {:?} for '{}', all filtered out by strategy/expectIPs", entry.ns.name(), ips, clean);
            return None;
        }
        let ttl = if entry.is_fakedns { 1 } else { ttl.max(1) };
        if !self.disable_cache && !entry.is_fakedns && !entry.ns.is_disable_cache() {
            let key = Self::cache_key(clean, v4, v6);
            self.cache.set(&key, filtered.clone(), Duration::from_secs(ttl as u64));
        }
        Some((filtered, ttl))
    }
    fn get_cached(&self, clean: &str, option: &IPOption) -> Option<Vec<IpAddr>> {
        if self.disable_cache { return None; }
        let (v4, v6) = Self::resolve_ip_flags(self.query_strategy, option);
        if !v4 && !v6 { return None; }
        self.cache
            .get(&Self::cache_key(clean, v4, v6))
            .or_else(|| self.cache.get(&Self::cache_key(clean, true, true)))
    }
    pub fn lookup_cached_or_hosts(&self, domain: &str) -> Vec<IpAddr> {
        let (clean, opt) = (domain.trim_end_matches('.'), IPOption::default());
        for ips in [self.hosts.lookup(clean), self.get_cached(clean, &opt)].into_iter().flatten() {
            let filtered = self.filter_ips(&ips, &opt);
            if !filtered.is_empty() { return filtered; }
        }
        Vec::new()
    }
    pub fn lookup_hosts_or_cache_ipv6(&self, domain: &str) -> Vec<IpAddr> {
        let (clean, opt) = (domain.trim_end_matches('.'), IPOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false });
        for ips in [self.hosts.lookup(clean), self.get_cached(clean, &opt)].into_iter().flatten() {
            let filtered = self.filter_ips(&ips, &opt);
            if !filtered.is_empty() { return filtered; }
        }
        Vec::new()
    }
    pub async fn lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.lookup_ip_with_option(domain, IPOption::default()).await.map(|(ips, _)| ips)
    }
    pub async fn lookup_for_dialer(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let (clean, option) = (domain.trim_end_matches('.'), IPOption::default());
        for ips in [self.hosts.lookup(clean), self.get_cached(clean, &option)].into_iter().flatten() {
            let filtered = self.filter_ips(&ips, &option);
            if !filtered.is_empty() { return Ok(filtered); }
        }
        let mut tried = vec![false; self.entries.len()];
        for (idx, entry) in self.entries.iter().enumerate() {
            if !entry.is_fakedns
                && !entry.ns.routes_via_proxy() && entry.domain_matchers.iter().any(|m| m.matches(clean))
            {
                tried[idx] = true;
                if let Some((ips, _)) = self.query_entry(entry, clean, &option).await { return Ok(ips); }
            }
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            if !tried[idx]
                && !entry.is_fakedns
                && !entry.ns.routes_via_proxy() && let Some((ips, _)) = self.query_entry(entry, clean, &option).await
            { return Ok(ips); }
        }
        Err(Error::NotFound(format!("No direct/local IP found for dialer domain: {}", domain)))
    }
    pub async fn lookup_ip_with_option(&self, domain: &str, option: IPOption) -> Result<(Vec<IpAddr>, u32)> {
        let clean = domain.trim_end_matches('.');
        if let Some(ips) = self.hosts.lookup(clean) {
            let filtered = self.filter_ips(&ips, &option);
            return if !filtered.is_empty() {
                Ok((filtered, 10))
            } else {
                Err(Error::NotFound(format!("Static host '{}' has no IP matching strategy", domain)))
            };
        }
        if let Some(ips) = self.get_cached(clean, &option) {
            let filtered = self.filter_ips(&ips, &option);
            if !filtered.is_empty() { return Ok((filtered, 60)); }
        }
        let mut tried = vec![false; self.entries.len()];
        let mut any_domain_matched = false;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.domain_matchers.iter().any(|m| m.matches(clean)) {
                any_domain_matched = true;
                tried[idx] = true;
                if let Some(res) = self.query_entry(entry, clean, &option).await { return Ok(res); }
            }
        }
        if !self.disable_fallback && !(self.disable_fallback_if_match && any_domain_matched) {
            for (idx, entry) in self.entries.iter().enumerate() {
                if tried[idx] || entry.skip_fallback { continue; }
                if let Some(res) = self.query_entry(entry, clean, &option).await { return Ok(res); }
            }
            #[cfg(not(target_os = "android"))]
            if self.entries.is_empty() && let Ok(ips) = LocalNameServer::new().query_ip(clean).await
            {
                let filtered = self.filter_ips(&ips, &option);
                if !filtered.is_empty() {
                    if !self.disable_cache {
                        let (v4, v6) = Self::resolve_ip_flags(self.query_strategy, &option);
                        self.cache.set(&Self::cache_key(clean, v4, v6), filtered.clone(), Duration::from_secs(300));
                    }
                    return Ok((filtered, 300));
                }
            }
        }
        Err(Error::NotFound(format!("No IP found for domain: {}", domain)))
    }
    pub fn r#type(&self) -> &'static str { TYPE_DNS_CLIENT }
    pub fn is_own_link(&self, inbound_tag: &str) -> bool {
        self.servers.iter().any(|s| s.tag.as_deref() == Some(inbound_tag))
    }
}

impl Feature for DnsClient {
    fn feature_type(&self) -> &'static str { TYPE_DNS_CLIENT }
    fn start(&self) -> Result<()> { Ok(()) }
    fn close(&self) -> Result<()> { Ok(()) }
}

#[async_trait]
impl DnsClientTrait for DnsClient {
    async fn lookup_ip_with_option(&self, domain: &str, option: IPOption) -> Result<(Vec<IpAddr>, u32)> {
        DnsClient::lookup_ip_with_option(self, domain, option).await
    }
}

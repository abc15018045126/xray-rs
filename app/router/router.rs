use super::balancing::Balancer;
use super::condition::Rule;
use crate::common::errors::{Error, Result};
use crate::common::net::Address;
use crate::common::protocol::SessionContext;
use crate::features::feature::{Feature, TYPE_ROUTER};
use crate::features::routing::context::RoutingContext;
use crate::features::routing::{Router as CoreRouterTrait, RouterFeature};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ipifnonmatch" | "ip_if_non_match" => Self::IpIfNonMatch,
            "ipondemand" | "ip_on_demand" => Self::IpOnDemand,
            _ => Self::AsIs,
        }
    }
}

pub type DomainIpResolverFn = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

#[derive(Clone)]
pub struct Router {
    pub domain_strategy: DomainStrategy,
    pub rules: Vec<Rule>,
    pub balancers: HashMap<String, Arc<Balancer>>,
    pub default_tag: Option<String>,
    ip_resolver: Option<DomainIpResolverFn>,
}

impl Router {
    pub fn new(rules: Vec<Rule>, default_tag: Option<String>) -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules,
            balancers: HashMap::new(),
            default_tag,
            ip_resolver: None,
        }
    }
    pub fn with_balancers(
        rules: Vec<Rule>,
        balancers: HashMap<String, Arc<Balancer>>,
        default_tag: Option<String>,
    ) -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules,
            balancers,
            default_tag,
            ip_resolver: None,
        }
    }
    pub fn set_domain_strategy(&mut self, strategy: DomainStrategy) { self.domain_strategy = strategy; }
    pub fn set_ip_resolver(&mut self, resolver: DomainIpResolverFn) { self.ip_resolver = Some(resolver); }
    pub fn add_balancer(&mut self, tag: impl Into<String>, balancer: Arc<Balancer>) {
        self.balancers.insert(tag.into(), balancer);
    }
    pub fn add_rule(&mut self, rule: Rule, append: bool) {
        if append {
            self.rules.push(rule);
        } else {
            self.rules.insert(0, rule);
        }
    }
    pub fn remove_rule(&mut self, rule_tag: &str) -> Result<()> {
        let before = self.rules.len();
        self.rules.retain(|r| r.tag != rule_tag);
        if self.rules.len() == before { return Err(Error::Other(format!("rule '{}' not found", rule_tag))); }
        Ok(())
    }
    pub fn list_rule(&self) -> &[Rule] { &self.rules }
    pub fn r#type(&self) -> &'static str { TYPE_ROUTER }
    pub fn start(&self) -> Result<()> { Ok(()) }
    pub fn close(&self) -> Result<()> { Ok(()) }
    fn session_domain(session: &SessionContext) -> Option<&str> {
        session
            .route_target
            .as_ref()
            .and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None })
            .or(session.sniffed_domain.as_deref())
            .or(match &session.destination.address { Address::Domain(s) => Some(s.as_str()), _ => None })
            .or_else(|| session.original_destination.as_ref().and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None }))
    }
    fn resolve_domain_ips(&self, domain: &str, port: u16) -> Vec<IpAddr> {
        if let Some(ref f) = self.ip_resolver {
            let ips = f(domain);
            if !ips.is_empty() { return ips; }
        }
        (domain, port).to_socket_addrs().map(|it| it.map(|sa| sa.ip()).collect()).unwrap_or_default()
    }
    fn resolve_rule_target<'a>(&'a self, rule: &'a Rule) -> Option<&'a str> {
        if let Some(b) = rule.balancer_tag.as_ref().and_then(|t| self.balancers.get(t))
            && let Some(picked) = b.pick()
            && let Some(found) = b.candidates.iter().chain(&b.selectors).find(|s| **s == picked)
        {
            return Some(found.as_str());
        }
        (!rule.tag.is_empty()).then_some(rule.tag.as_str())
    }
}

impl Feature for Router {
    fn feature_type(&self) -> &'static str { TYPE_ROUTER }
}

impl RouterFeature for Router {
    fn pick_outbound(&self, session: &SessionContext) -> Option<&str> {
        let mut cached_ips: Option<Vec<IpAddr>> = None;
        let mut cached_proc = None;
        for rule in &self.rules {
            let extra_ips: &[IpAddr] = if self.domain_strategy == DomainStrategy::IpOnDemand && !rule.ip_matchers.is_empty() {
                if cached_ips.is_none() {
                    cached_ips = Some(
                        Self::session_domain(session)
                            .map(|d| self.resolve_domain_ips(d, session.destination.port))
                            .unwrap_or_default(),
                    );
                }
                cached_ips.as_deref().unwrap_or(&[])
            } else {
                &[]
            };
            if rule.matches_with_cache(session, extra_ips, &mut cached_proc)
                && let Some(target) = self.resolve_rule_target(rule)
            {
                return Some(target);
            }
        }
        if self.domain_strategy == DomainStrategy::IpIfNonMatch
            && let Some(domain) = Self::session_domain(session)
        {
            let ips = self.resolve_domain_ips(domain, session.destination.port);
            if !ips.is_empty() {
                for rule in &self.rules {
                    if rule.matches_with_cache(session, &ips, &mut cached_proc)
                        && let Some(target) = self.resolve_rule_target(rule)
                    {
                        return Some(target);
                    }
                }
            }
        }
        self.default_tag.as_deref()
    }
}

#[async_trait]
impl CoreRouterTrait for Router {
    async fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<String> {
        let in_tag = ctx.get_inbound_tag();
        let target_port = ctx.get_target_port();
        let target_domain = ctx.get_target_domain();
        let target_ips = ctx.get_target_ips();
        let net = ctx.get_network();
        let proto = ctx.get_protocol();
        let user = ctx.get_user();
        let src_ips = ctx.get_source_ips();
        let src_port = ctx.get_source_port();
        let src_addr = (!src_ips.is_empty() && src_port > 0).then(|| std::net::SocketAddr::new(src_ips[0], src_port));
        let is_tcp = net == crate::common::net::Network::Tcp;
        let eval_pass = |ips: &[IpAddr]| -> Option<String> {
            for rule in &self.rules {
                if !rule.matches_local_os() { continue; }
                if !rule.process.is_empty() && !rule.matches_process(src_addr, is_tcp) { continue; }
                if !rule.inbound_tags.is_empty() && !rule.inbound_tags.iter().any(|t| t == in_tag) { continue; }
                if rule.network.is_some_and(|r_net| r_net != net) { continue; }
                if (!rule.ports.is_empty() || !rule.port_ranges.is_empty())
                    && !rule.ports.contains(&target_port)
                    && !rule.port_ranges.iter().any(|&(s, e)| (s..=e).contains(&target_port))
                { continue; }
                if (!rule.source_ports.is_empty() || !rule.source_port_ranges.is_empty())
                    && !rule.source_ports.contains(&src_port)
                    && !rule.source_port_ranges.iter().any(|&(s, e)| (s..=e).contains(&src_port))
                { continue; }
                if !rule.source_ip_matchers.is_empty()
                    && !src_ips.iter().any(|ip| rule.source_ip_matchers.iter().any(|m| m.matches(ip)))
                { continue; }
                if !rule.protocols.is_empty() && !proto.is_some_and(|p| rule.matches_protocol(p)) { continue; }
                if !rule.user_emails.is_empty() && !user.is_some_and(|u| rule.matches_user(u)) { continue; }
                if !rule.domain_matchers.is_empty()
                    && !target_domain.is_some_and(|d| rule.domain_matchers.iter().any(|m| m.matches(d)))
                { continue; }
                if !rule.ip_matchers.is_empty() && !ips.iter().any(|ip| rule.matches_destination_ip(ip)) {
                    continue;
                }
                if let Some(btag) = &rule.balancer_tag && let Some(picked) = self.balancers.get(btag).and_then(|b| b.pick())
                { return Some(picked); }
                if !rule.tag.is_empty() { return Some(rule.tag.clone()); }
            }
            None
        };
        let mut first_ips = target_ips.to_vec();
        if self.domain_strategy == DomainStrategy::IpOnDemand && first_ips.is_empty()
            && let Some(d) = target_domain
        {
            first_ips = self.resolve_domain_ips(d, target_port);
        }
        if let Some(picked) = eval_pass(&first_ips) { return Ok(picked); }
        if self.domain_strategy == DomainStrategy::IpIfNonMatch && first_ips.is_empty()
            && let Some(d) = target_domain
        {
            let resolved = self.resolve_domain_ips(d, target_port);
            if !resolved.is_empty() && let Some(picked) = eval_pass(&resolved) {
                return Ok(picked);
            }
        }
        self.default_tag.clone().ok_or_else(|| Error::NotFound("No matching route found".into()))
    }
}

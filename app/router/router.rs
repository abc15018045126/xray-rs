use super::balancing::Balancer;
use super::condition::Rule;
use crate::common::errors::{Error, Result};
use crate::common::protocol::SessionContext;
use crate::features::feature::{Feature, TYPE_ROUTER};
use crate::features::routing::context::RoutingContext;
use crate::features::routing::{Router as CoreRouterTrait, RouterFeature};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

#[derive(Clone)]
pub struct Router {
    pub domain_strategy: DomainStrategy,
    pub rules: Vec<Rule>,
    pub balancers: HashMap<String, Arc<Balancer>>,
    pub default_tag: Option<String>,
}

impl Router {
    pub fn new(rules: Vec<Rule>, default_tag: Option<String>) -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules,
            balancers: HashMap::new(),
            default_tag,
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
        }
    }
    pub fn set_domain_strategy(&mut self, strategy: DomainStrategy) { self.domain_strategy = strategy; }
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
}

impl Feature for Router {
    fn feature_type(&self) -> &'static str { TYPE_ROUTER }
}

impl RouterFeature for Router {
    fn pick_outbound(&self, session: &SessionContext) -> Option<&str> {
        for rule in self.rules.iter().filter(|r| r.matches(session)) {
            if let Some(b) = rule.balancer_tag.as_ref().and_then(|t| self.balancers.get(t))
                && let Some(picked) = b.pick()
                && let Some(found) = b.candidates.iter().chain(&b.selectors).find(|s| **s == picked)
            { return Some(found.as_str()); }
            if !rule.tag.is_empty() { return Some(&rule.tag); }
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
        for rule in &self.rules {
            if !rule.process.is_empty() && !rule.matches_process(src_addr, is_tcp) { continue; }
            if !rule.inbound_tags.is_empty() && !rule.inbound_tags.iter().any(|t| t == in_tag) { continue; }
            if rule.network.is_some_and(|r_net| r_net != net) { continue; }
            if (!rule.ports.is_empty() || !rule.port_ranges.is_empty())
                && !rule.ports.contains(&target_port)
                && !rule.port_ranges.iter().any(|&(s, e)| (s..=e).contains(&target_port))
            { continue; }
            if !rule.source_ports.is_empty() && !rule.source_ports.contains(&src_port) { continue; }
            if !rule.source_ip_matchers.is_empty()
                && !src_ips.iter().any(|ip| rule.source_ip_matchers.iter().any(|m| m.matches(ip)))
            { continue; }
            if !rule.protocols.is_empty()
                && !proto.is_some_and(|p| rule.protocols.iter().any(|rp| rp.eq_ignore_ascii_case(p)))
            { continue; }
            if !rule.user_emails.is_empty() && !user.is_some_and(|u| rule.user_emails.iter().any(|ru| ru == u))
            { continue; }
            let (has_dom, has_ip) = (!rule.domain_matchers.is_empty(), !rule.ip_matchers.is_empty());
            if has_dom || has_ip {
                let dom_ok = has_dom && target_domain.is_some_and(|d| rule.domain_matchers.iter().any(|m| m.matches(d)));
                let ip_ok = !dom_ok && has_ip && target_ips.iter().any(|ip| rule.matches_destination_ip(ip));
                if !dom_ok && !ip_ok { continue; }
            }
            if let Some(btag) = &rule.balancer_tag && let Some(picked) = self.balancers.get(btag).and_then(|b| b.pick())
            { return Ok(picked); }
            if !rule.tag.is_empty() { return Ok(rule.tag.clone()); }
        }
        self.default_tag.clone().ok_or_else(|| Error::NotFound("No matching route found".into()))
    }
}

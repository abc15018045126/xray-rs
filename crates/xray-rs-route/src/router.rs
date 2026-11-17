use std::net::IpAddr;

use ipnet::IpNet;
use xray_rs_types::{Address, Network, SessionContext};

use crate::geo::GLOBAL_GEO_DB;

#[derive(Debug, Clone)]
pub enum DomainRule {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Private,
    GeoSite(String),
}

impl DomainRule {
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.trim().to_ascii_lowercase();
        if lower == "geosite:private" {
            Some(Self::Private)
        } else if let Some(code) = lower.strip_prefix("geosite:") {
            Some(Self::GeoSite(code.to_string()))
        } else if let Some(rest) = lower.strip_prefix("full:") {
            Some(Self::Exact(rest.to_string()))
        } else if let Some(rest) = lower.strip_prefix("domain:") {
            Some(Self::Suffix(rest.to_string()))
        } else if let Some(rest) = lower.strip_prefix("keyword:") {
            Some(Self::Keyword(rest.to_string()))
        } else {
            Some(Self::Suffix(lower))
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        match self {
            Self::Exact(d) => h == *d,
            Self::Suffix(d) => h == *d || h.ends_with(&format!(".{}", d)),
            Self::Keyword(k) => h.contains(k.as_str()),
            Self::Private => {
                h == "localhost"
                    || h.ends_with(".local")
                    || h.ends_with(".localhost")
                    || h.ends_with(".lan")
                    || h.ends_with(".internal")
            }
            Self::GeoSite(code) => GLOBAL_GEO_DB.match_geosite(code, &h),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpRule {
    Net(IpNet),
    Private,
    GeoIp(String),
}

impl IpRule {
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("geoip:private") {
            return Some(Self::Private);
        }
        if let Some(code) = trimmed.to_ascii_lowercase().strip_prefix("geoip:") {
            return Some(Self::GeoIp(code.to_string()));
        }
        if let Ok(net) = trimmed.parse::<IpNet>() {
            return Some(Self::Net(net));
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Some(Self::Net(IpNet::from(ip)));
        }
        None
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::Net(net) => net.contains(&ip),
            Self::Private => match ip {
                IpAddr::V4(v4) => {
                    v4.is_private()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_multicast()
                }
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
            },
            Self::GeoIp(code) => GLOBAL_GEO_DB.match_geoip(code, &ip),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteRule {
    pub outbound_tag: String,
    pub network: Option<Network>,
    pub inbound_tags: Vec<String>,
    pub protocols: Vec<String>,
    pub domains: Vec<DomainRule>,
    pub ports: Vec<u16>,
    pub ip_rules: Vec<IpRule>,
}

impl RouteRule {
    pub fn new(outbound_tag: impl Into<String>) -> Self {
        Self {
            outbound_tag: outbound_tag.into(),
            network: None,
            inbound_tags: Vec::new(),
            protocols: Vec::new(),
            domains: Vec::new(),
            ports: Vec::new(),
            ip_rules: Vec::new(),
        }
    }

    pub fn matches(&self, session: &SessionContext) -> bool {
        if let Some(net) = self.network
            && session.destination.network != net
        {
            return false;
        }

        if !self.inbound_tags.is_empty()
            && !self.inbound_tags.iter().any(|t| t == &session.inbound_tag)
        {
            return false;
        }

        if !self.protocols.is_empty() {
            let matched = session
                .sniffed_protocol
                .as_deref()
                .is_some_and(|p| self.protocols.iter().any(|rp| rp.eq_ignore_ascii_case(p)));
            if !matched {
                return false;
            }
        }

        if !self.ports.is_empty() && !self.ports.contains(&session.destination.port) {
            return false;
        }

        if !self.domains.is_empty() {
            let domain = session
                .sniffed_domain
                .as_deref()
                .or(match &session.destination.address {
                    Address::Domain(d) => Some(d.as_str()),
                    _ => None,
                });
            match domain {
                Some(d) if self.domains.iter().any(|r| r.matches(d)) => {}
                _ => return false,
            }
        }

        if !self.ip_rules.is_empty() {
            match session.destination.address.as_ip() {
                Some(ip) if self.ip_rules.iter().any(|r| r.matches(ip)) => {}
                _ => return false,
            }
        }

        true
    }
}

/// Rule-based traffic router.
#[derive(Debug, Default)]
pub struct Router {
    rules: Vec<RouteRule>,
}

impl Router {
    pub fn new(rules: Vec<RouteRule>) -> Self {
        Self { rules }
    }

    pub fn pick_outbound(&self, session: &SessionContext) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| r.matches(session))
            .map(|r| r.outbound_tag.as_str())
    }
}

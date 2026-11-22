use crate::app::router::geo::GeoDatabase;
use crate::common::net::{Address, Network};
use crate::common::protocol::SessionContext;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

static GLOBAL_GEO_DB: LazyLock<GeoDatabase> = LazyLock::new(GeoDatabase::new);

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Plain(String),
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(Regex),
    GeoSite(String, bool),
}

impl DomainMatcher {
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some(pat) = s.strip_prefix("regexp:").or_else(|| s.strip_prefix("REGEXP:"))
            && let Ok(re) = Regex::new(pat)
        {
            return Self::Regex(re);
        }
        let lower = s.to_lowercase();
        let parse_geosite_tag = |raw: &str, neg_outer: bool| -> Self {
            let (neg_inner, tag) = match raw.strip_prefix('!') {
                Some(t) => (true, t),
                None => (false, raw),
            };
            Self::GeoSite(tag.to_string(), neg_outer ^ neg_inner)
        };
        if let Some(r) = lower.strip_prefix("!geosite:") { return parse_geosite_tag(r, true); }
        if let Some(r) = lower.strip_prefix("geosite:") { return parse_geosite_tag(r, false); }
        if let Some(r) = lower.strip_prefix("ext:") {
            if let Some((_, t)) = r.rsplit_once(':').filter(|(_, t)| !t.is_empty()) {
                return parse_geosite_tag(t, false);
            }
            return Self::Plain(lower);
        }
        if let Some(r) = lower.strip_prefix("full:") { Self::Exact(r.trim_end_matches('.').to_string()) }
        else if let Some(r) = lower.strip_prefix("domain:") { Self::Suffix(r.trim_end_matches('.').to_string()) }
        else if let Some(r) = lower.strip_prefix("keyword:") { Self::Keyword(r.to_string()) }
        else { Self::Plain(lower) }
    }
    pub fn matches(&self, domain: &str) -> bool {
        let d_raw = domain.trim_end_matches('.');
        if let DomainMatcher::Regex(re) = self { return re.is_match(d_raw); }
        let d = d_raw.to_lowercase();
        match self {
            DomainMatcher::Exact(pattern) => d == *pattern,
            DomainMatcher::Suffix(pattern) => {
                d == *pattern
                    || (d.len() > pattern.len()
                        && d.ends_with(pattern.as_str())
                        && d.as_bytes()[d.len() - pattern.len() - 1] == b'.')
            }
            DomainMatcher::Keyword(pattern) | DomainMatcher::Plain(pattern) => d.contains(pattern.as_str()),
            DomainMatcher::Regex(re) => re.is_match(&d),
            DomainMatcher::GeoSite(group, invert) => GLOBAL_GEO_DB.match_geosite(group, &d) ^ invert,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    Exact(IpAddr),
    CidrV4(Ipv4Addr, u8),
    CidrV6(Ipv6Addr, u8),
    Private(bool),
    GeoIp(String, bool),
}

impl IpMatcher {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let lower = s.to_lowercase();
        let geo = |raw: &str, neg_outer: bool| -> Self {
            let (neg_inner, tag) = match raw.strip_prefix('!') {
                Some(t) => (true, t),
                None => (false, raw),
            };
            let inv = neg_outer ^ neg_inner;
            if tag == "private" { Self::Private(inv) } else { Self::GeoIp(tag.to_string(), inv) }
        };
        if let Some(rest) = lower.strip_prefix("!geoip:") { return Some(geo(rest, true)); }
        if let Some(rest) = lower.strip_prefix("geoip:") { return Some(geo(rest, false)); }
        if let Some(rest) = lower.strip_prefix("ext:") {
            return rest.rsplit_once(':').filter(|(_, t)| !t.is_empty()).map(|(_, t)| geo(t, false));
        }
        if lower == "private" { return Some(Self::Private(false)); }
        if lower == "!private" { return Some(Self::Private(true)); }
        if let Some((ip_part, mask_part)) = s.split_once('/') && let Ok(mask) = mask_part.parse::<u8>() {
            if let Ok(v4) = Ipv4Addr::from_str(ip_part) { return Some(Self::CidrV4(v4, mask)); }
            if let Ok(v6) = Ipv6Addr::from_str(ip_part) { return Some(Self::CidrV6(v6, mask)); }
        }
        IpAddr::from_str(s).ok().map(Self::Exact)
    }
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IpMatcher::Exact(target_ip) => ip == target_ip,
            IpMatcher::Private(invert) => {
                let hit = match ip {
                    IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
                    IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || (v6.segments()[0] & 0xfe00) == 0xfc00,
                };
                hit ^ invert
            }
            IpMatcher::CidrV4(net, mask) => {
                if let IpAddr::V4(v4) = ip {
                    if *mask == 0 { return true; }
                    if *mask > 32 { return false; }
                    let net_u32 = u32::from_be_bytes(net.octets());
                    let ip_u32 = u32::from_be_bytes(v4.octets());
                    let mask_u32 = !0u32 << (32 - mask);
                    (ip_u32 & mask_u32) == (net_u32 & mask_u32)
                } else {
                    false
                }
            }
            IpMatcher::CidrV6(net, mask) => {
                if let IpAddr::V6(v6) = ip {
                    if *mask == 0 { return true; }
                    if *mask > 128 { return false; }
                    let net_u128 = u128::from_be_bytes(net.octets());
                    let ip_u128 = u128::from_be_bytes(v6.octets());
                    let mask_u128 = !0u128 << (128 - mask);
                    (ip_u128 & mask_u128) == (net_u128 & mask_u128)
                } else {
                    false
                }
            }
            IpMatcher::GeoIp(group, invert) => GLOBAL_GEO_DB.match_geoip(group, ip) ^ invert,
        }
    }
}

fn current_goos() -> &'static str {
    if cfg!(target_os = "windows") { "windows" }
    else if cfg!(target_os = "android") { "android" }
    else if cfg!(target_os = "macos") { "darwin" }
    else if cfg!(target_os = "freebsd") { "freebsd" }
    else { "linux" }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub tag: String,
    pub balancer_tag: Option<String>,
    pub inbound_tags: Vec<String>,
    pub domain_matchers: Vec<DomainMatcher>,
    pub ip_matchers: Vec<IpMatcher>,
    pub source_ip_matchers: Vec<IpMatcher>,
    pub ports: Vec<u16>,
    pub port_ranges: Vec<(u16, u16)>,
    pub source_ports: Vec<u16>,
    pub source_port_ranges: Vec<(u16, u16)>,
    pub network: Option<Network>,
    pub protocols: Vec<String>,
    pub user_emails: Vec<String>,
    pub process: Vec<String>,
    pub local_os: Vec<String>,
}

impl Rule {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(), balancer_tag: None, inbound_tags: Vec::new(), domain_matchers: Vec::new(),
            ip_matchers: Vec::new(), source_ip_matchers: Vec::new(), ports: Vec::new(), port_ranges: Vec::new(),
            source_ports: Vec::new(), source_port_ranges: Vec::new(), network: None, protocols: Vec::new(),
            user_emails: Vec::new(), process: Vec::new(), local_os: Vec::new(),
        }
    }
    pub fn with_balancer(balancer_tag: impl Into<String>) -> Self {
        let mut r = Self::new("");
        r.balancer_tag = Some(balancer_tag.into());
        r
    }
    pub fn matches_destination_ip(&self, ip: &IpAddr) -> bool {
        self.ip_matchers.iter().any(|m| m.matches(ip))
    }
    pub fn matches_user(&self, email: &str) -> bool {
        self.user_emails.iter().any(|pat| {
            if let Some(re_str) = pat.strip_prefix("regexp:") {
                Regex::new(re_str).is_ok_and(|re| re.is_match(email))
            } else {
                pat == email
            }
        })
    }
    pub fn matches_protocol(&self, proto: &str) -> bool {
        let p_low = proto.to_ascii_lowercase();
        self.protocols.iter().any(|rp| p_low.starts_with(&rp.to_ascii_lowercase()))
    }
    pub fn matches_local_os(&self) -> bool {
        let os = current_goos();
        self.local_os.is_empty() || self.local_os.iter().any(|n| n.eq_ignore_ascii_case(os))
    }
    pub fn matches_process(&self, src: Option<std::net::SocketAddr>, is_tcp: bool) -> bool {
        if self.process.is_empty() { return true; }
        let Some(src) = src else { return false };
        let Ok(Some(info)) = crate::common::net::ProcessFinder::find_process_by_socket(src, is_tcp) else {
            return false;
        };
        let cur_pid = std::process::id();
        self.process.iter().any(|p| {
            let p = p.replace('\\', "/");
            if p == "self/" {
                info.pid == cur_pid
            } else if p == "xray/" {
                info.pid == cur_pid || info.name.eq_ignore_ascii_case("xray")
            } else if p.ends_with('/') {
                info.path.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase())
            } else if p.contains('/') {
                info.path.eq_ignore_ascii_case(&p)
            } else {
                info.name.eq_ignore_ascii_case(p.trim_end_matches(".exe"))
            }
        })
    }
    pub fn matches(&self, session: &SessionContext) -> bool {
        self.matches_with_ips(session, &[])
    }
    pub fn matches_with_ips(&self, session: &SessionContext, resolved_ips: &[IpAddr]) -> bool {
        if !self.matches_local_os() { return false; }
        if !self.process.is_empty()
            && !self.matches_process(session.source, session.destination.network == Network::Tcp)
        { return false; }
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|tag| tag == &session.inbound_tag)
        { return false; }
        if self.network.is_some_and(|net| net != session.destination.network) { return false; }
        let target_port = session.route_target.as_ref().unwrap_or(&session.destination).port;
        if (!self.ports.is_empty() || !self.port_ranges.is_empty())
            && !self.ports.contains(&target_port)
            && !self.port_ranges.iter().any(|&(s, e)| (s..=e).contains(&target_port))
        { return false; }
        if !self.source_ports.is_empty() || !self.source_port_ranges.is_empty() {
            let sp = session.source.map(|s| s.port()).unwrap_or(0);
            if !self.source_ports.contains(&sp)
                && !self.source_port_ranges.iter().any(|&(s, e)| (s..=e).contains(&sp))
            { return false; }
        }
        if !self.source_ip_matchers.is_empty()
            && !session.source.is_some_and(|s| {
                let ip = s.ip();
                self.source_ip_matchers.iter().any(|m| m.matches(&ip))
            })
        { return false; }
        if !self.protocols.is_empty()
            && !session.sniffed_protocol.as_deref().is_some_and(|proto| self.matches_protocol(proto))
        { return false; }
        if !self.user_emails.is_empty()
            && !session.user.as_ref().is_some_and(|u| self.matches_user(&u.email))
        { return false; }
        if !self.domain_matchers.is_empty() {
            let domain = session
                .route_target
                .as_ref()
                .and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None })
                .or(session.sniffed_domain.as_deref())
                .or(match &session.destination.address { Address::Domain(s) => Some(s.as_str()), _ => None })
                .or_else(|| session.original_destination.as_ref().and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None }));
            if !domain.is_some_and(|d| self.domain_matchers.iter().any(|m| m.matches(d))) {
                return false;
            }
        }
        if !self.ip_matchers.is_empty() {
            let mut ip_matched = [
                session.route_target.as_ref().and_then(|d| d.address.as_ip()),
                session.destination.address.as_ip(),
                session.original_destination.as_ref().and_then(|d| d.address.as_ip()),
            ]
            .into_iter()
            .flatten()
            .any(|ip| self.matches_destination_ip(&ip));
            if !ip_matched && !resolved_ips.is_empty() {
                ip_matched = resolved_ips.iter().any(|ip| self.matches_destination_ip(ip));
            }
            if !ip_matched { return false; }
        }
        true
    }
}

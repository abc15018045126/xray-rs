use crate::common::log::Message;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsStatus {
    Queried,
    CacheHit,
    CacheOptimiste,
}

impl DnsStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsStatus::Queried => "got answer:",
            DnsStatus::CacheHit => "cache HIT:",
            DnsStatus::CacheOptimiste => "cache OPTIMISTE:",
        }
    }
}

impl fmt::Display for DnsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.as_str()) }
}

pub const DNS_QUERIED: &str = "got answer:";
pub const DNS_CACHE_HIT: &str = "cache HIT:";
pub const DNS_CACHE_OPTIMISTE: &str = "cache OPTIMISTE:";

#[derive(Debug, Clone)]
pub struct DnsLog {
    pub server: String,
    pub domain: String,
    pub result: Vec<IpAddr>,
    pub status: DnsStatus,
    pub elapsed: Duration,
    pub error: Option<String>,
}

impl DnsLog {
    pub fn new(server: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            domain: domain.into(),
            result: Vec::new(),
            status: DnsStatus::Queried,
            elapsed: Duration::ZERO,
            error: None,
        }
    }
}

impl Message for DnsLog {
    fn to_log_string(&self) -> String {
        use std::fmt::Write;
        let mut s = format!("{} {} {} -> [", self.server, self.status.as_str(), self.domain);
        for (i, ip) in self.result.iter().enumerate() {
            if i > 0 { s.push_str(", "); }
            let _ = write!(s, "{}", ip);
        }
        s.push(']');
        if self.elapsed > Duration::ZERO { let _ = write!(s, " {:?}", self.elapsed); }
        if let Some(ref err) = self.error { let _ = write!(s, " <{}>", err); }
        s
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

pub fn format_dns_log(domain: &str, ip: &str, rtt_ms: u64) -> String {
    format!("DNS Query: {} -> {} ({}ms)", domain, ip, rtt_ms)
}

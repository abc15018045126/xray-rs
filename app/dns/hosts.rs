use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

pub struct StaticHosts {
    exact: RwLock<HashMap<String, Vec<IpAddr>>>,
    domain_suffix: RwLock<Vec<(String, Vec<IpAddr>)>>,
    keywords: RwLock<Vec<(String, Vec<IpAddr>)>>,
}

impl StaticHosts {
    pub fn new() -> Self {
        Self {
            exact: RwLock::new(HashMap::new()),
            domain_suffix: RwLock::new(Vec::new()),
            keywords: RwLock::new(Vec::new()),
        }
    }
    pub fn add_exact(&self, domain: &str, ips: Vec<IpAddr>) {
        if let Ok(mut guard) = self.exact.write() { guard.insert(domain.to_lowercase(), ips); }
    }
    pub fn add_domain_suffix(&self, suffix: &str, ips: Vec<IpAddr>) {
        if let Ok(mut guard) = self.domain_suffix.write() { guard.push((suffix.to_lowercase(), ips)); }
    }
    pub fn add_keyword(&self, keyword: &str, ips: Vec<IpAddr>) {
        if let Ok(mut guard) = self.keywords.write() { guard.push((keyword.to_lowercase(), ips)); }
    }
    pub fn lookup(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let d = domain.to_lowercase();
        if let Ok(g) = self.exact.read() && let Some(ips) = g.get(&d) { return Some(ips.clone()); }
        if let Ok(g) = self.domain_suffix.read() {
            if let Some((_, ips)) = g.iter().find(|(s, _)| d == **s || d.strip_suffix(s.as_str()).is_some_and(|p| p.ends_with('.'))) {
                return Some(ips.clone());
            }
        }
        if let Ok(g) = self.keywords.read() {
            if let Some((_, ips)) = g.iter().find(|(k, _)| d.contains(k.as_str())) { return Some(ips.clone()); }
        }
        None
    }
}

impl Default for StaticHosts {
    fn default() -> Self { Self::new() }
}

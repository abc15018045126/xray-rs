use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::RwLock;

/// Lightweight FakeDNS pool mapping `198.18.0.0/16` virtual IPs to domains.
pub struct FakeDnsPool {
    next_offset: RwLock<u32>,
    ip_to_domain: RwLock<HashMap<IpAddr, String>>,
    domain_to_ip: RwLock<HashMap<String, IpAddr>>,
}

impl Default for FakeDnsPool {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDnsPool {
    pub fn new() -> Self {
        Self {
            next_offset: RwLock::new(1),
            ip_to_domain: RwLock::new(HashMap::new()),
            domain_to_ip: RwLock::new(HashMap::new()),
        }
    }

    pub fn is_fake_ip(ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] == 18)
    }

    pub fn allocate(&self, domain: &str) -> IpAddr {
        let key = domain.to_ascii_lowercase();
        if let Some(&ip) = self.domain_to_ip.read().unwrap().get(&key) {
            return ip;
        }

        let mut off = self.next_offset.write().unwrap();
        let val = *off;
        *off = if val >= 65534 { 1 } else { val + 1 };

        let ip = IpAddr::V4(Ipv4Addr::new(198, 18, ((val >> 8) & 0xff) as u8, (val & 0xff) as u8));
        self.domain_to_ip.write().unwrap().insert(key.clone(), ip);
        self.ip_to_domain.write().unwrap().insert(ip, key);
        ip
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_domain.read().unwrap().get(&ip).cloned()
    }
}

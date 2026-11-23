use crate::common::errors::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

pub struct FakeDnsHolder {
    pool_start: u32,
    pool_end: u32,
    next_ip: Mutex<u32>,
    domain_to_ip: Mutex<HashMap<String, Ipv4Addr>>,
    ip_to_domain: Mutex<HashMap<Ipv4Addr, String>>,
}

impl FakeDnsHolder {
    pub fn new(cidr: &str) -> Result<Self> {
        let (ip_s, pfx_s) = cidr.split_once('/').filter(|(_, r)| !r.contains('/'))
            .ok_or_else(|| Error::Config("Invalid FakeDNS CIDR format".into()))?;
        let base_ip: Ipv4Addr = ip_s.parse().map_err(|e| Error::Config(format!("Invalid FakeDNS IP: {}", e)))?;
        let prefix_len: u32 = pfx_s.parse().map_err(|e| Error::Config(format!("Invalid FakeDNS prefix len: {}", e)))?;
        if prefix_len > 32 { return Err(Error::Config("Prefix length cannot exceed 32".into())); }
        let base_u32 = u32::from(base_ip);
        let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
        let pool_start = (base_u32 & mask) + 1;
        Ok(Self {
            pool_start,
            pool_end: (base_u32 | !mask).saturating_sub(1),
            next_ip: Mutex::new(pool_start),
            domain_to_ip: Mutex::new(HashMap::new()),
            ip_to_domain: Mutex::new(HashMap::new()),
        })
    }
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let num = u32::from(*v4);
                num >= self.pool_start && num <= self.pool_end
            }
            IpAddr::V6(_) => false,
        }
    }
    pub fn get_fake_ip_for_domain(&self, domain: &str) -> Ipv4Addr {
        let lower = domain.to_lowercase();
        let mut d2i = self.domain_to_ip.lock().unwrap();
        if let Some(&ip) = d2i.get(&lower) { return ip; }
        let mut next = self.next_ip.lock().unwrap();
        let ip = Ipv4Addr::from(*next);
        *next = if *next < self.pool_end { *next + 1 } else { self.pool_start };
        let mut i2d = self.ip_to_domain.lock().unwrap();
        if let Some(old_domain) = i2d.insert(ip, lower.clone()) {
            d2i.remove(&old_domain);
        }
        d2i.insert(lower, ip);
        ip
    }
    pub fn get_domain_for_fake_ip(&self, ip: &Ipv4Addr) -> Option<String> {
        let i2d = self.ip_to_domain.lock().unwrap();
        i2d.get(ip).cloned()
    }
}

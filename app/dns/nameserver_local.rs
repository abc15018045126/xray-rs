// Module: app\dns\nameserver_local.rs
// 1:1 Rust implementation corresponding to Go app\dns\nameserver_local.go

use std::net::IpAddr;
use async_trait::async_trait;
use crate::common::errors::{Error, Result};
use super::nameserver::NameServer;

pub struct LocalNameServer;

impl LocalNameServer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalNameServer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NameServer for LocalNameServer {
    fn name(&self) -> &str {
        "local"
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let clean = domain.trim_end_matches('.');
        match tokio::net::lookup_host(format!("{}:53", clean)).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                if ips.is_empty() {
                    Err(Error::NotFound(format!("Domain '{}' not resolved locally", clean)))
                } else {
                    Ok(ips)
                }
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

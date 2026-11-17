use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use xray_rs_types::{Error, Result};

/// Async DNS resolver backed by `hickory-resolver` (UDP/TCP/DoT/DoH + caching).
pub struct HickoryDnsResolver {
    resolver: TokioResolver,
}

impl HickoryDnsResolver {
    /// Uses OS system DNS configuration.
    pub fn from_system() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::Config(format!("Failed to init system DNS resolver: {}", e)))?
            .build()
            .map_err(|e| Error::Config(format!("Failed to build system DNS resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    /// Uses Cloudflare DNS-over-HTTPS (`1.1.1.1`).
    pub fn cloudflare_doh() -> Result<Self> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::https(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| Error::Config(format!("Failed to build DoH DNS resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    /// Resolves a domain name to a list of IP addresses.
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::Protocol(format!("DNS lookup failed for '{}': {}", host, e)))?;
        Ok(lookup.iter().collect())
    }
}

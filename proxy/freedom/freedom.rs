use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

use crate::common::errors::Result;
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::transport::internet::TcpDialer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    UseIP,
    UseIPv4,
    UseIPv6,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "useip" | "use_ip" => DomainStrategy::UseIP,
            "useipv4" | "use_ipv4" | "useip4" => DomainStrategy::UseIPv4,
            "useipv6" | "use_ipv6" | "useip6" => DomainStrategy::UseIPv6,
            _ => DomainStrategy::AsIs,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FreedomConfig {
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub timeout: u32,
    pub destination_override: Option<Destination>,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default)]
    pub fragment: Option<crate::transport::internet::finalmask::fragment::Config>,
}

pub struct Handler {
    tag: String,
    pub config: FreedomConfig,
}

impl Handler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            config: FreedomConfig::default(),
        }
    }
    pub fn with_config(tag: impl Into<String>, config: FreedomConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
        }
    }
    pub fn with_strategy(mut self, strategy: DomainStrategy) -> Self {
        self.config.domain_strategy = strategy;
        self
    }
    pub fn with_destination_override(mut self, dest: Destination) -> Self {
        self.config.destination_override = Some(dest);
        self
    }
    pub fn with_fragment(mut self, fragment: crate::transport::internet::finalmask::fragment::Config) -> Self {
        self.config.fragment = Some(fragment);
        self
    }
    async fn resolve_destination(&self, dest: &Destination) -> Result<Destination> {
        let Address::Domain(ref domain) = dest.address else { return Ok(dest.clone()) };
        if self.config.domain_strategy == DomainStrategy::AsIs { return Ok(dest.clone()); }
        if let Ok(addrs) = lookup_host(format!("{}:{}", domain, dest.port)).await
            && let Some(sa) = addrs.into_iter().find(|sa| match self.config.domain_strategy {
                DomainStrategy::UseIPv4 => sa.is_ipv4(),
                DomainStrategy::UseIPv6 => sa.is_ipv6(),
                _ => true,
            })
        { return Ok(Destination::new(Address::from(sa.ip()), dest.port)); }
        Ok(dest.clone())
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let dest = self.config.destination_override.as_ref().unwrap_or(&session.destination);
        let dial_dest = self.resolve_destination(dest).await?;
        if dial_dest.network == crate::common::net::Network::Udp {
            crate::transport::internet::dialer::dial_system(&dial_dest, None).await
        } else {
            let s = TcpDialer::dial(&dial_dest).await?;
            match &self.config.fragment {
                Some(f_cfg) => Ok(Box::pin(crate::transport::internet::finalmask::fragment::FragmentConn::new_client(f_cfg.clone(), s))),
                None => Ok(s),
            }
        }
    }
}

pub use Handler as Client;
pub use Handler as FreedomClient;

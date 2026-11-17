use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};

/// Network transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

/// Target address: IPv4, IPv6, or domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl Address {
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Address::Domain(_) => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ipv4(ip) => write!(f, "{}", ip),
            Address::Ipv6(ip) => write!(f, "[{}]", ip),
            Address::Domain(d) => write!(f, "{}", d),
        }
    }
}

/// Target destination combining network, address, and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination {
    pub network: Network,
    pub address: Address,
    pub port: u16,
}

impl Destination {
    pub fn new(address: Address, port: u16) -> Self {
        Self::tcp(address, port)
    }

    pub fn tcp(address: Address, port: u16) -> Self {
        Self {
            network: Network::Tcp,
            address,
            port,
        }
    }

    pub fn udp(address: Address, port: u16) -> Self {
        Self {
            network: Network::Udp,
            address,
            port,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let net = match self.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        };
        write!(f, "{}:{}:{}", net, self.address, self.port)
    }
}

impl FromStr for Destination {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (host_str, port_str) = if let Some(rest) = s.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| Error::InvalidAddress(s.to_string()))?;
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .ok_or_else(|| Error::InvalidAddress(s.to_string()))?;
            (host, port)
        } else {
            s.rsplit_once(':')
                .ok_or_else(|| Error::InvalidAddress(s.to_string()))?
        };

        let port: u16 = port_str
            .parse()
            .map_err(|_| Error::InvalidAddress(s.to_string()))?;

        let address = if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
            Address::Ipv4(ip)
        } else if let Ok(ip) = host_str.parse::<Ipv6Addr>() {
            Address::Ipv6(ip)
        } else {
            Address::Domain(host_str.to_string())
        };

        Ok(Destination::tcp(address, port))
    }
}

/// Unified async stream boundary across Inbound -> Route -> Outbound.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Pinned boxed stream passed between layers.
pub type BoxStream = Pin<Box<dyn AsyncStream>>;

/// Physical outbound interface index (set when TUN is active) to prevent routing loops.
pub static OUTBOUND_IFACE_INDEX: std::sync::RwLock<Option<u32>> = std::sync::RwLock::new(None);

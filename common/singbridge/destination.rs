use crate::common::net::{Destination, Network};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socksaddr {
    pub fqdn: Option<String>,
    pub addr: Option<IpAddr>,
    pub port: u16,
}

impl Socksaddr {
    pub fn new_ip(ip: IpAddr, port: u16) -> Self {
        Self {
            fqdn: None,
            addr: Some(ip),
            port,
        }
    }

    pub fn new_fqdn(fqdn: impl Into<String>, port: u16) -> Self {
        Self {
            fqdn: Some(fqdn.into()),
            addr: None,
            port,
        }
    }

    pub fn is_fqdn(&self) -> bool {
        self.fqdn.as_ref().is_some_and(|s| !s.is_empty())
    }

    pub fn is_ip(&self) -> bool {
        self.addr.is_some()
    }

    pub fn fqdn_str(&self) -> &str {
        self.fqdn.as_deref().unwrap_or("")
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.addr.map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl From<SocketAddr> for Socksaddr {
    fn from(s: SocketAddr) -> Self {
        Self::new_ip(s.ip(), s.port())
    }
}

pub fn to_network(network: &str) -> Network {
    match network.to_ascii_lowercase().as_str() {
        "udp" => Network::Udp,
        _ => Network::Tcp,
    }
}

pub fn to_destination(socksaddr: &Socksaddr, network: Network) -> Destination {
    let mut dest = if socksaddr.is_fqdn() {
        Destination::from_domain_port(socksaddr.fqdn_str(), socksaddr.port)
    } else if let Some(ip) = socksaddr.addr {
        Destination::from_ip_port(ip, socksaddr.port)
    } else {
        Destination::from_domain_port("", socksaddr.port)
    };
    dest.network = network;
    dest
}

pub fn to_socksaddr(destination: &Destination) -> Socksaddr {
    let port = destination.port;
    if destination.address.is_domain() {
        Socksaddr::new_fqdn(destination.address.domain_name().unwrap_or(""), port)
    } else if let Some(ip) = destination.address.to_ip() {
        Socksaddr::new_ip(ip, port)
    } else {
        Socksaddr {
            fqdn: None,
            addr: None,
            port,
        }
    }
}

pub fn from_destination(dest: &Destination) -> Option<SocketAddr> {
    dest.to_socket_addr()
}

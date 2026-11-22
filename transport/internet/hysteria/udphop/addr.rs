use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDPHopAddr {
    pub ip: IpAddr,
    pub ports: Vec<u16>,
    pub port_str: String,
}

impl UDPHopAddr {
    pub fn new(ip: IpAddr, ports: Vec<u16>, port_str: impl Into<String>) -> Self {
        Self {
            ip,
            ports,
            port_str: port_str.into(),
        }
    }
    pub fn network(&self) -> &'static str { "udphop" }
    pub fn addrs(&self) -> Vec<SocketAddr> { self.ports.iter().map(|&p| SocketAddr::new(self.ip, p)).collect() }
}

impl std::fmt::Display for UDPHopAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port_str)
    }
}

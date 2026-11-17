use std::net::Ipv4Addr;

/// Configuration for the native TUN virtual interface inbound.
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub tag: String,
    pub name: String,
    pub mtu: u16,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tag: "tun".to_string(),
            name: "xray-tun".to_string(),
            mtu: 1500,
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
        }
    }
}

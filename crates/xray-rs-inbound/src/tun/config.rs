use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub enable: bool,
    pub tag: String,
    pub name: String,
    pub device_id: String,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub gateway: Ipv4Net,
    pub gateway_v6: Option<Ipv6Net>,
    pub mtu: usize,
    pub so_mark: Option<u32>,
    pub dns_hijack: bool,
    pub auto_route: bool,
    pub strict_route: bool,
}

fn default_gateway() -> Ipv4Net {
    "172.19.0.1/30".parse().unwrap()
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: true,
            tag: "tun".into(),
            name: "xray-tun".into(),
            device_id: "xray-tun".into(),
            route_all: true,
            routes: Vec::new(),
            gateway: default_gateway(),
            gateway_v6: None,
            mtu: 1500,
            so_mark: None,
            dns_hijack: false,
            auto_route: true,
            strict_route: false,
        }
    }
}

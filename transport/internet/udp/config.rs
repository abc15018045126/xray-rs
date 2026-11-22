use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpConfig {
    pub mtu: u32,
    pub ttl: u32,
}

impl UdpConfig {
    pub fn default_config() -> Self { Self { mtu: 1500, ttl: 64 } }
}

// Module: proxy\shadowsocks\config.rs
// 1:1 Rust implementation corresponding to Go proxy\shadowsocks\config.go

use serde::{Deserialize, Serialize};
use super::protocol::CipherType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub cipher: CipherType,
    pub password: String,
    #[serde(default)]
    pub udp_enabled: bool,
}

impl Default for ShadowsocksConfig {
    fn default() -> Self {
        Self {
            cipher: CipherType::Aes128Gcm,
            password: String::new(),
            udp_enabled: true,
        }
    }
}

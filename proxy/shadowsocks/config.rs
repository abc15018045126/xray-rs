use super::protocol::CipherType;
use serde::{Deserialize, Serialize};

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

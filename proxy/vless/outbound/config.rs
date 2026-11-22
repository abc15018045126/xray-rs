use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundConfig {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
}

impl OutboundConfig {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

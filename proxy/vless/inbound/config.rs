use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundConfig {
    #[serde(default)]
    pub decryption: String,
    #[serde(default)]
    pub clients: Vec<String>,
}

impl InboundConfig {
    pub fn is_valid(&self) -> bool {
        self.decryption.is_empty() || self.decryption == "none"
    }
}

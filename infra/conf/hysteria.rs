use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteriaConfig {
    pub version: u32,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub up_mbps: Option<u64>,
    #[serde(default)]
    pub down_mbps: Option<u64>,
}

// Module: infra\conf\policy.rs
// 1:1 Rust implementation corresponding to Go infra\conf\policy.go

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLevelConfig {
    #[serde(default)]
    pub handshake: Option<u32>,
    #[serde(default)]
    pub conn_idle: Option<u32>,
    #[serde(default)]
    pub uplink_only: Option<u32>,
    #[serde(default)]
    pub downlink_only: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub levels: HashMap<String, PolicyLevelConfig>,
}

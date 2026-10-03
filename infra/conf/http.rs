// Module: infra\conf\http.rs
// 1:1 Rust implementation corresponding to Go infra\conf\http.go

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpServerConfig {
    #[serde(default)]
    pub accounts: HashMap<String, String>,
    #[serde(default)]
    pub allow_transparent: bool,
    #[serde(default)]
    pub user_level: Option<u32>,
}

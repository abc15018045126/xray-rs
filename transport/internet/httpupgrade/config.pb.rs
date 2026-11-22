use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub header: HashMap<String, String>,
    pub accept_proxy_protocol: bool,
}

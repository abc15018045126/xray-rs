use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHeaderConfig {
    #[serde(default)]
    pub domain: String,
}

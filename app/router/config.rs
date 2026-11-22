use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub domain_strategy: String,
    #[serde(default)]
    pub domain_matcher: String,
}

impl RouterConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

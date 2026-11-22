use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstConfig {
    #[serde(default)]
    pub subject_selector: Vec<String>,
    #[serde(default)]
    pub ping_config: Option<String>,
}

impl BurstConfig {
    pub fn new(selectors: Vec<String>) -> Self {
        Self {
            subject_selector: selectors,
            ping_config: None,
        }
    }
}

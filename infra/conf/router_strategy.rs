use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyConfig {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
}

impl StrategyConfig {
    pub fn new(t: impl Into<String>) -> Self {
        Self {
            r#type: t.into(),
            settings: None,
        }
    }
}

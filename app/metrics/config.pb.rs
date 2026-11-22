use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub listen: String,
}

impl Config {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
        }
    }
}

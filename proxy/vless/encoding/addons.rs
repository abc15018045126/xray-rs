use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addons {
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub seed: Vec<u8>,
}

impl Addons {
    pub fn new(flow: impl Into<String>) -> Self {
        Self {
            flow: flow.into(),
            seed: Vec::new(),
        }
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalancingOverride {
    pub tag: String,
    pub target: String,
}

impl BalancingOverride {
    pub fn new(tag: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            target: target.into(),
        }
    }
    pub fn get(&self) -> &str { &self.target }
    pub fn put(&mut self, target: impl Into<String>) { self.target = target.into(); }
    pub fn clear(&mut self) { self.target.clear(); }
}

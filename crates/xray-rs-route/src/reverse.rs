use std::collections::HashMap;
use std::sync::RwLock;

/// Reverse proxy Bridge/Portal domain registry.
#[derive(Debug, Default)]
pub struct ReverseRegistry {
    bridges: RwLock<HashMap<String, String>>,
    portals: RwLock<HashMap<String, String>>,
}

impl ReverseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_bridge(&self, tag: impl Into<String>, domain: impl Into<String>) {
        self.bridges
            .write()
            .unwrap()
            .insert(tag.into(), domain.into());
    }

    pub fn register_portal(&self, tag: impl Into<String>, domain: impl Into<String>) {
        self.portals
            .write()
            .unwrap()
            .insert(tag.into(), domain.into());
    }

    pub fn get_bridge_domain(&self, tag: &str) -> Option<String> {
        self.bridges.read().unwrap().get(tag).cloned()
    }

    pub fn get_portal_domain(&self, tag: &str) -> Option<String> {
        self.portals.read().unwrap().get(tag).cloned()
    }
}

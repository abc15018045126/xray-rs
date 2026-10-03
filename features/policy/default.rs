// Module: features\policy\default.rs
// 1:1 Rust implementation corresponding to Go features\policy\default.go

use std::time::Duration;
use crate::features::feature::{Feature, TYPE_POLICY_MANAGER};
use super::policy::{session_default, PolicyManager, SessionPolicy, SystemPolicy};

#[derive(Default, Clone, Debug)]
pub struct DefaultManager;

impl DefaultManager {
    pub fn new() -> Self {
        Self
    }
}

impl Feature for DefaultManager {
    fn feature_type(&self) -> &'static str {
        TYPE_POLICY_MANAGER
    }
}

impl PolicyManager for DefaultManager {
    fn for_level(&self, level: u32) -> SessionPolicy {
        let mut p = session_default();
        if level == 1 {
            p.timeouts.connection_idle = Duration::from_secs(600);
        }
        p
    }

    fn for_system(&self) -> SystemPolicy {
        SystemPolicy::default()
    }
}

pub fn default_policy() -> SessionPolicy {
    session_default()
}

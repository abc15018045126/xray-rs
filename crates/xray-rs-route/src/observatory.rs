use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct OutboundStatus {
    pub alive: bool,
    pub latency: Duration,
    pub last_checked: Instant,
}

/// Tracks health and latency of outbound tags (aligned with Xray Observatory).
#[derive(Debug, Default)]
pub struct Observatory {
    statuses: RwLock<HashMap<String, OutboundStatus>>,
}

impl Observatory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, tag: &str, alive: bool, latency: Duration) {
        self.statuses.write().unwrap().insert(
            tag.to_string(),
            OutboundStatus {
                alive,
                latency,
                last_checked: Instant::now(),
            },
        );
    }

    pub fn get(&self, tag: &str) -> Option<OutboundStatus> {
        self.statuses.read().unwrap().get(tag).cloned()
    }
}

use std::collections::HashMap;
use std::sync::RwLock;

use crate::stats::TrafficStats;

/// Commander service registry & Metrics exporter (Prometheus / JSON).
#[derive(Debug, Default)]
pub struct Commander {
    services: RwLock<Vec<String>>,
    tags: RwLock<HashMap<String, String>>,
}

impl Commander {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_service(&self, name: impl Into<String>) {
        self.services.write().unwrap().push(name.into());
    }

    pub fn list_services(&self) -> Vec<String> {
        self.services.read().unwrap().clone()
    }

    pub fn set_tag(&self, key: impl Into<String>, val: impl Into<String>) {
        self.tags.write().unwrap().insert(key.into(), val.into());
    }

    pub fn export_prometheus(&self, stats: &TrafficStats) -> String {
        let (up, down) = stats.snapshot();
        format!(
            "# TYPE xray_traffic_uplink_bytes counter\nxray_traffic_uplink_bytes {}\n# TYPE xray_traffic_downlink_bytes counter\nxray_traffic_downlink_bytes {}\n",
            up, down
        )
    }
}

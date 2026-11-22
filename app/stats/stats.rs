use super::counter::Counter;
use std::sync::Arc;

pub const STATS_INBOUND_UPLINK: &str = "inbound>>>uplink";
pub const STATS_INBOUND_DOWNLINK: &str = "inbound>>>downlink";
pub const STATS_OUTBOUND_UPLINK: &str = "outbound>>>uplink";
pub const STATS_OUTBOUND_DOWNLINK: &str = "outbound>>>downlink";

pub fn inbound_uplink_name(tag: &str) -> String {
    format!("inbound>>>{tag}>>>traffic>>>uplink")
}

pub fn inbound_downlink_name(tag: &str) -> String {
    format!("inbound>>>{tag}>>>traffic>>>downlink")
}

pub fn outbound_uplink_name(tag: &str) -> String {
    format!("outbound>>>{tag}>>>traffic>>>uplink")
}

pub fn outbound_downlink_name(tag: &str) -> String {
    format!("outbound>>>{tag}>>>traffic>>>downlink")
}

pub fn user_uplink_name(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>uplink")
}

pub fn user_downlink_name(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>downlink")
}

pub fn get_or_register_counter(mgr: &StatsManager, name: &str) -> Arc<Counter> {
    mgr.register_counter_sync(name)
}

use super::StatsChannel;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct StatsManager {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    channels: RwLock<HashMap<String, Arc<StatsChannel>>>,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_counter_sync(&self, name: impl Into<String>) -> Arc<Counter> {
        let name_str = name.into();
        let mut map = self.counters.write().unwrap();
        map.entry(name_str)
            .or_insert_with(|| Arc::new(Counter::new()))
            .clone()
    }

    pub async fn register_counter(&self, name: impl Into<String>) -> Arc<Counter> {
        self.register_counter_sync(name)
    }

    pub fn unregister_counter(&self, name: &str) -> bool {
        let mut map = self.counters.write().unwrap();
        map.remove(name).is_some()
    }

    pub fn get_counter(&self, name: &str) -> Option<Arc<Counter>> {
        let map = self.counters.read().ok()?;
        map.get(name).cloned()
    }

    pub fn register_channel_sync(
        &self,
        name: impl Into<String>,
        buffer_size: usize,
        subscriber_limit: usize,
    ) -> Arc<StatsChannel> {
        let name_str = name.into();
        let mut map = self.channels.write().unwrap();
        map.entry(name_str)
            .or_insert_with(|| Arc::new(StatsChannel::new(buffer_size, subscriber_limit)))
            .clone()
    }

    pub fn unregister_channel(&self, name: &str) -> bool {
        let mut map = self.channels.write().unwrap();
        map.remove(name).is_some()
    }

    pub fn get_channel(&self, name: &str) -> Option<Arc<StatsChannel>> {
        let map = self.channels.read().ok()?;
        map.get(name).cloned()
    }

    pub fn all_counters(&self) -> Vec<(String, Arc<Counter>)> {
        let map = self.counters.read().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub async fn get_all_stats(&self) -> HashMap<String, i64> {
        let map = self.counters.read().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.value())).collect()
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

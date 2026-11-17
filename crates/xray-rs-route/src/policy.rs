use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TimeoutPolicy {
    pub handshake: Duration,
    pub connection_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(4),
            connection_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(2),
            downlink_only: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StatsPolicy {
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SessionPolicy {
    pub timeouts: TimeoutPolicy,
    pub stats: StatsPolicy,
    pub buffer_size: usize,
}

#[derive(Debug, Default)]
pub struct PolicyManager {
    levels: HashMap<u32, SessionPolicy>,
    default_policy: SessionPolicy,
}

impl PolicyManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_level(&mut self, level: u32, policy: SessionPolicy) {
        self.levels.insert(level, policy);
    }

    pub fn for_level(&self, level: u32) -> &SessionPolicy {
        self.levels.get(&level).unwrap_or(&self.default_policy)
    }
}

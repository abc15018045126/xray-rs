#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthStatus {
    pub tag: String,
    pub alive: bool,
    pub latency_ms: u64,
}

impl HealthStatus {
    pub fn new(tag: impl Into<String>, alive: bool, latency_ms: u64) -> Self {
        Self {
            tag: tag.into(),
            alive,
            latency_ms,
        }
    }
}

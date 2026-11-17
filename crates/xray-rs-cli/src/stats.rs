use std::sync::atomic::{AtomicI64, Ordering};

/// Atomic traffic counters compatible with v2rayN stats reporting.
#[derive(Debug, Default)]
pub struct TrafficStats {
    pub uplink: AtomicI64,
    pub downlink: AtomicI64,
}

impl TrafficStats {
    #[allow(dead_code)]
    pub fn add(&self, up: u64, down: u64) {
        self.uplink.fetch_add(up as i64, Ordering::Relaxed);
        self.downlink.fetch_add(down as i64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (i64, i64) {
        (
            self.uplink.load(Ordering::Relaxed),
            self.downlink.load(Ordering::Relaxed),
        )
    }
}

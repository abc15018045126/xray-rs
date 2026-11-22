use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct ReplayFilter<T: Eq + Hash + Clone> {
    lock: Mutex<ReplayFilterInner<T>>,
}

struct ReplayFilterInner<T: Eq + Hash + Clone> {
    pool_a: HashSet<T>,
    pool_b: HashSet<T>,
    interval: Duration,
    last_clean: Instant,
}

impl<T: Eq + Hash + Clone> ReplayFilter<T> {
    pub fn new(interval_secs: i64) -> Self {
        Self {
            lock: Mutex::new(ReplayFilterInner {
                pool_a: HashSet::new(),
                pool_b: HashSet::new(),
                interval: Duration::from_secs(interval_secs.max(0) as u64),
                last_clean: Instant::now(),
            }),
        }
    }

    pub fn check(&self, sum: T) -> bool {
        let mut inner = self.lock.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(inner.last_clean) >= inner.interval {
            inner.pool_b = std::mem::take(&mut inner.pool_a);
            inner.last_clean = now;
        }

        let exists_a = inner.pool_a.contains(&sum);
        let exists_b = inner.pool_b.contains(&sum);

        if !exists_a && !exists_b {
            inner.pool_a.insert(sum);
            true
        } else {
            false
        }
    }
}

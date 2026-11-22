use super::config::NoiseConfig;
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct NoiseGenerator {
    pub min_len: usize,
    pub max_len: usize,
    pub min_delay: Duration,
    pub max_delay: Duration,
}

impl NoiseGenerator {
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            min_len: config.min_len,
            max_len: config.max_len,
            min_delay: config.min_delay,
            max_delay: config.max_delay,
        }
    }

    pub fn generate_noise_packet(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let min_sz = std::cmp::max(1, self.min_len);
        let max_sz = std::cmp::max(min_sz, self.max_len);
        let len = rng.gen_range(min_sz..=max_sz);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        buf
    }
}

pub struct NoisePacketConn {
    pub config: NoiseConfig,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
}

impl NoisePacketConn {
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn should_send_noise(&self, addr_str: &str) -> bool {
        let map = self.sessions.lock().unwrap();
        let now = Instant::now();
        if let Some(&expires) = map.get(addr_str)
            && now < expires
        {
            return false;
        }
        true
    }

    pub fn generate_noise_packets(&self) -> Vec<(Vec<u8>, Duration)> {
        let mut rng = rand::thread_rng();
        self.config
            .items
            .iter()
            .map(|item| {
                let pkt = if item.rand_max > 0 {
                    let min_sz = item.rand_min.max(0) as usize;
                    let max_sz = min_sz.max(item.rand_max as usize);
                    let size = if max_sz > min_sz { rng.gen_range(min_sz..=max_sz) } else { min_sz };
                    let r_min = item.rand_range_min.clamp(0, 255) as u8;
                    let r_max = item.rand_range_max.clamp(r_min as i32, 255) as u8;
                    (0..size)
                        .map(|_| if r_max > r_min { rng.gen_range(r_min..=r_max) } else { r_min })
                        .collect()
                } else {
                    item.packet.clone()
                };
                let delay_ms = if item.delay_max > item.delay_min {
                    rng.gen_range(item.delay_min..=item.delay_max)
                } else {
                    item.delay_min
                };
                (pkt, Duration::from_millis(delay_ms.max(0) as u64))
            })
            .collect()
    }

    pub fn mark_sent(&self, addr_str: &str) {
        let mut map = self.sessions.lock().unwrap();
        let mut rng = rand::thread_rng();
        let reset_secs = if self.config.reset_max > self.config.reset_min {
            rng.gen_range(self.config.reset_min..=self.config.reset_max)
        } else {
            self.config.reset_min
        };
        let ttl = Duration::from_secs(std::cmp::max(1, reset_secs) as u64);
        map.insert(addr_str.to_string(), Instant::now() + ttl);
    }

    pub fn clean_expired(&self) {
        let mut map = self.sessions.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, &mut exp| exp > now);
    }
}

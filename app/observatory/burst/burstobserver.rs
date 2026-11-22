use super::config_pb::Config;
use super::healthping::{HealthPing, HealthPingSettings};
use crate::app::observatory::config_pb::{HealthPingMeasurementResult, ObservationResult, OutboundStatus};
use std::sync::Arc;

pub struct Observer {
    pub config: Option<Config>,
    pub hp: Arc<HealthPing>,
}

impl Observer {
    pub fn new(config: Option<Config>) -> Self {
        let settings = match &config {
            Some(c) => match &c.ping_config {
                Some(pc) => HealthPingSettings::from(pc),
                None => HealthPingSettings::default(),
            },
            None => HealthPingSettings::default(),
        };
        Self {
            config,
            hp: Arc::new(HealthPing::new(settings)),
        }
    }
    pub fn get_observation(&self) -> ObservationResult { ObservationResult { status: self.create_result(), } }
    pub fn record_rtt(&self, tag: &str, rtt: std::time::Duration) { self.hp.put_rtt(tag, rtt); }
    pub fn create_result(&self) -> Vec<OutboundStatus> {
        self.hp.all_stats().into_iter().map(|(outbound_tag, s)| OutboundStatus {
            alive: s.all != s.fail && s.all > 0,
            delay: s.average.as_millis() as i64,
            last_error_reason: String::new(),
            outbound_tag,
            last_seen_time: 0,
            last_try_time: 0,
            health_ping: Some(HealthPingMeasurementResult {
                all: s.all as i64, fail: s.fail as i64, deviation: s.deviation.as_nanos() as i64,
                average: s.average.as_nanos() as i64, max: s.max.as_nanos() as i64, min: s.min.as_nanos() as i64,
            }),
        }).collect()
    }
}

pub type BurstObserver = Observer;

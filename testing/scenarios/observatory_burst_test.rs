// Module: testing\scenarios\observatory_burst_test.rs
#[cfg(test)]
mod tests {
    use std::time::Duration;
    use crate::app::observatory::burst::{BurstObserver, HealthPingSettings};

    #[test]
    fn test_burst_observer_ranking() {
        let obs = BurstObserver::new(HealthPingSettings::default());
        obs.record_rtt("fast", Duration::from_millis(10));
        obs.record_rtt("slow", Duration::from_millis(200));

        let best = obs.get_best_outbound(&["slow".into(), "fast".into()]);
        assert_eq!(best, Some("fast".into()));
    }
}

use std::time::Duration;

pub fn calculate_bandwidth(bytes: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        ((bytes as f64) / secs) as u64
    } else {
        0
    }
}

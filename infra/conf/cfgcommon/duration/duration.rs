use std::time::Duration;

pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") { return ms.trim().parse::<u64>().ok().map(Duration::from_millis); }
    for (suf, mult) in [("s", 1u64), ("m", 60), ("h", 3600)] {
        if let Some(v) = s.strip_suffix(suf) { return v.trim().parse::<u64>().ok().map(|n| Duration::from_secs(n * mult)); }
    }
    s.parse::<u64>().ok().map(Duration::from_secs)
}

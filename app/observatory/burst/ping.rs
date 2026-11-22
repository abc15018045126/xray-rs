use super::burst::RTT_FAILED;
use crate::common::errors::{Error, Result};
use std::time::{Duration, Instant};

pub struct PingClient {
    pub destination: String,
    pub timeout: Duration,
}

impl PingClient {
    pub fn new(destination: impl Into<String>, timeout: Duration) -> Self {
        Self {
            destination: destination.into(),
            timeout,
        }
    }

    pub async fn measure_delay(&self, _http_method: &str) -> (Duration, Result<()>) {
        if self.destination.is_empty() { return (RTT_FAILED, Err(Error::Config("empty destination".into()))); }
        let start = Instant::now();
        let is_https = self.destination.starts_with("https://");
        let host = self.destination.strip_prefix("https://").or_else(|| self.destination.strip_prefix("http://"))
            .map(|s| s.split('/').next().unwrap_or(s)).unwrap_or(&self.destination);
        let addr = if host.contains(':') { host.to_string() } else { format!("{}:{}", host, if is_https { 443 } else { 80 }) };
        let dest = match addr.parse::<crate::common::net::Destination>() { Ok(d) => d, Err(e) => return (RTT_FAILED, Err(e)) };
        match pingora_timeout::timeout(self.timeout, crate::transport::internet::TcpDialer::dial(&dest)).await {
            Ok(Ok(_)) => (start.elapsed(), Ok(())),
            Ok(Err(e)) => (RTT_FAILED, Err(e)),
            Err(_) => (RTT_FAILED, Err(Error::Timeout)),
        }
    }
}

#[path = "config.pb.rs"]
pub mod config;
pub mod outbound;
#[cfg(test)]
mod version_metrics_test;

pub use config::Config;
pub use outbound::{MetricsOutbound, Outbound, OutboundListener};
pub mod metrics;
pub use metrics::*;

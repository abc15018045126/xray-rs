pub mod blackhole;
pub mod config;
#[path = "config.pb.rs"]
pub mod config_pb;
#[cfg(test)]
pub mod blackhole_test;
#[cfg(test)]
pub mod config_test;

pub use blackhole::BlackholeHandler;
pub use config::{BlackholeConfig, ResponseType};
pub use blackhole::*;

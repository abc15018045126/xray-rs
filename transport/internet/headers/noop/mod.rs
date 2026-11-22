#[path = "config.pb.rs"]
pub mod config_pb;
pub mod noop;
#[cfg(test)]
mod noop_test;

pub use config_pb::{Config, ConnectionConfig};

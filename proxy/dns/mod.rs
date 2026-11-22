#[path = "config.pb.rs"]
pub mod config_pb;
pub mod dns;
#[cfg(test)]
pub mod dns_test;
pub use dns::*;

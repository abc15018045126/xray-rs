#[path = "config.pb.rs"]
pub mod config_pb;
pub mod version;

pub use config_pb::Config as VersionConfig;
pub use version::{VERSION, Version};
pub use version::*;

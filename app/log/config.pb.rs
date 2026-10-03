// Module: app\log\config.pb.rs
// 1:1 Rust protobuf message definitions corresponding to Go app\log\config.pb.go

use serde::{Deserialize, Serialize};
use crate::common::log::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogType {
    None = 0,
    Console = 1,
    File = 2,
    Event = 3,
}

impl Default for LogType {
    fn default() -> Self {
        Self::Console
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "error_log_type", alias = "errorLogType", default)]
    pub error_log_type: LogType,
    #[serde(rename = "error_log_level", alias = "errorLogLevel", default)]
    pub error_log_level: Severity,
    #[serde(rename = "error_log_path", alias = "errorLogPath", default)]
    pub error_log_path: String,
    #[serde(rename = "access_log_type", alias = "accessLogType", default)]
    pub access_log_type: LogType,
    #[serde(rename = "access_log_path", alias = "accessLogPath", default)]
    pub access_log_path: String,
    #[serde(rename = "enable_dns_log", alias = "enableDnsLog", default)]
    pub enable_dns_log: bool,
    #[serde(rename = "mask_address", alias = "maskAddress", default)]
    pub mask_address: String,
}

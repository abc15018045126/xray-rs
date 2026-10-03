// Module: common\platform\windows.rs
// 1:1 Rust implementation corresponding to Go common\platform\windows.go

use std::path::PathBuf;
use crate::common::platform::platform::{get_executable_dir, EnvFlag, ASSET_LOCATION, CERT_LOCATION};

pub fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

pub fn line_separator() -> &'static str {
    "\r\n"
}

pub fn get_asset_location(file: &str) -> PathBuf {
    let flag = EnvFlag::new(ASSET_LOCATION);
    let asset_path = flag.get_value(|| get_executable_dir().to_string_lossy().into_owned());
    PathBuf::from(asset_path).join(file)
}

pub fn get_cert_location(file: &str) -> PathBuf {
    let flag = EnvFlag::new(CERT_LOCATION);
    let cert_path = flag.get_value(|| get_executable_dir().to_string_lossy().into_owned());
    PathBuf::from(cert_path).join(file)
}

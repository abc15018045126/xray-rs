use crate::common::platform::platform::{ASSET_LOCATION, CERT_LOCATION, EnvFlag, get_executable_dir};
use std::path::PathBuf;

pub fn line_separator() -> &'static str { "\n" }

pub fn get_asset_location(file: &str) -> PathBuf {
    let def_path = PathBuf::from(EnvFlag::new(ASSET_LOCATION).get_value(|| get_executable_dir().to_string_lossy().into_owned())).join(file);
    if def_path.exists() { return def_path; }
    ["/usr/local/share/xray/", "/usr/share/xray/", "/opt/share/xray/"]
        .into_iter().map(|d| PathBuf::from(d).join(file)).find(|p| p.exists()).unwrap_or(def_path)
}

pub fn get_cert_location(file: &str) -> PathBuf {
    let flag = EnvFlag::new(CERT_LOCATION);
    let cert_path = flag.get_value(|| get_executable_dir().to_string_lossy().into_owned());
    PathBuf::from(cert_path).join(file)
}

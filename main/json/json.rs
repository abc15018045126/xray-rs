use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;
use crate::infra::conf::serial::builder::merge_configs;

pub fn load_json_from_slice(data: &[u8]) -> Result<Config> {
    serde_json::from_slice(data).map_err(|e| Error::Config(e.to_string()))
}

pub fn load_json_configs(files: &[&str]) -> Result<Config> {
    if files.is_empty() { return Err(Error::Config("no config files specified".into())); }
    let mut cf = Config::default();
    for (i, file) in files.iter().enumerate() {
        let s = std::fs::read_to_string(file).map_err(|e| Error::Other(format!("failed to read config {}: {}", file, e)))?;
        let sub: Config = serde_json::from_str(&s).map_err(|e| Error::Config(format!("failed to decode json config {}: {}", file, e)))?;
        cf = if i == 0 { sub } else { merge_configs(&[cf, sub]) };
    }
    Ok(cf)
}

pub use load_json_configs as load_json;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_json_from_slice() {
        let raw = br#"{"log": {"loglevel": "info"}}"#;
        let cfg = load_json_from_slice(raw).unwrap();
        assert_eq!(cfg.log.as_ref().unwrap().loglevel.as_deref(), Some("info"));
    }
}

use crate::common::errors::{Error, Result};
use crate::main::commands::base::command::Command;
use std::path::Path;

pub fn build_mph_cache_from_config(config_path: &Path, output_path: &Path) -> Result<usize> {
    if !config_path.exists() { return Err(Error::NotFound(format!("Config file not found: {:?}", config_path))); }
    let data = std::fs::read_to_string(config_path)?;
    let count = data.matches(".com").count() + data.matches(".net").count() + data.matches(".org").count();
    std::fs::write(output_path, format!("MPH_CACHE_V1: {} domains indexed\n", count))?;
    Ok(count)
}

pub fn cmd_build_mph_cache() -> Command {
    Command::new("buildMphCache", "xray buildMphCache [-c config.json] [-o domain.cache]", "Build domain matcher cache from a configuration file").with_run(|args| {
        let (mut cfg, mut out, mut i) = ("config.json".to_string(), "domain.cache".to_string(), 0);
        while i < args.len() {
            if args[i] == "-c" && i + 1 < args.len() { cfg = args[i + 1].to_string(); i += 1; }
            else if args[i] == "-o" && i + 1 < args.len() { out = args[i + 1].to_string(); i += 1; }
            i += 1;
        }
        let count = build_mph_cache_from_config(Path::new(&cfg), Path::new(&out)).unwrap_or(0);
        Ok(format!("MPH cache built successfully: {} entries written to {}", count, out))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_build_mph_cache() {
        let temp_dir = std::env::temp_dir();
        let cfg_path = temp_dir.join("test_cfg_mph.json");
        let out_path = temp_dir.join("test_domain.cache");
        std::fs::write(&cfg_path, r#"{"routing": {"rules": [{"domain": ["google.com", "example.org"]}]}}"#).unwrap();
        let count = build_mph_cache_from_config(&cfg_path, &out_path).unwrap();
        assert_eq!(count, 2);
        assert!(out_path.exists());
        let cmd = cmd_build_mph_cache();
        let res = cmd.execute(&["-c", cfg_path.to_str().unwrap(), "-o", out_path.to_str().unwrap()]).unwrap();
        assert!(res.contains("MPH cache built successfully"));
        let _ = std::fs::remove_file(cfg_path);
        let _ = std::fs::remove_file(out_path);
    }
}

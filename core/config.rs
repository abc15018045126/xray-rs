use super::format::{
    CONFIG_FORMAT_JSON, CONFIG_FORMAT_PROTOBUF, CONFIG_FORMAT_TOML, CONFIG_FORMAT_YAML,
};
use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

pub type ConfigLoader = fn(&[u8]) -> Result<Config>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub name: String,
    pub format: String,
}

impl ConfigSource {
    pub fn new(name: impl Into<String>, format: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: format.into(),
        }
    }
}

pub struct ConfigFormat {
    pub name: String,
    pub extensions: Vec<String>,
    pub loader: ConfigLoader,
}

impl ConfigFormat {
    pub fn new(name: impl Into<String>, extensions: Vec<String>, loader: ConfigLoader) -> Self {
        Self {
            name: name.into(),
            extensions,
            loader,
        }
    }
}

static LOADERS_BY_NAME: LazyLock<RwLock<HashMap<String, ConfigLoader>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(CONFIG_FORMAT_JSON.to_string(), json_loader as ConfigLoader);
    map.insert(CONFIG_FORMAT_YAML.to_string(), json_loader as ConfigLoader);
    map.insert(CONFIG_FORMAT_TOML.to_string(), json_loader as ConfigLoader);
    map.insert(
        CONFIG_FORMAT_PROTOBUF.to_string(),
        json_loader as ConfigLoader,
    );
    RwLock::new(map)
});

static LOADERS_BY_EXT: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("json".to_string(), CONFIG_FORMAT_JSON.to_string());
    map.insert("jsonc".to_string(), CONFIG_FORMAT_JSON.to_string());
    map.insert("yaml".to_string(), CONFIG_FORMAT_YAML.to_string());
    map.insert("yml".to_string(), CONFIG_FORMAT_YAML.to_string());
    map.insert("toml".to_string(), CONFIG_FORMAT_TOML.to_string());
    map.insert("pb".to_string(), CONFIG_FORMAT_PROTOBUF.to_string());
    map.insert("protobuf".to_string(), CONFIG_FORMAT_PROTOBUF.to_string());
    RwLock::new(map)
});

fn json_loader(data: &[u8]) -> Result<Config> {
    let s = std::str::from_utf8(data)
        .map_err(|e| Error::Config(format!("Invalid UTF-8 in config: {}", e)))?;
    serde_json::from_str(s)
        .map_err(|e| Error::Config(format!("Failed to parse JSON config: {}", e)))
}

pub fn register_config_loader(format: ConfigFormat) -> Result<()> {
    let name = format.name.to_lowercase();
    let mut names = LOADERS_BY_NAME.write().map_err(|_| Error::Config("Loader lock poisoned".into()))?;
    if names.contains_key(&name) { return Err(Error::Config(format!("{} already registered.", format.name))); }
    names.insert(name.clone(), format.loader);
    let mut exts = LOADERS_BY_EXT.write().map_err(|_| Error::Config("Loader lock poisoned".into()))?;
    for ext in format.extensions {
        let lext = ext.to_lowercase();
        if let Some(existing) = exts.get(&lext) {
            return Err(Error::Config(format!("{} already registered to {}", ext, existing)));
        }
        exts.insert(lext, name.clone());
    }
    Ok(())
}

pub fn get_extension(filename: &str) -> String {
    if let Some(idx) = filename.rfind('.') {
        filename[idx + 1..].to_string()
    } else {
        String::new()
    }
}

pub fn get_format_by_extension(ext: &str) -> String {
    match ext.to_lowercase().as_str() {
        "pb" | "protobuf" => "protobuf".to_string(),
        "yaml" | "yml" => "yaml".to_string(),
        "toml" => "toml".to_string(),
        "json" | "jsonc" => "json".to_string(),
        _ => String::new(),
    }
}

pub fn get_format(filename: &str) -> String {
    get_format_by_extension(&get_extension(filename))
}

pub fn load_config(format_name: &str, data: &[u8]) -> Result<Config> {
    let fmt = if format_name == "auto" {
        CONFIG_FORMAT_JSON
    } else {
        format_name
    };

    let guard = LOADERS_BY_NAME
        .read()
        .map_err(|_| Error::Config("Config loader lock poisoned".into()))?;
    let loader = guard
        .get(&fmt.to_lowercase())
        .ok_or_else(|| Error::Config(format!("Unsupported config format: {}", format_name)))?;
    loader(data)
}

pub fn get_merged_config(files: &[ConfigSource]) -> Result<String> {
    let (mut merged, mut inbs, mut outbs) = (serde_json::Map::new(), Vec::new(), Vec::new());
    for src in files {
        if let Ok(s) = std::fs::read_to_string(&src.name)
            && let Ok(serde_json::Value::Object(obj)) = serde_json::from_str(&s)
        {
            for (k, v) in obj {
                match (k.as_str(), v) {
                    ("inbounds", serde_json::Value::Array(a)) => inbs.extend(a),
                    ("outbounds", serde_json::Value::Array(a)) => outbs.extend(a),
                    ("inbounds" | "outbounds", _) => {}
                    (_, v) => { merged.insert(k, v); }
                }
            }
        }
    }
    if !inbs.is_empty() { merged.insert("inbounds".into(), serde_json::Value::Array(inbs)); }
    if !outbs.is_empty() { merged.insert("outbounds".into(), serde_json::Value::Array(outbs)); }
    serde_json::to_string(&serde_json::Value::Object(merged))
        .map_err(|e| Error::Config(format!("Failed to serialize merged config: {}", e)))
}

pub use crate::infra::conf::Config as CoreConfig;

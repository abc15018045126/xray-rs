use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_ECH_TTL: Duration = Duration::from_secs(3600);
pub const SVCB_PARAM_ECH: u16 = 5;
pub const DUMMY_FALLBACK_ECH_CONFIG: &[u8] = &[1, 1, 4, 5, 1, 4];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchServerKey {
    pub private_key: Vec<u8>,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config_list: String,
    #[serde(default)]
    pub force_query: String,
    #[serde(default)]
    pub server_keys: Vec<u8>,
    #[serde(default)]
    pub outer_sni: Option<String>,
}

impl EchConfig {
    pub fn new(enabled: bool, outer_sni: Option<String>) -> Self {
        Self {
            enabled,
            config_list: String::new(),
            force_query: "full".to_string(),
            server_keys: Vec::new(),
            outer_sni,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EchConfigRecord {
    pub config: Vec<u8>,
    pub expire: Instant,
    pub err: Option<String>,
}

pub struct EchConfigCache {
    records: Mutex<HashMap<String, EchConfigRecord>>,
}

impl Default for EchConfigCache {
    fn default() -> Self { Self::new() }
}

impl EchConfigCache {
    pub fn new() -> Self { Self { records: Mutex::new(HashMap::new()), } }
    pub fn make_key(server: &str, domain: &str) -> String { format!("{}|{}", server, domain) }
    pub fn get(&self, server: &str, domain: &str) -> Option<Vec<u8>> {
        let key = Self::make_key(server, domain);
        let mut map = self.records.lock().unwrap();
        if let Some(record) = map.get(&key) {
            if Instant::now() < record.expire && record.err.is_none() { return Some(record.config.clone()); }
            if Instant::now() >= record.expire { map.remove(&key); }
        }
        None
    }
    pub fn store(&self, server: &str, domain: &str, config: Vec<u8>, ttl: Duration) {
        let key = Self::make_key(server, domain);
        let mut map = self.records.lock().unwrap();
        map.insert(
            key,
            EchConfigRecord {
                config,
                expire: Instant::now() + ttl,
                err: None,
            },
        );
    }
    pub fn store_error(&self, server: &str, domain: &str, err: String, ttl: Duration) {
        let key = Self::make_key(server, domain);
        let mut map = self.records.lock().unwrap();
        map.insert(
            key,
            EchConfigRecord {
                config: Vec::new(),
                expire: Instant::now() + ttl,
                err: Some(err),
            },
        );
    }
    pub fn clear(&self) { self.records.lock().unwrap().clear(); }
}

pub static GLOBAL_ECH_CACHE: std::sync::LazyLock<Arc<EchConfigCache>> =
    std::sync::LazyLock::new(|| Arc::new(EchConfigCache::new()));

pub fn convert_to_ech_keys(data: &[u8]) -> Result<Vec<EchServerKey>, &'static str> {
    let (mut keys, mut off) = (Vec::new(), 0);
    let read_block = |off: &mut usize| -> Result<Vec<u8>, &'static str> {
        let h = data.get(*off..*off + 2).ok_or("goech: invalid length")?;
        let len = u16::from_be_bytes([h[0], h[1]]) as usize;
        *off += 2;
        let blk = data.get(*off..*off + len).ok_or("goech: invalid length")?;
        *off += len;
        Ok(blk.to_vec())
    };
    while off < data.len() {
        keys.push(EchServerKey { private_key: read_block(&mut off)?, config: read_block(&mut off)? });
    }
    Ok(keys)
}

pub fn encode_ech_keys(keys: &[EchServerKey]) -> Vec<u8> {
    let mut buf = Vec::new();
    for k in keys {
        buf.extend_from_slice(&(k.private_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&k.private_key);
        buf.extend_from_slice(&(k.config.len() as u16).to_be_bytes());
        buf.extend_from_slice(&k.config);
    }
    buf
}

pub fn parse_svcb_ech_param(svcb_params: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    while offset + 4 <= svcb_params.len() {
        let key = u16::from_be_bytes([svcb_params[offset], svcb_params[offset + 1]]);
        let len = u16::from_be_bytes([svcb_params[offset + 2], svcb_params[offset + 3]]) as usize;
        offset += 4;
        if offset + len > svcb_params.len() { return None; }
        if key == SVCB_PARAM_ECH { return Some(svcb_params[offset..offset + len].to_vec()); }
        offset += len;
    }
    None
}

pub fn encode_svcb_ech_param(ech_config: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + ech_config.len());
    buf.extend_from_slice(&SVCB_PARAM_ECH.to_be_bytes());
    buf.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
    buf.extend_from_slice(ech_config);
    buf
}

pub fn resolve_ech_config(
    ech_config_list: &str,
    server_name: &str,
    force_query: &str,
) -> Result<Option<Vec<u8>>, String> {
    if ech_config_list.is_empty() { return Ok(None); }
    let mode = if force_query.is_empty() { "full" } else { force_query };
    let result = if ech_config_list.contains("://") {
        let parts: Vec<&str> = ech_config_list.split('+').collect();
        let (name, dns_server) = match parts.as_slice() {
            [n, s] => (*n, *s),
            [s] => (server_name, *s),
            _ => return Err(format!("Invalid ECH DNS server format: {}", ech_config_list)),
        };
        if name.is_empty() {
            return Err("Using DNS for ECH Config needs serverName or example.com+server format".into());
        }
        GLOBAL_ECH_CACHE.get(dns_server, name)
    } else {
        Some(
            base64::engine::general_purpose::STANDARD
                .decode(ech_config_list.trim()).map_err(|e| format!("Failed to unmarshal ECHConfigList: {}", e))?,
        )
    };
    match result {
        Some(cfg) if !cfg.is_empty() => Ok(Some(cfg)),
        _ => Ok((mode == "full").then(|| DUMMY_FALLBACK_ECH_CONFIG.to_vec())),
    }
}

use std::collections::HashMap;

/// SplitHTTP (XHTTP) transport configuration.
#[derive(Debug, Clone, Default)]
pub struct SplitHttpConfig {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub headers: HashMap<String, String>,
    pub no_grpc_header: bool,
}

/// gRPC (Gun) transport configuration.
#[derive(Debug, Clone, Default)]
pub struct GrpcConfig {
    pub service_name: String,
    pub multi_mode: bool,
    pub idle_timeout_secs: u32,
    pub health_check_timeout_secs: u32,
}

/// mKCP transport configuration.
#[derive(Debug, Clone)]
pub struct KcpConfig {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub seed: Option<String>,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            seed: None,
        }
    }
}

/// Hysteria2 transport & congestion configuration.
#[derive(Debug, Clone, Default)]
pub struct HysteriaConfig {
    pub version: u8,
    pub auth: String,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs_type: Option<String>,
    pub obfs_password: Option<String>,
}

/// WireGuard peer & interface configuration.
#[derive(Debug, Clone, Default)]
pub struct WireGuardConfig {
    pub secret_key: String,
    pub endpoint: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub mtu: u16,
    pub keepalive_secs: u16,
    pub reserved: [u8; 3],
}

impl WireGuardConfig {
    /// Formats a standard WireGuard UAPI IPC configuration string.
    pub fn to_ipc_config(&self) -> String {
        let mut out = format!("private_key={}\n", self.secret_key);
        out.push_str(&format!("public_key={}\n", self.public_key));
        if let Some(psk) = &self.preshared_key {
            out.push_str(&format!("preshared_key={}\n", psk));
        }
        out.push_str(&format!("endpoint={}\n", self.endpoint));
        if self.keepalive_secs > 0 {
            out.push_str(&format!(
                "persistent_keepalive_interval={}\n",
                self.keepalive_secs
            ));
        }
        out
    }
}

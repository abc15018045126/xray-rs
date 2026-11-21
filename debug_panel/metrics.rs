//! Debug-only per-website connection, reuse, latency, and traffic feature telemetry.
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::debug_panel::capture::{FlowRecord, SizeBuckets};
use crate::debug_panel::probe::DirectProbeResult;

const MAX_RECENT_PROBES: usize = 20;
const MAX_RECENT_EVENTS: usize = 50;
const MAX_LATENCY_SAMPLES: usize = 200;
const MAX_PAGE_LOADS: usize = 60;
const MAX_CONN_TRACES: usize = 100;
const PAGE_LOAD_IDLE_GAP_MS: u64 = 2500;

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn percentile(samples: &VecDeque<f64>, p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = samples.iter().copied().collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    round2(sorted[idx.min(sorted.len() - 1)])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModeStats {
    pub established: u64,
    pub reused: u64,
    pub failed: u64,
    pub reuse_rate_pct: f64,
    pub avg_connect_ms: f64,
    pub p50_connect_ms: f64,
    pub p95_connect_ms: f64,
    pub max_connect_ms: f64,
    pub avg_ttfb_ms: f64,
    pub p95_ttfb_ms: f64,
    pub avg_duration_ms: f64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_fingerprint: Option<String>,
    pub size_buckets: SizeBuckets,
}

#[derive(Debug, Clone, Default)]
struct ModeStatsInner {
    established: u64,
    reused: u64,
    failed: u64,
    connect_ms_sum: f64,
    connect_ms_count: u64,
    max_connect_ms: f64,
    connect_samples: VecDeque<f64>,
    ttfb_ms_sum: f64,
    ttfb_ms_count: u64,
    ttfb_samples: VecDeque<f64>,
    duration_ms_sum: f64,
    duration_ms_count: u64,
    uplink_bytes: u64,
    downlink_bytes: u64,
    sample_fingerprint: Option<String>,
    size_buckets: SizeBuckets,
}

impl ModeStatsInner {
    fn push_connect(&mut self, ms: f64, reused: bool) {
        if reused {
            self.reused += 1;
        } else {
            self.established += 1;
        }
        self.connect_ms_sum += ms;
        self.connect_ms_count += 1;
        if ms > self.max_connect_ms {
            self.max_connect_ms = ms;
        }
        if self.connect_samples.len() >= MAX_LATENCY_SAMPLES {
            self.connect_samples.pop_front();
        }
        self.connect_samples.push_back(ms);
    }

    fn push_ttfb(&mut self, ms: f64) {
        self.ttfb_ms_sum += ms;
        self.ttfb_ms_count += 1;
        if self.ttfb_samples.len() >= MAX_LATENCY_SAMPLES {
            self.ttfb_samples.pop_front();
        }
        self.ttfb_samples.push_back(ms);
    }

    fn push_end(&mut self, uplink: u64, downlink: u64, duration_ms: f64, flow: Option<&FlowRecord>) {
        self.uplink_bytes += uplink;
        self.downlink_bytes += downlink;
        self.duration_ms_sum += duration_ms;
        self.duration_ms_count += 1;
        if let Some(f) = flow {
            if !f.first_n_sizes.is_empty() {
                self.sample_fingerprint = Some(f.fingerprint.clone());
            }
            self.size_buckets.tiny_lt_100 += f.size_buckets.tiny_lt_100;
            self.size_buckets.small_100_512 += f.size_buckets.small_100_512;
            self.size_buckets.medium_512_1400 += f.size_buckets.medium_512_1400;
            self.size_buckets.large_gt_1400 += f.size_buckets.large_gt_1400;
        }
    }

    fn to_public(&self) -> ModeStats {
        let total = self.established + self.reused;
        let reuse_rate_pct = if total > 0 {
            round2((self.reused as f64 / total as f64) * 100.0)
        } else {
            0.0
        };
        let avg_connect_ms = if self.connect_ms_count > 0 {
            round2(self.connect_ms_sum / self.connect_ms_count as f64)
        } else {
            0.0
        };
        let avg_ttfb_ms = if self.ttfb_ms_count > 0 {
            round2(self.ttfb_ms_sum / self.ttfb_ms_count as f64)
        } else {
            0.0
        };
        let avg_duration_ms = if self.duration_ms_count > 0 {
            round2(self.duration_ms_sum / self.duration_ms_count as f64)
        } else {
            0.0
        };
        ModeStats {
            established: self.established,
            reused: self.reused,
            failed: self.failed,
            reuse_rate_pct,
            avg_connect_ms,
            p50_connect_ms: percentile(&self.connect_samples, 0.50),
            p95_connect_ms: percentile(&self.connect_samples, 0.95),
            max_connect_ms: round2(self.max_connect_ms),
            avg_ttfb_ms,
            p95_ttfb_ms: percentile(&self.ttfb_samples, 0.95),
            avg_duration_ms,
            uplink_bytes: self.uplink_bytes,
            downlink_bytes: self.downlink_bytes,
            sample_fingerprint: self.sample_fingerprint.clone(),
            size_buckets: self.size_buckets.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCompare {
    pub host: String,
    pub has_both: bool,
    pub direct: ModeStats,
    pub proxy: ModeStats,
    pub delta_avg_connect_ms: f64,
    pub delta_p95_connect_ms: f64,
    pub delta_avg_ttfb_ms: f64,
}

/// Extracted traffic features from the initial client payload (normal/direct or proxied).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficFeatures {
    pub protocol: String,
    pub first_packet_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_record_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_handshake_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_user_agent: Option<String>,
    pub summary: String,
}

/// Inspect raw initial client bytes to extract normal traffic characteristics (TLS ClientHello or HTTP).
pub fn inspect_initial_payload(buf: &[u8]) -> TrafficFeatures {
    if buf.is_empty() {
        return TrafficFeatures {
            protocol: "unknown".into(),
            first_packet_bytes: 0,
            summary: "empty initial payload".into(),
            ..Default::default()
        };
    }

    // Check TLS ClientHello: ContentType = 0x16 (Handshake), HandshakeType = 0x01 (ClientHello)
    if buf.len() >= 43 && buf[0] == 0x16 && buf[5] == 0x01 {
        return parse_tls_client_hello(buf);
    }

    // Check HTTP/1.x plaintext request
    if let Ok(text) = std::str::from_utf8(&buf[..buf.len().min(1024)]) {
        let first_line = text.lines().next().unwrap_or("");
        let http_methods = [
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ",
        ];
        if http_methods.iter().any(|m| first_line.starts_with(m)) {
            let method = first_line.split_whitespace().next().map(|s| s.to_string());
            let mut host = None;
            let mut ua = None;
            for line in text.lines().skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim().to_ascii_lowercase();
                    let val = v.trim().to_string();
                    if key == "host" {
                        host = Some(val);
                    } else if key == "user-agent" {
                        ua = Some(val);
                    }
                }
            }
            let summary = format!(
                "HTTP {} host={} len={}B",
                method.as_deref().unwrap_or("?"),
                host.as_deref().unwrap_or("-"),
                buf.len()
            );
            return TrafficFeatures {
                protocol: "http".into(),
                first_packet_bytes: buf.len(),
                http_method: method,
                http_host: host,
                http_user_agent: ua,
                summary,
                ..Default::default()
            };
        }
    }

    TrafficFeatures {
        protocol: "tcp/raw".into(),
        first_packet_bytes: buf.len(),
        summary: format!("raw TCP payload ({}B, magic=0x{:02x}{:02x})", buf.len(), buf[0], buf.get(1).copied().unwrap_or(0)),
        ..Default::default()
    }
}

fn tls_ver_str(major: u8, minor: u8) -> String {
    match (major, minor) {
        (3, 0) => "SSL 3.0".into(),
        (3, 1) => "TLS 1.0".into(),
        (3, 2) => "TLS 1.1".into(),
        (3, 3) => "TLS 1.2".into(),
        (3, 4) => "TLS 1.3".into(),
        _ => format!("0x{:02x}{:02x}", major, minor),
    }
}

fn parse_tls_client_hello(buf: &[u8]) -> TrafficFeatures {
    let record_ver = tls_ver_str(buf[1], buf[2]);
    let handshake_ver = tls_ver_str(buf[9], buf[10]);

    let mut features = TrafficFeatures {
        protocol: "tls".into(),
        first_packet_bytes: buf.len(),
        tls_record_version: Some(record_ver.clone()),
        tls_handshake_version: Some(handshake_ver.clone()),
        ..Default::default()
    };

    // Offset after: 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random) = 43
    let mut pos = 43;
    if pos >= buf.len() {
        features.summary = format!("TLS {} ClientHello ({}B)", handshake_ver, buf.len());
        return features;
    }

    // Session ID
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > buf.len() {
        features.summary = format!("TLS {} ClientHello ({}B)", handshake_ver, buf.len());
        return features;
    }

    // Cipher Suites
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    features.cipher_suite_count = Some(cs_len / 2);
    pos += 2 + cs_len;
    if pos + 1 > buf.len() {
        features.summary = format!("TLS {} ClientHello ({}B)", handshake_ver, buf.len());
        return features;
    }

    // Compression methods
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        features.summary = format!("TLS {} ClientHello ({}B)", handshake_ver, buf.len());
        return features;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());
    let mut ext_count = 0usize;
    let mut supported_tls13 = false;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        ext_count += 1;
        let data = &buf[pos..pos + ext_len];

        match ext_type {
            // SNI (0x0000)
            0x0000 if data.len() >= 5 => {
                let mut p = 2;
                while p + 3 <= data.len() {
                    let name_type = data[p];
                    let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
                    p += 3;
                    if name_type == 0 && p + name_len <= data.len() {
                        if let Ok(sni) = std::str::from_utf8(&data[p..p + name_len]) {
                            features.sni = Some(sni.to_string());
                        }
                        break;
                    }
                    p += name_len;
                }
            }
            // ALPN (0x0010)
            0x0010 if data.len() >= 2 => {
                let mut p = 2;
                while p < data.len() {
                    let l = data[p] as usize;
                    p += 1;
                    if p + l <= data.len() {
                        if let Ok(proto) = std::str::from_utf8(&data[p..p + l]) {
                            features.alpn.push(proto.to_string());
                        }
                    }
                    p += l;
                }
            }
            // supported_versions (0x002b)
            0x002b if data.len() >= 3 => {
                let list_len = data[0] as usize;
                let mut p = 1;
                while p + 2 <= (1 + list_len).min(data.len()) {
                    if data[p] == 0x03 && data[p + 1] == 0x04 {
                        supported_tls13 = true;
                    }
                    p += 2;
                }
            }
            _ => {}
        }

        pos += ext_len;
    }

    features.extension_count = Some(ext_count);
    if supported_tls13 {
        features.tls_handshake_version = Some("TLS 1.3".into());
    }

    features.summary = format!(
        "TLS {} SNI={} ALPN=[{}] ciphers={} exts={} len={}B",
        features.tls_handshake_version.as_deref().unwrap_or(&handshake_ver),
        features.sni.as_deref().unwrap_or("-"),
        features.alpn.join(","),
        features.cipher_suite_count.unwrap_or(0),
        ext_count,
        buf.len()
    );
    features
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMetrics {
    pub host: String,
    pub established: u64,
    pub reused: u64,
    pub active: u64,
    pub failed: u64,
    pub reuse_rate_pct: f64,
    pub bypassed_count: u64,
    pub proxied_count: u64,
    pub avg_connect_ms: f64,
    pub p50_connect_ms: f64,
    pub p95_connect_ms: f64,
    pub min_connect_ms: f64,
    pub max_connect_ms: f64,
    pub last_connect_ms: f64,
    pub avg_ttfb_ms: f64,
    pub p95_ttfb_ms: f64,
    pub avg_duration_ms: f64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub last_outbound: String,
    pub last_protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_traffic_features: Option<TrafficFeatures>,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone)]
struct SiteMetricsInner {
    host: String,
    established: u64,
    reused: u64,
    active: u64,
    failed: u64,
    bypassed_count: u64,
    proxied_count: u64,
    connect_ms_sum: f64,
    connect_ms_count: u64,
    min_connect_ms: f64,
    max_connect_ms: f64,
    last_connect_ms: f64,
    connect_samples: VecDeque<f64>,
    ttfb_ms_sum: f64,
    ttfb_ms_count: u64,
    ttfb_samples: VecDeque<f64>,
    duration_ms_sum: f64,
    duration_ms_count: u64,
    uplink_bytes: u64,
    downlink_bytes: u64,
    last_outbound: String,
    last_protocol: String,
    last_fingerprint: Option<String>,
    last_traffic_features: Option<TrafficFeatures>,
    direct_mode: ModeStatsInner,
    proxy_mode: ModeStatsInner,
    last_seen_ms: u64,
}

impl SiteMetricsInner {
    fn new(host: String) -> Self {
        Self {
            host,
            established: 0,
            reused: 0,
            active: 0,
            failed: 0,
            bypassed_count: 0,
            proxied_count: 0,
            connect_ms_sum: 0.0,
            connect_ms_count: 0,
            min_connect_ms: f64::MAX,
            max_connect_ms: 0.0,
            last_connect_ms: 0.0,
            connect_samples: VecDeque::with_capacity(MAX_LATENCY_SAMPLES),
            ttfb_ms_sum: 0.0,
            ttfb_ms_count: 0,
            ttfb_samples: VecDeque::with_capacity(MAX_LATENCY_SAMPLES),
            duration_ms_sum: 0.0,
            duration_ms_count: 0,
            uplink_bytes: 0,
            downlink_bytes: 0,
            last_outbound: String::new(),
            last_protocol: "unknown".into(),
            last_fingerprint: None,
            last_traffic_features: None,
            direct_mode: ModeStatsInner::default(),
            proxy_mode: ModeStatsInner::default(),
            last_seen_ms: now_epoch_ms(),
        }
    }

    fn to_public(&self) -> SiteMetrics {
        let total = self.established + self.reused;
        let reuse_rate_pct = if total > 0 {
            round2((self.reused as f64 / total as f64) * 100.0)
        } else {
            0.0
        };
        let avg_connect_ms = if self.connect_ms_count > 0 {
            round2(self.connect_ms_sum / self.connect_ms_count as f64)
        } else {
            0.0
        };
        let min_connect_ms = if self.connect_ms_count > 0 {
            round2(self.min_connect_ms)
        } else {
            0.0
        };
        let avg_ttfb_ms = if self.ttfb_ms_count > 0 {
            round2(self.ttfb_ms_sum / self.ttfb_ms_count as f64)
        } else {
            0.0
        };
        let avg_duration_ms = if self.duration_ms_count > 0 {
            round2(self.duration_ms_sum / self.duration_ms_count as f64)
        } else {
            0.0
        };

        SiteMetrics {
            host: self.host.clone(),
            established: self.established,
            reused: self.reused,
            active: self.active,
            failed: self.failed,
            reuse_rate_pct,
            bypassed_count: self.bypassed_count,
            proxied_count: self.proxied_count,
            avg_connect_ms,
            p50_connect_ms: percentile(&self.connect_samples, 0.50),
            p95_connect_ms: percentile(&self.connect_samples, 0.95),
            min_connect_ms,
            max_connect_ms: round2(self.max_connect_ms),
            last_connect_ms: round2(self.last_connect_ms),
            avg_ttfb_ms,
            p95_ttfb_ms: percentile(&self.ttfb_samples, 0.95),
            avg_duration_ms,
            uplink_bytes: self.uplink_bytes,
            downlink_bytes: self.downlink_bytes,
            last_outbound: self.last_outbound.clone(),
            last_protocol: self.last_protocol.clone(),
            last_fingerprint: self.last_fingerprint.clone(),
            last_traffic_features: self.last_traffic_features.clone(),
            last_seen_ms: self.last_seen_ms,
        }
    }

    fn to_compare(&self) -> SiteCompare {
        let direct = self.direct_mode.to_public();
        let proxy = self.proxy_mode.to_public();
        let has_both = (direct.established + direct.reused) > 0 && (proxy.established + proxy.reused) > 0;
        SiteCompare {
            host: self.host.clone(),
            has_both,
            delta_avg_connect_ms: round2(proxy.avg_connect_ms - direct.avg_connect_ms),
            delta_p95_connect_ms: round2(proxy.p95_connect_ms - direct.p95_connect_ms),
            delta_avg_ttfb_ms: round2(proxy.avg_ttfb_ms - direct.avg_ttfb_ms),
            direct,
            proxy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectBypassConfig {
    /// When true, matching connections bypass proxy outbounds and go directly through the OS kernel.
    pub enabled: bool,
    /// Optional domain filter. If empty and `enabled == true`, ALL traffic bypasses proxy directly.
    pub domains: Vec<String>,
}

impl Default for DirectBypassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
        }
    }
}

impl DirectBypassConfig {
    pub fn should_bypass(&self, host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.domains.is_empty() {
            return true;
        }
        let h = host.to_ascii_lowercase();
        self.domains.iter().any(|d| {
            let d = d.trim().to_ascii_lowercase();
            !d.is_empty() && (h == d || h.ends_with(&format!(".{}", d)))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub timestamp_ms: u64,
    pub host: String,
    pub outbound: String,
    pub bypassed: bool,
    pub reused: bool,
    pub connect_ms: f64,
    pub status: String,
    pub feature_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalsSummary {
    pub total_sites: usize,
    pub total_established: u64,
    pub total_reused: u64,
    pub total_active: u64,
    pub total_failed: u64,
    pub overall_reuse_rate_pct: f64,
    pub total_bypassed: u64,
    pub total_proxied: u64,
    pub avg_connect_ms: f64,
    pub total_uplink_bytes: u64,
    pub total_downlink_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageLoadRecord {
    pub site: String,
    pub started_at_ms: u64,
    pub first_connect_ms: f64,
    pub first_byte_ms: f64,
    pub load_time_ms: f64,
    pub conn_count: u64,
    pub failed_count: u64,
    pub downlink_bytes: u64,
    pub outbound: String,
    pub bypassed: bool,
    pub status: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone)]
struct PageLoadInner {
    site: String,
    started_at_ms: u64,
    last_activity_ms: u64,
    first_connect_ms: f64,
    first_byte_ms: Option<f64>,
    conn_count: u64,
    failed_count: u64,
    downlink_bytes: u64,
    outbound: String,
    bypassed: bool,
    hosts: Vec<String>,
}

impl PageLoadInner {
    fn to_public(&self, now_ms: u64) -> PageLoadRecord {
        let is_done = now_ms.saturating_sub(self.last_activity_ms) >= PAGE_LOAD_IDLE_GAP_MS;
        let span_ms = self.last_activity_ms.saturating_sub(self.started_at_ms) as f64;
        let min_floor = self.first_byte_ms.unwrap_or(self.first_connect_ms);
        let load_time_ms = round2(span_ms.max(min_floor));
        PageLoadRecord {
            site: self.site.clone(),
            started_at_ms: self.started_at_ms,
            first_connect_ms: round2(self.first_connect_ms),
            first_byte_ms: round2(self.first_byte_ms.unwrap_or(0.0)),
            load_time_ms,
            conn_count: self.conn_count,
            failed_count: self.failed_count,
            downlink_bytes: self.downlink_bytes,
            outbound: self.outbound.clone(),
            bypassed: self.bypassed,
            status: if is_done {
                "done".into()
            } else {
                "loading".into()
            },
            hosts: self.hosts.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub name: String,
    pub offset_ms: f64,
    pub duration_ms: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTrace {
    pub id: u64,
    pub started_at_ms: u64,
    pub host: String,
    pub target: String,
    pub inbound: String,
    pub outbound: String,
    pub mode: String,
    pub reused: bool,
    pub total_ms: f64,
    pub status: String,
    pub error: Option<String>,
    pub steps: Vec<TraceStep>,
}

pub struct DebugMetricsStore {
    sites: RwLock<HashMap<String, SiteMetricsInner>>,
    bypass: RwLock<DirectBypassConfig>,
    recent_probes: RwLock<VecDeque<DirectProbeResult>>,
    recent_events: RwLock<VecDeque<ConnectionEvent>>,
    page_loads: RwLock<VecDeque<PageLoadInner>>,
    conn_traces: RwLock<VecDeque<ConnectionTrace>>,
    next_trace_id: AtomicU64,
}

impl Default for DebugMetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugMetricsStore {
    pub fn new() -> Self {
        Self {
            sites: RwLock::new(HashMap::new()),
            bypass: RwLock::new(DirectBypassConfig::default()),
            recent_probes: RwLock::new(VecDeque::with_capacity(MAX_RECENT_PROBES)),
            recent_events: RwLock::new(VecDeque::with_capacity(MAX_RECENT_EVENTS)),
            page_loads: RwLock::new(VecDeque::with_capacity(MAX_PAGE_LOADS)),
            conn_traces: RwLock::new(VecDeque::with_capacity(MAX_CONN_TRACES)),
            next_trace_id: AtomicU64::new(1),
        }
    }

    pub fn bypass_config(&self) -> DirectBypassConfig {
        self.bypass
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_bypass(&self, enabled: bool, domains: Option<Vec<String>>) -> DirectBypassConfig {
        let mut guard = self.bypass.write().unwrap_or_else(|e| e.into_inner());
        guard.enabled = enabled;
        if let Some(d) = domains {
            guard.domains = d
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        guard.clone()
    }

    pub fn should_bypass(&self, host: &str) -> bool {
        self.bypass
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .should_bypass(host)
    }

    /// Record a newly established (or reused) connection attempt.
    pub fn record_connect_start(
        &self,
        host: &str,
        outbound: &str,
        bypassed: bool,
        reused: bool,
        connect_ms: f64,
        features: Option<TrafficFeatures>,
    ) {
        let now = now_epoch_ms();
        let host_key = normalize_host(host);
        let feature_summary = features
            .as_ref()
            .map(|f| f.summary.clone())
            .unwrap_or_default();

        {
            let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
            let entry = sites
                .entry(host_key.clone())
                .or_insert_with(|| SiteMetricsInner::new(host_key.clone()));

            if reused {
                entry.reused += 1;
            } else {
                entry.established += 1;
            }
            entry.active += 1;
            if bypassed {
                entry.bypassed_count += 1;
                entry.direct_mode.push_connect(connect_ms, reused);
            } else {
                entry.proxied_count += 1;
                entry.proxy_mode.push_connect(connect_ms, reused);
            }
            entry.connect_ms_sum += connect_ms;
            entry.connect_ms_count += 1;
            if connect_ms < entry.min_connect_ms {
                entry.min_connect_ms = connect_ms;
            }
            if connect_ms > entry.max_connect_ms {
                entry.max_connect_ms = connect_ms;
            }
            if entry.connect_samples.len() >= MAX_LATENCY_SAMPLES {
                entry.connect_samples.pop_front();
            }
            entry.connect_samples.push_back(connect_ms);
            entry.last_connect_ms = connect_ms;
            entry.last_outbound = outbound.to_string();
            if let Some(f) = features {
                entry.last_protocol = f.protocol.clone();
                entry.last_traffic_features = Some(f);
            }
            entry.last_seen_ms = now;
        }

        self.update_page_load_start(&host_key, outbound, bypassed, connect_ms, now);

        self.push_event(ConnectionEvent {
            timestamp_ms: now,
            host: host_key,
            outbound: outbound.to_string(),
            bypassed,
            reused,
            connect_ms: (connect_ms * 100.0).round() / 100.0,
            status: "ok".into(),
            feature_summary,
        });
    }

    /// Record a failed connection attempt.
    pub fn record_connect_failed(
        &self,
        host: &str,
        outbound: &str,
        bypassed: bool,
        connect_ms: f64,
        err_msg: &str,
    ) {
        let now = now_epoch_ms();
        let host_key = normalize_host(host);
        {
            let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
            let entry = sites
                .entry(host_key.clone())
                .or_insert_with(|| SiteMetricsInner::new(host_key.clone()));
            entry.failed += 1;
            if bypassed {
                entry.direct_mode.failed += 1;
            } else {
                entry.proxy_mode.failed += 1;
            }
            entry.last_outbound = outbound.to_string();
            entry.last_seen_ms = now;
        }
        self.update_page_load_fail(&host_key, outbound, bypassed, connect_ms, now);

        self.push_event(ConnectionEvent {
            timestamp_ms: now,
            host: host_key,
            outbound: outbound.to_string(),
            bypassed,
            reused: false,
            connect_ms: (connect_ms * 100.0).round() / 100.0,
            status: format!("err: {}", err_msg),
            feature_summary: String::new(),
        });
    }

    /// Record a connection reuse hit from a connection pool (e.g. PingoraStreamPool).
    pub fn record_pool_reuse(&self, host: &str, outbound: &str) {
        let host_key = normalize_host(host);
        let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
        let entry = sites
            .entry(host_key.clone())
            .or_insert_with(|| SiteMetricsInner::new(host_key));
        entry.reused += 1;
        entry.last_outbound = outbound.to_string();
        entry.last_seen_ms = now_epoch_ms();
    }

    /// Record time-to-first-byte (TTFB ms) from server for a connection.
    pub fn record_ttfb(&self, host: &str, bypassed: bool, ttfb_ms: f64) {
        let host_key = normalize_host(host);
        let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = sites.get_mut(&host_key) {
            entry.ttfb_ms_sum += ttfb_ms;
            entry.ttfb_ms_count += 1;
            if entry.ttfb_samples.len() >= MAX_LATENCY_SAMPLES {
                entry.ttfb_samples.pop_front();
            }
            entry.ttfb_samples.push_back(ttfb_ms);
            if bypassed {
                entry.direct_mode.push_ttfb(ttfb_ms);
            } else {
                entry.proxy_mode.push_ttfb(ttfb_ms);
            }
        }
        self.update_page_load_ttfb(&host_key, ttfb_ms, now_epoch_ms());
    }

    /// Record connection completion, transferred bytes, duration, and optional flow fingerprint.
    pub fn record_connect_end(
        &self,
        host: &str,
        bypassed: bool,
        uplink: u64,
        downlink: u64,
        duration_ms: f64,
        flow: Option<FlowRecord>,
    ) {
        let host_key = normalize_host(host);
        let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = sites.get_mut(&host_key) {
            entry.active = entry.active.saturating_sub(1);
            entry.uplink_bytes += uplink;
            entry.downlink_bytes += downlink;
            entry.duration_ms_sum += duration_ms;
            entry.duration_ms_count += 1;
            if let Some(ref f) = flow
                && !f.first_n_sizes.is_empty()
            {
                entry.last_fingerprint = Some(f.fingerprint.clone());
            }
            if bypassed {
                entry
                    .direct_mode
                    .push_end(uplink, downlink, duration_ms, flow.as_ref());
            } else {
                entry
                    .proxy_mode
                    .push_end(uplink, downlink, duration_ms, flow.as_ref());
            }
            entry.last_seen_ms = now_epoch_ms();
        }
        self.update_page_load_end(&host_key, downlink, now_epoch_ms());
    }

    /// Direct vs Proxy A/B comparison across sites (prioritizing sites that have BOTH direct & proxy data).
    pub fn compare(&self, host_filter: Option<&str>) -> Vec<SiteCompare> {
        let sites = self.sites.read().unwrap_or_else(|e| e.into_inner());
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());
        let mut list: Vec<SiteCompare> = sites
            .values()
            .filter(|s| match &filter_lc {
                Some(f) if !f.is_empty() => s.host.to_ascii_lowercase().contains(f),
                _ => true,
            })
            .map(|s| s.to_compare())
            .collect();
        list.sort_by(|a, b| {
            b.has_both.cmp(&a.has_both).then_with(|| {
                let ta = a.direct.established + a.proxy.established;
                let tb = b.direct.established + b.proxy.established;
                tb.cmp(&ta)
            })
        });
        list
    }

    pub fn record_probe(&self, probe: DirectProbeResult) {
        // Also reflect the probe in site metrics so the site table shows the tested host
        {
            let host_key = normalize_host(&probe.host);
            let mut sites = self.sites.write().unwrap_or_else(|e| e.into_inner());
            let entry = sites
                .entry(host_key.clone())
                .or_insert_with(|| SiteMetricsInner::new(host_key));
            if probe.success {
                entry.established += 1;
                entry.bypassed_count += 1;
                if probe.reuse_succeeded {
                    entry.reused += 1;
                }
                let ms = probe.tcp_connect_ms;
                entry.connect_ms_sum += ms;
                entry.connect_ms_count += 1;
                if ms < entry.min_connect_ms {
                    entry.min_connect_ms = ms;
                }
                if ms > entry.max_connect_ms {
                    entry.max_connect_ms = ms;
                }
                if entry.connect_samples.len() >= MAX_LATENCY_SAMPLES {
                    entry.connect_samples.pop_front();
                }
                entry.connect_samples.push_back(ms);
                entry.direct_mode.push_connect(ms, false);
                if probe.reuse_succeeded {
                    entry.direct_mode.reused += 1;
                }
                if probe.first_request_ms > 0.0 {
                    entry.ttfb_ms_sum += probe.first_request_ms;
                    entry.ttfb_ms_count += 1;
                    if entry.ttfb_samples.len() >= MAX_LATENCY_SAMPLES {
                        entry.ttfb_samples.pop_front();
                    }
                    entry.ttfb_samples.push_back(probe.first_request_ms);
                    entry.direct_mode.push_ttfb(probe.first_request_ms);
                }
                entry.last_connect_ms = ms;
                entry.last_outbound = "debug-direct-probe".into();
                entry.last_protocol = if probe.tls_version.is_some() {
                    "tls".into()
                } else {
                    "http".into()
                };
                entry.last_traffic_features = Some(TrafficFeatures {
                    protocol: entry.last_protocol.clone(),
                    first_packet_bytes: 0,
                    tls_record_version: probe.tls_version.clone(),
                    tls_handshake_version: probe.tls_version.clone(),
                    sni: Some(probe.host.clone()),
                    alpn: probe.alpn.clone().into_iter().collect(),
                    cipher_suite_count: None,
                    extension_count: None,
                    http_method: Some("HEAD".into()),
                    http_host: Some(probe.host.clone()),
                    http_user_agent: None,
                    summary: probe.feature_summary.clone(),
                });
            } else {
                entry.failed += 1;
            }
            entry.last_seen_ms = now_epoch_ms();
        }

        let mut probes = self
            .recent_probes
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if probes.len() >= MAX_RECENT_PROBES {
            probes.pop_front();
        }
        probes.push_back(probe);
    }

    pub fn sites(&self, host_filter: Option<&str>) -> Vec<SiteMetrics> {
        let sites = self.sites.read().unwrap_or_else(|e| e.into_inner());
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());
        let mut list: Vec<SiteMetrics> = sites
            .values()
            .filter(|s| match &filter_lc {
                Some(f) if !f.is_empty() => s.host.to_ascii_lowercase().contains(f),
                _ => true,
            })
            .map(|s| s.to_public())
            .collect();
        // Sort by total connections descending, then last_seen descending
        list.sort_by(|a, b| {
            (b.established + b.reused)
                .cmp(&(a.established + a.reused))
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        list
    }

    pub fn totals(&self) -> TotalsSummary {
        let sites = self.sites.read().unwrap_or_else(|e| e.into_inner());
        let mut total_established = 0u64;
        let mut total_reused = 0u64;
        let mut total_active = 0u64;
        let mut total_failed = 0u64;
        let mut total_bypassed = 0u64;
        let mut total_proxied = 0u64;
        let mut total_uplink = 0u64;
        let mut total_downlink = 0u64;
        let mut ms_sum = 0.0f64;
        let mut ms_cnt = 0u64;

        for s in sites.values() {
            total_established += s.established;
            total_reused += s.reused;
            total_active += s.active;
            total_failed += s.failed;
            total_bypassed += s.bypassed_count;
            total_proxied += s.proxied_count;
            total_uplink += s.uplink_bytes;
            total_downlink += s.downlink_bytes;
            ms_sum += s.connect_ms_sum;
            ms_cnt += s.connect_ms_count;
        }

        let total = total_established + total_reused;
        let overall_reuse_rate_pct = if total > 0 {
            ((total_reused as f64 / total as f64) * 10000.0).round() / 100.0
        } else {
            0.0
        };
        let avg_connect_ms = if ms_cnt > 0 {
            ((ms_sum / ms_cnt as f64) * 100.0).round() / 100.0
        } else {
            0.0
        };

        TotalsSummary {
            total_sites: sites.len(),
            total_established,
            total_reused,
            total_active,
            total_failed,
            overall_reuse_rate_pct,
            total_bypassed,
            total_proxied,
            avg_connect_ms,
            total_uplink_bytes: total_uplink,
            total_downlink_bytes: total_downlink,
        }
    }

    pub fn recent_probes(&self) -> Vec<DirectProbeResult> {
        self.recent_probes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn recent_events(&self) -> Vec<ConnectionEvent> {
        self.recent_events
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn page_loads(&self, host_filter: Option<&str>) -> Vec<PageLoadRecord> {
        let now = now_epoch_ms();
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());
        self.page_loads
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .filter(|p| match &filter_lc {
                Some(f) if !f.is_empty() => {
                    p.site.to_ascii_lowercase().contains(f)
                        || p.hosts.iter().any(|h| h.to_ascii_lowercase().contains(f))
                }
                _ => true,
            })
            .map(|p| p.to_public(now))
            .collect()
    }

    fn update_page_load_start(
        &self,
        host: &str,
        outbound: &str,
        bypassed: bool,
        connect_ms: f64,
        now: u64,
    ) {
        let site = root_site(host);
        let mut loads = self.page_loads.write().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = loads
            .iter_mut()
            .rev()
            .find(|p| p.site == site && now.saturating_sub(p.last_activity_ms) < PAGE_LOAD_IDLE_GAP_MS)
        {
            active.conn_count += 1;
            active.last_activity_ms = now;
            if active.hosts.len() < 6 && !active.hosts.iter().any(|h| h == host) {
                active.hosts.push(host.to_string());
            }
            return;
        }
        if loads.len() >= MAX_PAGE_LOADS {
            loads.pop_front();
        }
        let started_at_ms = now.saturating_sub(connect_ms.round() as u64);
        loads.push_back(PageLoadInner {
            site,
            started_at_ms,
            last_activity_ms: now,
            first_connect_ms: connect_ms,
            first_byte_ms: None,
            conn_count: 1,
            failed_count: 0,
            downlink_bytes: 0,
            outbound: outbound.to_string(),
            bypassed,
            hosts: vec![host.to_string()],
        });
    }

    fn update_page_load_ttfb(&self, host: &str, ttfb_ms: f64, now: u64) {
        let site = root_site(host);
        let mut loads = self.page_loads.write().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = loads
            .iter_mut()
            .rev()
            .find(|p| p.site == site && now.saturating_sub(p.last_activity_ms) < PAGE_LOAD_IDLE_GAP_MS * 2)
        {
            if active.first_byte_ms.is_none() {
                active.first_byte_ms = Some(ttfb_ms);
            }
            active.last_activity_ms = now;
        }
    }

    fn update_page_load_fail(
        &self,
        host: &str,
        outbound: &str,
        bypassed: bool,
        connect_ms: f64,
        now: u64,
    ) {
        let site = root_site(host);
        let mut loads = self.page_loads.write().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = loads
            .iter_mut()
            .rev()
            .find(|p| p.site == site && now.saturating_sub(p.last_activity_ms) < PAGE_LOAD_IDLE_GAP_MS)
        {
            active.failed_count += 1;
            active.last_activity_ms = now;
            return;
        }
        if loads.len() >= MAX_PAGE_LOADS {
            loads.pop_front();
        }
        let started_at_ms = now.saturating_sub(connect_ms.round() as u64);
        loads.push_back(PageLoadInner {
            site,
            started_at_ms,
            last_activity_ms: now,
            first_connect_ms: connect_ms,
            first_byte_ms: None,
            conn_count: 0,
            failed_count: 1,
            downlink_bytes: 0,
            outbound: outbound.to_string(),
            bypassed,
            hosts: vec![host.to_string()],
        });
    }

    fn update_page_load_end(&self, host: &str, downlink: u64, now: u64) {
        let site = root_site(host);
        let mut loads = self.page_loads.write().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = loads
            .iter_mut()
            .rev()
            .find(|p| p.site == site && now.saturating_sub(p.last_activity_ms) < PAGE_LOAD_IDLE_GAP_MS * 2)
        {
            active.downlink_bytes += downlink;
            if downlink > 0 {
                active.last_activity_ms = now;
            }
        }
    }

    pub fn reset(&self) {
        self.sites.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.recent_probes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.recent_events
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.page_loads
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.conn_traces
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn start_trace(&self, host: &str, target: &str, inbound: &str) -> u64 {
        let id = self.next_trace_id.fetch_add(1, Ordering::Relaxed);
        let trace = ConnectionTrace {
            id,
            started_at_ms: now_epoch_ms(),
            host: normalize_host(host),
            target: target.to_string(),
            inbound: inbound.to_string(),
            outbound: String::new(),
            mode: "pending".into(),
            reused: false,
            total_ms: 0.0,
            status: "active".into(),
            error: None,
            steps: Vec::with_capacity(8),
        };
        let mut traces = self.conn_traces.write().unwrap_or_else(|e| e.into_inner());
        if traces.len() >= MAX_CONN_TRACES {
            traces.pop_front();
        }
        traces.push_back(trace);
        id
    }

    pub fn update_trace_meta(
        &self,
        trace_id: u64,
        host: Option<&str>,
        outbound: Option<&str>,
        mode: Option<&str>,
        reused: Option<bool>,
    ) {
        let mut traces = self.conn_traces.write().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = traces.iter_mut().rev().find(|t| t.id == trace_id) {
            if let Some(h) = host {
                t.host = normalize_host(h);
            }
            if let Some(o) = outbound {
                t.outbound = o.to_string();
            }
            if let Some(m) = mode {
                t.mode = m.to_string();
            }
            if let Some(r) = reused {
                t.reused = r;
            }
        }
    }

    pub fn add_trace_step(
        &self,
        trace_id: u64,
        name: &str,
        offset_ms: f64,
        duration_ms: f64,
        detail: impl Into<String>,
    ) {
        let mut traces = self.conn_traces.write().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = traces.iter_mut().rev().find(|t| t.id == trace_id) {
            let end = offset_ms + duration_ms;
            if end > t.total_ms {
                t.total_ms = round2(end);
            }
            t.steps.push(TraceStep {
                name: name.to_string(),
                offset_ms: round2(offset_ms),
                duration_ms: round2(duration_ms),
                detail: detail.into(),
            });
        }
    }

    pub fn finish_trace(&self, trace_id: u64, total_ms: f64, error: Option<&str>) {
        let mut traces = self.conn_traces.write().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = traces.iter_mut().rev().find(|t| t.id == trace_id) {
            if total_ms > t.total_ms {
                t.total_ms = round2(total_ms);
            }
            if let Some(err) = error {
                t.status = "failed".into();
                t.error = Some(err.to_string());
            } else if t.status == "active" {
                t.status = "ok".into();
            }
        }
    }

    pub fn traces(&self, host_filter: Option<&str>, limit: usize) -> Vec<ConnectionTrace> {
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());
        self.conn_traces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .filter(|t| match &filter_lc {
                Some(f) if !f.is_empty() => {
                    t.host.to_ascii_lowercase().contains(f)
                        || t.target.to_ascii_lowercase().contains(f)
                        || t.outbound.to_ascii_lowercase().contains(f)
                }
                _ => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    fn push_event(&self, ev: ConnectionEvent) {
        let mut events = self
            .recent_events
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if events.len() >= MAX_RECENT_EVENTS {
            events.pop_front();
        }
        events.push_back(ev);
    }
}

pub fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim();
    // Strip scheme if any
    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    // Strip path
    let host_port = no_scheme.split('/').next().unwrap_or(no_scheme);
    // Strip port for IPv4 / domain (keep IPv6 brackets cleanly)
    if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .unwrap_or(host_port)
            .trim_start_matches('[')
            .to_string()
    } else if let Some((h, _p)) = host_port.rsplit_once(':') {
        if !h.contains(':') {
            h.to_ascii_lowercase()
        } else {
            host_port.to_ascii_lowercase()
        }
    } else {
        host_port.to_ascii_lowercase()
    }
}

pub fn root_site(host: &str) -> String {
    let h = normalize_host(host);
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    // Group well-known CDN companion domains under their main website
    if h.ends_with(".ytimg.com")
        || h == "ytimg.com"
        || h.ends_with(".googlevideo.com")
        || h.ends_with(".ggpht.com")
    {
        return "youtube.com".into();
    }
    if h.ends_with(".twimg.com") || h == "twimg.com" || h.ends_with(".twitter.com") || h == "twitter.com" {
        return "x.com".into();
    }
    if h.ends_with(".bdstatic.com") || h.ends_with(".bcebos.com") {
        return "baidu.com".into();
    }
    if h.ends_with(".hdslb.com") || h.ends_with(".bilivideo.com") {
        return "bilibili.com".into();
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() <= 2 {
        return h;
    }
    let last2 = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if matches!(
        last2.as_str(),
        "com.cn" | "net.cn" | "org.cn" | "gov.cn" | "co.uk" | "co.jp" | "com.hk" | "com.tw"
    ) && parts.len() >= 3
    {
        return format!("{}.{}", parts[parts.len() - 3], last2);
    }
    last2
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

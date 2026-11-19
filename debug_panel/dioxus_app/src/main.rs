//! Debug-only Dioxus Desktop Dashboard for `xray-rs`.
//! Matches the Web Dashboard 1:1 with a left vertical sidebar:
//! Home | Direct vs Proxy A/B Compare | Flows & Wireshark Capture | Latency & TTFB | AI API.
//! Only active in debug builds (`cfg(debug_assertions)`).

#[cfg(not(debug_assertions))]
fn main() {
    eprintln!("xray-debug-panel is disabled in release builds (debug_assertions only).");
}

#[cfg(debug_assertions)]
fn main() {
    dioxus::launch(app::App);
}

#[cfg(debug_assertions)]
mod app {
    use dioxus::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    const DEFAULT_API: &str = "http://127.0.0.1:19876";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Tab {
        Home,
        Compare,
        Flows,
        Latency,
        Ai,
    }

    impl Tab {
        fn title(&self) -> &'static str {
            match self {
                Tab::Home => "主页总览",
                Tab::Compare => "直连 vs 代理对比 (A/B)",
                Tab::Flows => "流指纹与 Wireshark 抓包",
                Tab::Latency => "延迟分位 (P50/P95) 与 TTFB 分布",
                Tab::Ai => "极简 AI 接口",
            }
        }
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct ResourceSnapshot {
        pub pid: u32,
        pub cpu_percent: f64,
        pub memory_rss_mb: f64,
        pub memory_private_mb: f64,
        pub memory_peak_mb: f64,
        pub cpu_cores: usize,
        pub uptime_secs: u64,
        pub timestamp_ms: u64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct DirectBypassConfig {
        pub enabled: bool,
        pub domains: Vec<String>,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct TrafficFeatures {
        pub protocol: String,
        pub first_packet_bytes: usize,
        pub tls_record_version: Option<String>,
        pub tls_handshake_version: Option<String>,
        pub sni: Option<String>,
        #[serde(default)]
        pub alpn: Vec<String>,
        pub cipher_suite_count: Option<usize>,
        pub extension_count: Option<usize>,
        pub http_method: Option<String>,
        pub http_host: Option<String>,
        pub http_user_agent: Option<String>,
        pub summary: String,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
        #[serde(default)]
        pub p50_connect_ms: f64,
        #[serde(default)]
        pub p95_connect_ms: f64,
        pub min_connect_ms: f64,
        pub max_connect_ms: f64,
        pub last_connect_ms: f64,
        #[serde(default)]
        pub avg_ttfb_ms: f64,
        #[serde(default)]
        pub p95_ttfb_ms: f64,
        #[serde(default)]
        pub avg_duration_ms: f64,
        pub uplink_bytes: u64,
        pub downlink_bytes: u64,
        pub last_outbound: String,
        pub last_protocol: String,
        #[serde(default)]
        pub last_fingerprint: Option<String>,
        pub last_traffic_features: Option<TrafficFeatures>,
        pub last_seen_ms: u64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct DirectProbeResult {
        pub target: String,
        pub host: String,
        pub port: u16,
        pub use_tls: bool,
        pub success: bool,
        pub error: Option<String>,
        #[serde(default)]
        pub resolved_ips: Vec<String>,
        pub remote_addr: Option<String>,
        pub dns_ms: f64,
        pub tcp_connect_ms: f64,
        pub tls_handshake_ms: Option<f64>,
        pub tls_version: Option<String>,
        pub cipher_suite: Option<String>,
        pub alpn: Option<String>,
        pub peer_cert_count: usize,
        pub http_status: Option<String>,
        pub server_header: Option<String>,
        pub connection_header: Option<String>,
        pub first_request_ms: f64,
        pub reuse_succeeded: bool,
        pub reused_request_ms: Option<f64>,
        pub total_ms: f64,
        pub cpu_percent_snapshot: f64,
        pub memory_mb_snapshot: f64,
        pub feature_summary: String,
        pub timestamp_ms: u64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct SizeBuckets {
        pub tiny_lt_100: u64,
        pub small_100_512: u64,
        pub medium_512_1400: u64,
        pub large_gt_1400: u64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct CaptureStatus {
        pub enabled: bool,
        pub packet_count: usize,
        pub total_captured: u64,
        pub max_packets: usize,
        #[serde(default)]
        pub flow_count: usize,
        pub c2s_packets: u64,
        pub s2c_packets: u64,
        pub avg_packet_bytes: f64,
        pub size_buckets: SizeBuckets,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct CapturedPacket {
        pub seq: u64,
        #[serde(default)]
        pub conn_id: u64,
        pub timestamp_ms: u64,
        #[serde(default)]
        pub iat_ms: f64,
        pub host: String,
        pub src: String,
        pub dst: String,
        pub direction: String,
        pub outbound: String,
        pub bypassed: bool,
        pub protocol: String,
        pub length: usize,
        pub captured_len: usize,
        pub info: String,
        pub hex_dump: String,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct FlowRecord {
        pub conn_id: u64,
        pub host: String,
        pub outbound: String,
        pub bypassed: bool,
        pub started_ms: u64,
        pub packet_count: u64,
        pub c2s_bytes: u64,
        pub s2c_bytes: u64,
        #[serde(default)]
        pub first_n_sizes: Vec<i64>,
        pub fingerprint: String,
        pub avg_iat_ms: f64,
        pub max_iat_ms: f64,
        pub size_buckets: SizeBuckets,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
        pub sample_fingerprint: Option<String>,
        pub size_buckets: SizeBuckets,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct SiteCompare {
        pub host: String,
        pub has_both: bool,
        pub direct: ModeStats,
        pub proxy: ModeStats,
        pub delta_avg_connect_ms: f64,
        pub delta_p95_connect_ms: f64,
        pub delta_avg_ttfb_ms: f64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct AiSummary {
        pub mode: String,
        pub resources: ResourceSnapshot,
        pub bypass: DirectBypassConfig,
        #[serde(default)]
        pub capture: CaptureStatus,
        pub totals: TotalsSummary,
        pub sites: Vec<SiteMetrics>,
        pub recent_probes: Vec<DirectProbeResult>,
    }

    #[derive(Debug, Serialize)]
    struct BypassPayload {
        enabled: bool,
        domains: Vec<String>,
    }

    #[derive(Debug, Serialize)]
    struct CapturePayload {
        enabled: bool,
    }

    #[derive(Debug, Serialize)]
    struct ProbePayload {
        target: String,
    }

    fn format_bytes(b: u64) -> String {
        if b >= 1024 * 1024 * 1024 {
            format!("{:.2} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if b >= 1024 * 1024 {
            format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
        } else if b >= 1024 {
            format!("{:.1} KB", b as f64 / 1024.0)
        } else {
            format!("{} B", b)
        }
    }

    fn format_dur(ms: f64) -> String {
        if ms >= 60_000.0 {
            format!("{:.1} min", ms / 60_000.0)
        } else if ms >= 1000.0 {
            format!("{:.2} s", ms / 1000.0)
        } else {
            format!("{:.0} ms", ms)
        }
    }

    const STYLE: &str = r#"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0b1120;
            color: #e2e8f0;
            font-size: 13px;
            line-height: 1.5;
        }
        .shell { display: flex; min-height: 100vh; }
        .sidebar {
            width: 205px;
            flex-shrink: 0;
            background: #070c18;
            border-right: 1px solid #1e293b;
            padding: 16px 12px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            position: sticky;
            top: 0;
            height: 100vh;
        }
        .brand {
            font-size: 15px;
            font-weight: 700;
            color: #f8fafc;
            padding: 4px 8px 12px;
            border-bottom: 1px solid #1e293b;
            margin-bottom: 6px;
        }
        .brand-sub { font-size: 11px; color: #64748b; font-weight: 500; margin-top: 2px; }
        .nav-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 9px 10px;
            border-radius: 8px;
            color: #94a3b8;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            border: 1px solid transparent;
            background: transparent;
            text-align: left;
            width: 100%;
        }
        .nav-item:hover { background: #111827; color: #e2e8f0; }
        .nav-item.active {
            background: #172554;
            color: #93c5fd;
            border-color: #1d4ed8;
        }
        .nav-pill {
            font-size: 10px;
            padding: 1px 6px;
            border-radius: 999px;
            background: #1e293b;
            color: #cbd5e1;
        }
        .sidebar-foot {
            margin-top: auto;
            padding-top: 12px;
            border-top: 1px solid #1e293b;
            font-size: 11px;
            color: #64748b;
        }
        .main { flex: 1; padding: 16px 20px; min-width: 0; overflow-x: hidden; }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid #1e293b;
            flex-wrap: wrap;
        }
        .title { font-size: 18px; font-weight: 700; color: #f8fafc; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .badge {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 999px;
            font-weight: 600;
        }
        .badge-ok { background: #064e3b; color: #34d399; border: 1px solid #059669; }
        .badge-err { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
        .badge-warn { background: #78350f; color: #fcd34d; border: 1px solid #d97706; }
        .badge-info { background: #1e3a8a; color: #93c5fd; border: 1px solid #2563eb; }
        .badge-ghost { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
        .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .grid-kpi {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        .card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 14px;
            margin-bottom: 14px;
        }
        .kpi-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.04em; }
        .kpi-val { font-size: 22px; font-weight: 700; color: #f8fafc; margin-top: 4px; }
        .kpi-sub { font-size: 11px; color: #64748b; margin-top: 2px; }
        .card-title { font-size: 14px; font-weight: 600; color: #f1f5f9; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }
        input {
            background: #0f172a;
            border: 1px solid #334155;
            color: #f8fafc;
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 12px;
            outline: none;
        }
        input:focus { border-color: #38bdf8; }
        button {
            border: none;
            border-radius: 6px;
            padding: 7px 14px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.15s;
        }
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-primary { background: #2563eb; color: #fff; }
        .btn-success { background: #059669; color: #fff; }
        .btn-warn { background: #d97706; color: #fff; }
        .btn-danger { background: #dc2626; color: #fff; }
        .btn-ghost { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th {
            text-align: left;
            padding: 8px 10px;
            color: #94a3b8;
            font-weight: 600;
            border-bottom: 1px solid #1f2937;
            background: #0f172a;
        }
        td {
            padding: 8px 10px;
            border-bottom: 1px solid #1e293b;
            vertical-align: top;
        }
        tr:hover td { background: #172033; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
        .pre-box {
            background: #020617;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 10px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 11px;
            color: #cbd5e1;
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 240px;
            overflow-y: auto;
        }
        .split { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        @media (max-width: 960px) { .split { grid-template-columns: 1fr; } }
    "#;

    #[component]
    pub fn App() -> Element {
        let initial_api = std::env::var("XRAY_DEBUG_API").unwrap_or_else(|_| DEFAULT_API.to_string());
        let mut api_url = use_signal(|| initial_api);
        let mut current_tab = use_signal(|| Tab::Home);
        let mut summary = use_signal(AiSummary::default);
        let mut connected = use_signal(|| false);
        let mut last_err = use_signal(|| Option::<String>::None);

        let mut bypass_domains_input = use_signal(String::new);
        let mut probe_target = use_signal(|| "www.cloudflare.com".to_string());
        let mut probing = use_signal(|| false);
        let mut host_filter = use_signal(String::new);
        let mut ai_text_preview = use_signal(|| Option::<String>::None);

        let mut packets = use_signal(Vec::<CapturedPacket>::new);
        let mut flows = use_signal(Vec::<FlowRecord>::new);
        let mut compares = use_signal(Vec::<SiteCompare>::new);
        let mut selected_pkt = use_signal(|| Option::<CapturedPacket>::None);
        let mut pcap_msg = use_signal(|| Option::<String>::None);

        // Background 1-second polling loop
        use_future(move || async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap_or_default();
            loop {
                let base = api_url.read().trim_end_matches('/').to_string();
                let tab = *current_tab.read();
                match client.get(format!("{}/ai/summary", base)).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.json::<AiSummary>().await {
                        Ok(data) => {
                            let should_fetch_pkts =
                                data.capture.enabled || data.capture.packet_count > 0;
                            summary.set(data);
                            connected.set(true);
                            last_err.set(None);

                            if tab == Tab::Compare {
                                if let Ok(cr) = client.get(format!("{}/ai/compare", base)).send().await
                                    && let Ok(list) = cr.json::<Vec<SiteCompare>>().await
                                {
                                    compares.set(list);
                                }
                            } else if tab == Tab::Flows {
                                if let Ok(fr) =
                                    client.get(format!("{}/ai/flows?limit=80", base)).send().await
                                    && let Ok(list) = fr.json::<Vec<FlowRecord>>().await
                                {
                                    flows.set(list);
                                }
                                if should_fetch_pkts {
                                    if let Ok(pr) = client
                                        .get(format!("{}/ai/packets?limit=80", base))
                                        .send()
                                        .await
                                        && let Ok(list) = pr.json::<Vec<CapturedPacket>>().await
                                    {
                                        packets.set(list);
                                    }
                                } else if !packets.read().is_empty() {
                                    packets.set(Vec::new());
                                }
                            }
                        }
                        Err(e) => {
                            connected.set(false);
                            last_err.set(Some(format!("JSON 解析失败: {}", e)));
                        }
                    },
                    Ok(resp) => {
                        connected.set(false);
                        last_err.set(Some(format!("HTTP {}", resp.status())));
                    }
                    Err(e) => {
                        connected.set(false);
                        last_err.set(Some(format!("未连接到 xray-rs debug 服务 ({})", e)));
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let data = summary.read().clone();
        let tab = *current_tab.read();
        let is_connected = *connected.read();
        let bypass_on = data.bypass.enabled;
        let cap_on = data.capture.enabled;

        let filter_str = host_filter.read().to_ascii_lowercase();
        let filtered_sites: Vec<SiteMetrics> = data
            .sites
            .iter()
            .filter(|s| filter_str.is_empty() || s.host.to_ascii_lowercase().contains(&filter_str))
            .cloned()
            .collect();
        let pkt_list = packets.read().clone();
        let flow_list = flows.read().clone();
        let compare_list = compares.read().clone();
        let both_cnt = compare_list.iter().filter(|c| c.has_both).count();

        let on_toggle_bypass = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            let target_enabled = !summary.read().bypass.enabled;
            let domains: Vec<String> = bypass_domains_input
                .read()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("{}/ai/bypass", base))
                    .json(&BypassPayload {
                        enabled: target_enabled,
                        domains,
                    })
                    .send()
                    .await;
            });
        };

        let on_apply_domains = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            let current_enabled = summary.read().bypass.enabled;
            let domains: Vec<String> = bypass_domains_input
                .read()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("{}/ai/bypass", base))
                    .json(&BypassPayload {
                        enabled: current_enabled,
                        domains,
                    })
                    .send()
                    .await;
            });
        };

        let on_run_probe = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            let target = probe_target.read().trim().to_string();
            if target.is_empty() {
                return;
            }
            probing.set(true);
            spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(15))
                    .build()
                    .unwrap_or_default();
                let _ = client
                    .post(format!("{}/ai/probe", base))
                    .json(&ProbePayload { target })
                    .send()
                    .await;
                probing.set(false);
            });
        };

        let on_reset = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            selected_pkt.set(None);
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client.post(format!("{}/ai/reset", base)).send().await;
            });
        };

        let on_toggle_capture = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            let target_on = !summary.read().capture.enabled;
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("{}/ai/capture", base))
                    .json(&CapturePayload { enabled: target_on })
                    .send()
                    .await;
            });
        };

        let on_clear_capture = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            selected_pkt.set(None);
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(format!("{}/ai/capture/clear", base))
                    .send()
                    .await;
            });
        };

        let on_export_pcap = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            spawn(async move {
                let client = reqwest::Client::new();
                match client.get(format!("{}/ai/capture.pcap", base)).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                        Ok(bytes) => {
                            let path = std::env::current_dir()
                                .unwrap_or_default()
                                .join("xray_capture.pcap");
                            match std::fs::write(&path, &bytes) {
                                Ok(_) => pcap_msg.set(Some(format!(
                                    "已导出 {} 字节到 {} (可直接用 Wireshark 打开)",
                                    bytes.len(),
                                    path.display()
                                ))),
                                Err(e) => pcap_msg.set(Some(format!("写入文件失败: {}", e))),
                            }
                        }
                        Err(e) => pcap_msg.set(Some(format!("读取失败: {}", e))),
                    },
                    Ok(r) => pcap_msg.set(Some(format!("导出失败 HTTP {}", r.status()))),
                    Err(e) => pcap_msg.set(Some(format!("请求失败: {}", e))),
                }
            });
        };

        let fetch_ai_text = move |endpoint: &'static str| {
            let base = api_url.read().trim_end_matches('/').to_string();
            spawn(async move {
                let client = reqwest::Client::new();
                if let Ok(resp) = client.get(format!("{}{}", base, endpoint)).send().await
                    && let Ok(txt) = resp.text().await
                {
                    ai_text_preview.set(Some(txt));
                }
            });
        };

        rsx! {
            style { "{STYLE}" }
            div { class: "shell",
                // Left Vertical Sidebar
                aside { class: "sidebar",
                    div { class: "brand",
                        "xray-rs Debug"
                        div { class: "brand-sub", "抓包分析 · 统计 · AI" }
                    }
                    button {
                        class: if tab == Tab::Home { "nav-item active" } else { "nav-item" },
                        onclick: move |_| current_tab.set(Tab::Home),
                        span { "主页总览" }
                        span { class: "nav-pill", "{data.totals.total_sites}" }
                    }
                    button {
                        class: if tab == Tab::Compare { "nav-item active" } else { "nav-item" },
                        onclick: move |_| current_tab.set(Tab::Compare),
                        span { "直连 vs 代理对比" }
                        span { class: "nav-pill", "{both_cnt}" }
                    }
                    button {
                        class: if tab == Tab::Flows { "nav-item active" } else { "nav-item" },
                        onclick: move |_| current_tab.set(Tab::Flows),
                        span { "流指纹与抓包" }
                        span { class: "nav-pill", "{data.capture.flow_count}" }
                    }
                    button {
                        class: if tab == Tab::Latency { "nav-item active" } else { "nav-item" },
                        onclick: move |_| current_tab.set(Tab::Latency),
                        span { "延迟 / TTFB 分布" }
                        span { class: "nav-pill", "P95" }
                    }
                    button {
                        class: if tab == Tab::Ai { "nav-item active" } else { "nav-item" },
                        onclick: move |_| current_tab.set(Tab::Ai),
                        span { "AI 极简接口" }
                        span { class: "nav-pill", "API" }
                    }
                    div { class: "sidebar-foot",
                        div { "PID: {data.resources.pid}" }
                        div { "CPU {data.resources.cpu_percent:.1}% · {data.resources.memory_rss_mb:.1} MB" }
                    }
                }

                // Main Content
                main { class: "main",
                    div { class: "header",
                        div { class: "title",
                            span { "{tab.title()}" }
                            span { class: "badge badge-info", "Dioxus · Debug Only" }
                            if is_connected {
                                span { class: "badge badge-ok", "已连接 PID {data.resources.pid}" }
                            } else {
                                span { class: "badge badge-err", "未连接" }
                            }
                            if bypass_on {
                                span { class: "badge badge-warn", "直连内核模式已开启 (不代理)" }
                            }
                        }
                        div { class: "row",
                            button {
                                class: if bypass_on { "btn-warn" } else { "btn-success" },
                                onclick: on_toggle_bypass,
                                if bypass_on { "关闭直连内核" } else { "开启直连内核" }
                            }
                            button {
                                class: if cap_on { "btn-danger" } else { "btn-ghost" },
                                onclick: on_toggle_capture,
                                if cap_on { "停止抓包 ({data.capture.packet_count})" } else { "开启抓包" }
                            }
                            input {
                                value: "{api_url}",
                                oninput: move |e| api_url.set(e.value()),
                                placeholder: "http://127.0.0.1:19876",
                                style: "width: 190px;"
                            }
                            button { class: "btn-ghost", onclick: on_reset, "清空统计" }
                        }
                    }

                    if let Some(err) = last_err.read().as_ref() {
                        div { class: "card", style: "border-color: #7f1d1d; background: #1c1014;",
                            span { style: "color: #fca5a5;", "{err}" }
                        }
                    }

                    // ==================== TAB 1: HOME ====================
                    if tab == Tab::Home {
                        div { class: "grid-kpi",
                            div { class: "card", style: "margin-bottom:0;",
                                div { class: "kpi-label", "CPU 占用" }
                                div { class: "kpi-val", "{data.resources.cpu_percent:.2}%" }
                                div { class: "kpi-sub", "{data.resources.cpu_cores} 核心 · 运行 {data.resources.uptime_secs}s" }
                            }
                            div { class: "card", style: "margin-bottom:0;",
                                div { class: "kpi-label", "内存占用 (RSS)" }
                                div { class: "kpi-val", "{data.resources.memory_rss_mb:.2} MB" }
                                div { class: "kpi-sub", "私有 {data.resources.memory_private_mb:.1} MB · 峰值 {data.resources.memory_peak_mb:.1} MB" }
                            }
                            div { class: "card", style: "margin-bottom:0;",
                                div { class: "kpi-label", "新建连接 / 活跃" }
                                div { class: "kpi-val", "{data.totals.total_established} / {data.totals.total_active}" }
                                div { class: "kpi-sub", "网站数 {data.totals.total_sites} · 失败 {data.totals.total_failed}" }
                            }
                            div { class: "card", style: "margin-bottom:0;",
                                div { class: "kpi-label", "连接复用 (Reuse)" }
                                div { class: "kpi-val", "{data.totals.total_reused} ({data.totals.overall_reuse_rate_pct:.1}%)" }
                                div { class: "kpi-sub", "直连 {data.totals.total_bypassed} · 代理 {data.totals.total_proxied}" }
                            }
                            div { class: "card", style: "margin-bottom:0;",
                                div { class: "kpi-label", "平均建连耗时" }
                                div { class: "kpi-val", "{data.totals.avg_connect_ms:.2} ms" }
                                div { class: "kpi-sub", "↑ {format_bytes(data.totals.total_uplink_bytes)} · ↓ {format_bytes(data.totals.total_downlink_bytes)}" }
                            }
                        }

                        div { class: "split",
                            div { class: "card",
                                div { class: "card-title",
                                    span { "直接过内核不代理 (实时流量特征观察)" }
                                    if bypass_on {
                                        span { class: "badge badge-warn", "DIRECT BYPASS ON" }
                                    } else {
                                        span { class: "badge badge-ghost", "正常代理路由" }
                                    }
                                }
                                p { style: "color:#94a3b8; margin-bottom:10px; font-size:12px;",
                                    "点击按钮后跳过代理直接经由 OS 内核 TCP 直连，抓取正常流量特征与前 N 包指纹，供 A/B 对比。"
                                }
                                div { class: "row", style: "margin-bottom: 10px;",
                                    button {
                                        class: if bypass_on { "btn-warn" } else { "btn-success" },
                                        onclick: on_toggle_bypass,
                                        if bypass_on { "关闭直连内核 (恢复代理)" } else { "开启直连内核 (不代理)" }
                                    }
                                    input {
                                        value: "{bypass_domains_input}",
                                        oninput: move |e| bypass_domains_input.set(e.value()),
                                        placeholder: "可选域名白名单，逗号分隔 (留空=全部直连)",
                                        style: "flex:1; min-width:180px;"
                                    }
                                    button { class: "btn-ghost", onclick: on_apply_domains, "应用域名" }
                                }
                                div { class: "mono", style: "color:#64748b;",
                                    if data.bypass.domains.is_empty() {
                                        "当前作用域: 全部流量"
                                    } else {
                                        "当前仅直连域名: {data.bypass.domains.join(\", \")}"
                                    }
                                }
                            }

                            div { class: "card",
                                div { class: "card-title",
                                    span { "一键直连内核探测 (正常流量特征 + 复用测试)" }
                                    span { class: "badge badge-info", "DNS / TCP / TLS / Keep-Alive" }
                                }
                                div { class: "row", style: "margin-bottom:10px;",
                                    input {
                                        value: "{probe_target}",
                                        oninput: move |e| probe_target.set(e.value()),
                                        placeholder: "例如 www.cloudflare.com",
                                        style: "flex:1;"
                                    }
                                    button {
                                        class: "btn-primary",
                                        disabled: *probing.read(),
                                        onclick: on_run_probe,
                                        if *probing.read() { "探测中..." } else { "直连内核探测" }
                                    }
                                }
                                if let Some(latest) = data.recent_probes.first() {
                                    div { class: "pre-box",
                                        "目标: {latest.target} -> {latest.remote_addr.as_deref().unwrap_or(\"-\")}\n"
                                        "DNS: {latest.dns_ms:.2}ms | TCP: {latest.tcp_connect_ms:.2}ms | TLS: {latest.tls_handshake_ms.unwrap_or(0.0):.2}ms ({latest.tls_version.as_deref().unwrap_or(\"plain\")})\n"
                                        "HTTP: {latest.http_status.as_deref().unwrap_or(\"-\")} | 首包: {latest.first_request_ms:.2}ms | 复用: "
                                        if latest.reuse_succeeded { "OK ({latest.reused_request_ms.unwrap_or(0.0):.2}ms)" } else { "NO" }
                                    }
                                }
                            }
                        }

                        div { class: "card",
                            div { class: "card-title",
                                span { "各网站连接数 / 复用数 / 耗时 / 流量特征 ({filtered_sites.len()})" }
                                input {
                                    value: "{host_filter}",
                                    oninput: move |e| host_filter.set(e.value()),
                                    placeholder: "按域名过滤...",
                                    style: "width: 220px;"
                                }
                            }
                            if filtered_sites.is_empty() {
                                div { style: "color:#64748b; padding: 12px 0;", "暂无网站连接记录。" }
                            } else {
                                div { style: "overflow-x:auto;",
                                    table {
                                        thead {
                                            tr {
                                                th { "网站 (Host)" }
                                                th { "新建 / 复用" }
                                                th { "活跃" }
                                                th { "建连 avg / p95" }
                                                th { "首包 TTFB" }
                                                th { "流量 (↑ / ↓)" }
                                                th { "出站 / 直连" }
                                                th { "前 N 包指纹 / 流量特征" }
                                            }
                                        }
                                        tbody {
                                            for site in filtered_sites.clone() {
                                                tr { key: "{site.host}",
                                                    td { class: "mono", style: "color:#f8fafc; font-weight:600;", "{site.host}" }
                                                    td { class: "mono", "{site.established} / {site.reused} ({site.reuse_rate_pct:.0}%)" }
                                                    td { "{site.active}" }
                                                    td { class: "mono", "{site.avg_connect_ms:.1} / {site.p95_connect_ms:.1} ms" }
                                                    td { class: "mono", "{site.avg_ttfb_ms:.1} ms" }
                                                    td { class: "mono", "↑ {format_bytes(site.uplink_bytes)} / ↓ {format_bytes(site.downlink_bytes)}" }
                                                    td { class: "mono", "{site.last_outbound} (直:{site.bypassed_count})" }
                                                    td { class: "mono", style: "color:#93c5fd; max-width:320px; word-break:break-all;",
                                                        if let Some(fp) = &site.last_fingerprint {
                                                            div { style: "color:#fcd34d; font-size:10px;", "FP: {fp}" }
                                                        }
                                                        if let Some(feat) = &site.last_traffic_features {
                                                            "{feat.summary}"
                                                        } else {
                                                            "{site.last_protocol}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ==================== TAB 2: COMPARE ====================
                    if tab == Tab::Compare {
                        div { class: "card",
                            div { class: "card-title",
                                span { "直连正常流量 vs 代理流量 同站自动 A/B 对比 ({compare_list.len()})" }
                            }
                            if compare_list.is_empty() {
                                div { style: "color:#64748b; padding:12px 0;", "暂无对比数据。先在代理模式访问网站，再开启直连内核访问同一网站即可对比。" }
                            } else {
                                div { style: "overflow-x:auto;",
                                    table {
                                        thead {
                                            tr {
                                                th { "网站 (Host)" }
                                                th { "直连 (avg/p95 · TTFB · 复用)" }
                                                th { "代理 (avg/p95 · TTFB · 复用)" }
                                                th { "差值 (代理 - 直连)" }
                                                th { "前 N 包指纹对比" }
                                            }
                                        }
                                        tbody {
                                            for c in compare_list {
                                                tr { key: "{c.host}",
                                                    td { class: "mono", style: "color:#f8fafc; font-weight:600;",
                                                        "{c.host}"
                                                        if c.has_both {
                                                            span { class: "badge badge-ok", style: "margin-left:6px;", "可对比" }
                                                        }
                                                    }
                                                    td { class: "mono",
                                                        "新:{c.direct.established} 复:{c.direct.reused} ({c.direct.reuse_rate_pct:.0}%)"
                                                        div { "avg {c.direct.avg_connect_ms:.1} / p95 {c.direct.p95_connect_ms:.1} ms" }
                                                        div { "TTFB {c.direct.avg_ttfb_ms:.1} ms · {format_dur(c.direct.avg_duration_ms)}" }
                                                    }
                                                    td { class: "mono",
                                                        "新:{c.proxy.established} 复:{c.proxy.reused} ({c.proxy.reuse_rate_pct:.0}%)"
                                                        div { "avg {c.proxy.avg_connect_ms:.1} / p95 {c.proxy.p95_connect_ms:.1} ms" }
                                                        div { "TTFB {c.proxy.avg_ttfb_ms:.1} ms · {format_dur(c.proxy.avg_duration_ms)}" }
                                                    }
                                                    td { class: "mono",
                                                        div { "建连: {c.delta_avg_connect_ms:+.1} ms" }
                                                        div { "P95: {c.delta_p95_connect_ms:+.1} ms" }
                                                        div { "TTFB: {c.delta_avg_ttfb_ms:+.1} ms" }
                                                    }
                                                    td { class: "mono", style: "max-width:340px; word-break:break-all;",
                                                        div { style: "color:#fcd34d;", "直连: {c.direct.sample_fingerprint.as_deref().unwrap_or(\"-\")}" }
                                                        div { style: "color:#93c5fd;", "代理: {c.proxy.sample_fingerprint.as_deref().unwrap_or(\"-\")}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ==================== TAB 3: FLOWS & PACKETS ====================
                    if tab == Tab::Flows {
                        div { class: "card",
                            div { class: "card-title",
                                span { "连接流指纹列表 (conn_id · 前 N 包带符号长度序列 · 同流包间隔 IAT)" }
                            }
                            if flow_list.is_empty() {
                                div { style: "color:#64748b; padding:8px 0;", "暂无连接流记录。" }
                            } else {
                                div { style: "max-height:240px; overflow-y:auto; border:1px solid #1e293b; border-radius:6px;",
                                    table {
                                        thead {
                                            tr {
                                                th { "conn_id" }
                                                th { "网站" }
                                                th { "出站" }
                                                th { "包数" }
                                                th { "平均 / 最大 IAT" }
                                                th { "流量 (↑ / ↓)" }
                                                th { "前 N 包长度指纹 (+上行 / -下行)" }
                                            }
                                        }
                                        tbody {
                                            for fl in flow_list {
                                                tr { key: "{fl.conn_id}",
                                                    td { class: "mono", style: "color:#38bdf8;", "#{fl.conn_id}" }
                                                    td { class: "mono", "{fl.host}" }
                                                    td { class: "mono", style: if fl.bypassed { "color:#fcd34d;" } else { "color:#94a3b8;" }, "{fl.outbound}" }
                                                    td { class: "mono", "{fl.packet_count}" }
                                                    td { class: "mono", "{fl.avg_iat_ms:.1} / {fl.max_iat_ms:.1} ms" }
                                                    td { class: "mono", "↑ {format_bytes(fl.c2s_bytes)} / ↓ {format_bytes(fl.s2c_bytes)}" }
                                                    td { class: "mono", style: "color:#fcd34d; max-width:340px; word-break:break-all;", "{fl.fingerprint}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        div { class: "card",
                            div { class: "card-title",
                                div { class: "row",
                                    span { "Wireshark 风格逐包抓包 (conn_id · iat_ms · 导出 .pcap)" }
                                    if cap_on {
                                        span { class: "badge badge-ok", "CAPTURING ({data.capture.packet_count}/{data.capture.max_packets})" }
                                    } else {
                                        span { class: "badge badge-info", "已缓冲 {data.capture.packet_count} 包" }
                                    }
                                }
                                div { class: "row",
                                    button {
                                        class: if cap_on { "btn-danger" } else { "btn-success" },
                                        onclick: on_toggle_capture,
                                        if cap_on { "停止抓包" } else { "开启抓包" }
                                    }
                                    button { class: "btn-primary", onclick: on_export_pcap, "导出 .pcap" }
                                    button { class: "btn-ghost", onclick: on_clear_capture, "清空包" }
                                }
                            }
                            if let Some(msg) = pcap_msg.read().as_ref() {
                                div { class: "mono", style: "color:#34d399; margin-bottom:8px;", "{msg}" }
                            }
                            if pkt_list.is_empty() {
                                div { style: "color:#64748b; padding: 8px 0;", "点击「开启抓包」后将实时显示每个数据包，点击行可展开 Hex/ASCII。" }
                            } else {
                                div { style: "max-height:240px; overflow-y:auto; border:1px solid #1e293b; border-radius:6px;",
                                    table {
                                        thead {
                                            tr {
                                                th { "#" }
                                                th { "conn_id" }
                                                th { "IAT(ms)" }
                                                th { "方向" }
                                                th { "网站" }
                                                th { "协议" }
                                                th { "长度" }
                                                th { "Info" }
                                            }
                                        }
                                        tbody {
                                            for pkt in pkt_list {
                                                {
                                                    let pkt_click = pkt.clone();
                                                    let is_c2s = pkt.direction == "C->S";
                                                    rsx! {
                                                        tr {
                                                            key: "{pkt.seq}",
                                                            style: "cursor:pointer;",
                                                            onclick: move |_| selected_pkt.set(Some(pkt_click.clone())),
                                                            td { class: "mono", "{pkt.seq}" }
                                                            td { class: "mono", style: "color:#38bdf8;", "#{pkt.conn_id}" }
                                                            td { class: "mono", "+{pkt.iat_ms:.1}" }
                                                            td { class: "mono", style: if is_c2s { "color:#38bdf8;" } else { "color:#a78bfa;" }, "{pkt.direction}" }
                                                            td { class: "mono", "{pkt.host}" }
                                                            td { class: "mono", "{pkt.protocol}" }
                                                            td { class: "mono", "{pkt.length} B" }
                                                            td { class: "mono", "{pkt.info}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(sel) = selected_pkt.read().as_ref() {
                                div { style: "margin-top:10px;",
                                    div { class: "mono", style: "color:#94a3b8; margin-bottom:4px;",
                                        "Packet #{sel.seq} | conn_id=#{sel.conn_id} | iat=+{sel.iat_ms:.2}ms | {sel.src} -> {sel.dst} ({sel.direction})"
                                    }
                                    div { class: "pre-box", "{sel.hex_dump}" }
                                }
                            }
                        }
                    }

                    // ==================== TAB 4: LATENCY & TTFB ====================
                    if tab == Tab::Latency {
                        div { class: "card",
                            div { class: "card-title",
                                span { "各网站延迟分位 (P50 / P95 / Max)、首包 TTFB 与平均存活时长" }
                                input {
                                    value: "{host_filter}",
                                    oninput: move |e| host_filter.set(e.value()),
                                    placeholder: "按域名过滤...",
                                    style: "width: 200px;"
                                }
                            }
                            if filtered_sites.is_empty() {
                                div { style: "color:#64748b; padding:12px 0;", "暂无延迟分布数据。" }
                            } else {
                                div { style: "overflow-x:auto;",
                                    table {
                                        thead {
                                            tr {
                                                th { "网站 (Host)" }
                                                th { "新建 / 复用" }
                                                th { "建连 Avg" }
                                                th { "建连 P50" }
                                                th { "建连 P95" }
                                                th { "建连 Max" }
                                                th { "TTFB Avg" }
                                                th { "TTFB P95" }
                                                th { "平均存活" }
                                            }
                                        }
                                        tbody {
                                            for s in filtered_sites {
                                                tr { key: "{s.host}",
                                                    td { class: "mono", style: "color:#f8fafc; font-weight:600;", "{s.host}" }
                                                    td { class: "mono", "{s.established} / {s.reused} ({s.reuse_rate_pct:.1}%)" }
                                                    td { class: "mono", "{s.avg_connect_ms:.1} ms" }
                                                    td { class: "mono", "{s.p50_connect_ms:.1} ms" }
                                                    td { class: "mono", style: "color:#fcd34d; font-weight:600;", "{s.p95_connect_ms:.1} ms" }
                                                    td { class: "mono", "{s.max_connect_ms:.1} ms" }
                                                    td { class: "mono", style: "color:#38bdf8;", "{s.avg_ttfb_ms:.1} ms" }
                                                    td { class: "mono", style: "color:#38bdf8;", "{s.p95_ttfb_ms:.1} ms" }
                                                    td { class: "mono", "{format_dur(s.avg_duration_ms)}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ==================== TAB 5: AI API ====================
                    if tab == Tab::Ai {
                        div { class: "card",
                            div { class: "card-title",
                                span { "极简 AI 接口 (给 AI Agent 直接调用)" }
                                div { class: "row",
                                    button { class: "btn-primary", onclick: move |_| fetch_ai_text("/ai/summary?format=text"), "预览 Summary" }
                                    button { class: "btn-ghost", onclick: move |_| fetch_ai_text("/ai/compare?format=text"), "预览 A/B 对比" }
                                    button { class: "btn-ghost", onclick: move |_| fetch_ai_text("/ai/flows?format=text&limit=30"), "预览流指纹" }
                                    button { class: "btn-ghost", onclick: move |_| fetch_ai_text("/ai/packets?format=text&limit=30"), "预览抓包" }
                                }
                            }
                            div { class: "mono", style: "color:#94a3b8; margin-bottom:10px;",
                                "GET {api_url}/ai/summary?format=text | /ai/compare?format=text | /ai/flows?format=text | /ai/packets?format=text | /ai/capture.pcap"
                            }
                            if let Some(txt) = ai_text_preview.read().as_ref() {
                                div { class: "pre-box", "{txt}" }
                            } else {
                                div { class: "pre-box", "点击上方按钮预览对应 AI 文本接口的实时输出..." }
                            }
                        }
                    }
                }
            }
        }
    }
}

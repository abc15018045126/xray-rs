//! Debug-only Dioxus Desktop Dashboard for `xray-rs`.
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
        pub min_connect_ms: f64,
        pub max_connect_ms: f64,
        pub last_connect_ms: f64,
        pub uplink_bytes: u64,
        pub downlink_bytes: u64,
        pub last_outbound: String,
        pub last_protocol: String,
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
        pub c2s_packets: u64,
        pub s2c_packets: u64,
        pub avg_packet_bytes: f64,
        pub size_buckets: SizeBuckets,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct CapturedPacket {
        pub seq: u64,
        pub timestamp_ms: u64,
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
    struct CapturePayload {
        enabled: bool,
    }

    #[derive(Debug, Serialize)]
    struct BypassPayload {
        enabled: bool,
        domains: Vec<String>,
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

    const STYLE: &str = r#"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0b1120;
            color: #e2e8f0;
            padding: 16px 20px;
            font-size: 13px;
            line-height: 1.5;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid #1e293b;
        }
        .title { font-size: 18px; font-weight: 700; color: #f8fafc; display: flex; align-items: center; gap: 10px; }
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
        .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .grid-kpi {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
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
        .card-title { font-size: 14px; font-weight: 600; color: #f1f5f9; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
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
            max-height: 220px;
            overflow-y: auto;
        }
        .split { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        @media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
    "#;

    #[component]
    pub fn App() -> Element {
        let initial_api = std::env::var("XRAY_DEBUG_API").unwrap_or_else(|_| DEFAULT_API.to_string());
        let mut api_url = use_signal(|| initial_api);
        let mut summary = use_signal(AiSummary::default);
        let mut connected = use_signal(|| false);
        let mut last_err = use_signal(|| Option::<String>::None);

        let mut bypass_domains_input = use_signal(String::new);
        let mut probe_target = use_signal(|| "www.cloudflare.com".to_string());
        let mut probing = use_signal(|| false);
        let mut host_filter = use_signal(String::new);
        let mut ai_text_preview = use_signal(|| Option::<String>::None);
        let mut packets = use_signal(Vec::<CapturedPacket>::new);
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
                let url = format!("{}/ai/summary", base);
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<AiSummary>().await {
                            Ok(data) => {
                                let should_fetch_pkts = data.capture.enabled || data.capture.packet_count > 0;
                                summary.set(data);
                                connected.set(true);
                                last_err.set(None);

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
                            Err(e) => {
                                connected.set(false);
                                last_err.set(Some(format!("JSON 解析失败: {}", e)));
                            }
                        }
                    }
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
        let is_connected = *connected.read();
        let bypass_on = data.bypass.enabled;

        let filter_str = host_filter.read().to_ascii_lowercase();
        let filtered_sites: Vec<SiteMetrics> = data
            .sites
            .iter()
            .filter(|s| filter_str.is_empty() || s.host.to_ascii_lowercase().contains(&filter_str))
            .cloned()
            .collect();

        // Action: Toggle Direct Kernel Bypass (no proxy)
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

        // Action: Apply bypass domain list without flipping toggle
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

        // Action: Run Direct Kernel Probe
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

        // Action: Reset Metrics
        let on_reset = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            spawn(async move {
                let client = reqwest::Client::new();
                let _ = client.post(format!("{}/ai/reset", base)).send().await;
            });
        };

        // Action: Fetch AI compact text preview
        let on_fetch_ai_text = move |_| {
            let base = api_url.read().trim_end_matches('/').to_string();
            spawn(async move {
                let client = reqwest::Client::new();
                if let Ok(resp) = client
                    .get(format!("{}/ai/summary?format=text", base))
                    .send()
                    .await
                    && let Ok(txt) = resp.text().await
                {
                    ai_text_preview.set(Some(txt));
                }
            });
        };

        // Action: Toggle Wireshark-style Packet Capture
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

        // Action: Clear Captured Packets
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

        // Action: Export standard Wireshark .pcap file
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

        let cap_on = data.capture.enabled;
        let pkt_list = packets.read().clone();

        rsx! {
            style { "{STYLE}" }

            // Header
            div { class: "header",
                div { class: "title",
                    span { "xray-rs Debug Panel" }
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
                    input {
                        value: "{api_url}",
                        oninput: move |e| api_url.set(e.value()),
                        placeholder: "http://127.0.0.1:19876",
                        style: "width: 210px;"
                    }
                    button { class: "btn-ghost", onclick: on_reset, "清空统计" }
                }
            }

            if let Some(err) = last_err.read().as_ref() {
                div { class: "card", style: "border-color: #7f1d1d; background: #1c1014;",
                    span { style: "color: #fca5a5;", "{err} — 请先以 debug 模式运行 xray-rs (cargo run)" }
                }
            }

            // KPI Cards: CPU, Memory, Connections, Reuse, Latency
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

            // Split Row: Direct Kernel Bypass & Direct Probe
            div { class: "split",
                // Direct Kernel Bypass Control
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
                        "点击按钮后，xray-rs 内核分发器将跳过代理出站，直接经由操作系统内核 TCP 直连目标，同时抓取正常流量特征 (TLS 版本 / SNI / ALPN / ClientHello 长度 / HTTP 头)。"
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
                            style: "flex:1; min-width:200px;"
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

                // Direct Kernel Probe
                div { class: "card",
                    div { class: "card-title",
                        span { "一键直连内核探测 (正常流量特征 + 复用测试)" }
                        span { class: "badge badge-info", "DNS / TCP / TLS / Keep-Alive" }
                    }
                    div { class: "row", style: "margin-bottom:10px;",
                        input {
                            value: "{probe_target}",
                            oninput: move |e| probe_target.set(e.value()),
                            placeholder: "例如 www.cloudflare.com 或 https://github.com",
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
                            "状态: "
                            if latest.success { "SUCCESS" } else { "FAILED" }
                            " | 总耗时: {latest.total_ms:.2} ms\n"
                            "DNS: {latest.dns_ms:.2} ms | TCP: {latest.tcp_connect_ms:.2} ms | TLS: {latest.tls_handshake_ms.unwrap_or(0.0):.2} ms\n"
                            "TLS特征: {latest.tls_version.as_deref().unwrap_or(\"plain\")} | Cipher: {latest.cipher_suite.as_deref().unwrap_or(\"-\")} | ALPN: {latest.alpn.as_deref().unwrap_or(\"-\")} | 证书链: {latest.peer_cert_count}\n"
                            "HTTP: {latest.http_status.as_deref().unwrap_or(\"-\")} | Server: {latest.server_header.as_deref().unwrap_or(\"-\")} | 首包: {latest.first_request_ms:.2} ms\n"
                            "连接复用测试: "
                            if latest.reuse_succeeded {
                                "复用成功 ({latest.reused_request_ms.unwrap_or(0.0):.2} ms)"
                            } else {
                                "未复用 / 服务端关闭"
                            }
                            "\n资源快照: CPU {latest.cpu_percent_snapshot:.2}% | MEM {latest.memory_mb_snapshot:.2} MB"
                            if let Some(err) = &latest.error {
                                "\n错误: {err}"
                            }
                        }
                    } else {
                        div { style: "color:#64748b; font-size:12px;", "点击「直连内核探测」立即绕过代理测试任意网站的正常流量特征与连接复用耗时。" }
                    }
                }
            }

            // Per-Website Connection & Reuse Table
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
                    div { style: "color:#64748b; padding: 12px 0;", "暂无网站连接记录。浏览网页或点击上方「直连内核探测」后将实时显示。" }
                } else {
                    div { style: "overflow-x:auto;",
                        table {
                            thead {
                                tr {
                                    th { "网站 (Host)" }
                                    th { "新建连接" }
                                    th { "复用 (复用率)" }
                                    th { "活跃" }
                                    th { "建连耗时 (ms)" }
                                    th { "流量 (↑ / ↓)" }
                                    th { "出站 / 直连次数" }
                                    th { "流量特征 (正常/嗅探)" }
                                }
                            }
                            tbody {
                                for site in filtered_sites {
                                    tr { key: "{site.host}",
                                        td { class: "mono", style: "color:#f8fafc; font-weight:600;", "{site.host}" }
                                        td { "{site.established}" }
                                        td {
                                            span { style: "color:#34d399; font-weight:600;", "{site.reused}" }
                                            span { style: "color:#64748b;", " ({site.reuse_rate_pct:.1}%)" }
                                        }
                                        td { "{site.active}" }
                                        td { class: "mono",
                                            "{site.avg_connect_ms:.1} ms"
                                            div { style: "color:#64748b; font-size:10px;",
                                                "min {site.min_connect_ms:.1} / max {site.max_connect_ms:.1}"
                                            }
                                        }
                                        td { class: "mono",
                                            "↑ {format_bytes(site.uplink_bytes)} / ↓ {format_bytes(site.downlink_bytes)}"
                                        }
                                        td { class: "mono",
                                            "{site.last_outbound}"
                                            div { style: "color:#64748b; font-size:10px;",
                                                "直连:{site.bypassed_count} 代理:{site.proxied_count}"
                                            }
                                        }
                                        td { class: "mono", style: "color:#93c5fd; max-width:340px; word-break:break-all;",
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

            // Wireshark-style Packet Capture Panel
            div { class: "card",
                div { class: "card-title",
                    div { class: "row",
                        span { "Wireshark 风格实时抓包 (无需 Npcap · 支持导出 .pcap)" }
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
                        button { class: "btn-primary", onclick: on_export_pcap, "导出 .pcap (Wireshark)" }
                        button { class: "btn-ghost", onclick: on_clear_capture, "清空包" }
                    }
                }
                div { class: "mono", style: "color:#94a3b8; margin-bottom:8px;",
                    "方向: C->S {data.capture.c2s_packets} | S->C {data.capture.s2c_packets} | 平均包长: {data.capture.avg_packet_bytes:.1} B | 包长分布: <100B({data.capture.size_buckets.tiny_lt_100}) · 100-512B({data.capture.size_buckets.small_100_512}) · 512-1400B({data.capture.size_buckets.medium_512_1400}) · >1400B({data.capture.size_buckets.large_gt_1400})"
                }
                if let Some(msg) = pcap_msg.read().as_ref() {
                    div { class: "mono", style: "color:#34d399; margin-bottom:8px;", "{msg}" }
                }
                if pkt_list.is_empty() {
                    div { style: "color:#64748b; padding: 8px 0;", "点击「开启抓包」后，经过 xray-rs 内核的每个数据包（直连或代理）都会按 Wireshark 格式实时显示，点击任意行可查看 Hex/ASCII 十六进制负载。" }
                } else {
                    div { style: "max-height:240px; overflow-y:auto; border:1px solid #1e293b; border-radius:6px;",
                        table {
                            thead {
                                tr {
                                    th { "#" }
                                    th { "方向" }
                                    th { "网站" }
                                    th { "协议" }
                                    th { "长度" }
                                    th { "出站" }
                                    th { "Info (L7 解析)" }
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
                                                td { class: "mono", style: if is_c2s { "color:#38bdf8;" } else { "color:#a78bfa;" }, "{pkt.direction}" }
                                                td { class: "mono", "{pkt.host}" }
                                                td { class: "mono", "{pkt.protocol}" }
                                                td { class: "mono", "{pkt.length} B" }
                                                td { class: "mono", style: if pkt.bypassed { "color:#fcd34d;" } else { "color:#94a3b8;" }, "{pkt.outbound}" }
                                                td { class: "mono", style: "color:#e2e8f0;", "{pkt.info}" }
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
                            "Packet #{sel.seq} | {sel.src} -> {sel.dst} ({sel.direction}) | {sel.protocol} | {sel.length} B (展示前 {sel.captured_len.min(256)} B)"
                        }
                        div { class: "pre-box", "{sel.hex_dump}" }
                    }
                }
            }

            // AI Interface Card
            div { class: "card",
                div { class: "card-title",
                    span { "极简 AI 接口 (给 AI Agent 直接调用)" }
                    button { class: "btn-ghost", onclick: on_fetch_ai_text, "预览 AI 极简文本输出" }
                }
                div { class: "mono", style: "color:#94a3b8; margin-bottom:8px;",
                    "GET {api_url}/ai/summary?format=text  |  GET {api_url}/ai/capture?on=1  |  GET {api_url}/ai/packets?format=text  |  GET {api_url}/ai/capture.pcap"
                }
                if let Some(txt) = ai_text_preview.read().as_ref() {
                    div { class: "pre-box", "{txt}" }
                }
            }
        }
    }
}

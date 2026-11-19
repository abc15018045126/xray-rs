//! Debug-only lightweight HTTP server exposing ultra-simple AI endpoints
//! and backend data for the Dioxus debug panel.
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::debug_panel::{
    CaptureStatus, DirectBypassConfig, DirectProbeResult, ResourceReport, ResourceSnapshot,
    SiteMetrics, TotalsSummary, capture, metrics, probe, resources,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummary {
    pub mode: &'static str,
    pub resources: ResourceSnapshot,
    pub bypass: DirectBypassConfig,
    pub capture: CaptureStatus,
    pub totals: TotalsSummary,
    pub sites: Vec<SiteMetrics>,
    pub recent_probes: Vec<DirectProbeResult>,
}

#[derive(Debug, Deserialize)]
struct BypassRequest {
    enabled: bool,
    #[serde(default)]
    domains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CaptureToggleRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ProbeRequest {
    target: String,
}

/// Spawn the debug HTTP + AI API server on `bind_addr` (default `127.0.0.1:19876`).
pub fn spawn_server(bind_addr: String) -> tokio::task::JoinHandle<()> {
    // Background 1-second resource sampler so CPU% is always warm and accurate
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let _ = resources().sample();
        }
    });

    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!("Debug panel HTTP server failed to bind {}: {}", bind_addr, e);
                return;
            }
        };
        info!(
            "[DEBUG PANEL] Listening on http://{} (AI API: http://{}/ai/summary)",
            bind_addr, bind_addr
        );

        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    tokio::spawn(async move {
                        let _ = handle_conn(stream).await;
                    });
                }
                Err(e) => {
                    warn!("[DEBUG PANEL] Accept error: {}", e);
                }
            }
        }
    })
}

async fn handle_conn(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16384];
    let mut read_len = 0usize;

    // Read HTTP request header (+ small JSON body)
    loop {
        let n = stream.read(&mut buf[read_len..]).await?;
        if n == 0 {
            break;
        }
        read_len += n;
        if let Some(hdr_end) = find_header_end(&buf[..read_len]) {
            let content_len = parse_content_length(&buf[..hdr_end]);
            if read_len >= hdr_end + content_len || read_len >= buf.len() {
                break;
            }
        }
        if read_len >= buf.len() {
            break;
        }
    }

    if read_len == 0 {
        return Ok(());
    }

    let hdr_end = find_header_end(&buf[..read_len]).unwrap_or(read_len);
    let header_str = String::from_utf8_lossy(&buf[..hdr_end]);
    let body_bytes = &buf[hdr_end..read_len];

    let first_line = header_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let full_target = parts.next().unwrap_or("/");

    if method == "OPTIONS" {
        write_response(&mut stream, "204 No Content", "text/plain", b"").await?;
        return Ok(());
    }

    let (path, query_str) = match full_target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_target, ""),
    };
    let query = parse_query(query_str);

    let (status, content_type, resp_body) = route(method, path, &query, body_bytes).await;
    write_response(&mut stream, status, content_type, &resp_body).await
}

async fn route(
    method: &str,
    path: &str,
    query: &HashMap<String, String>,
    body: &[u8],
) -> (&'static str, &'static str, Vec<u8>) {
    match (method, path) {
        ("GET", "/ai") | ("GET", "/ai/help") => {
            let help = serde_json::json!({
                "name": "xray-rs Debug & AI Telemetry API (debug_assertions only)",
                "endpoints": {
                    "GET /ai/summary": "Full snapshot (CPU, Mem, bypass state, totals, per-site connections/reuse/ms, recent probes). Add ?format=text for compact plain text.",
                    "GET /ai/sites": "Per-website connection stats (established, reused, active, reuse_rate_pct, connect_ms, traffic_features). Optional ?host=<substr>.",
                    "GET /ai/resources": "Process CPU %, Memory RSS/Private/Peak MB, and 60-sample history.",
                    "GET /ai/events": "Recent connection events (last 50).",
                    "GET /ai/probes": "Recent direct kernel probe results (last 20).",
                    "GET /ai/bypass": "Get direct kernel bypass state. Shortcut: ?on=1 or ?off=1&domains=a.com,b.com.",
                    "POST /ai/bypass": "Toggle direct kernel bypass (no proxy). JSON: {\"enabled\": true, \"domains\": []} or query ?on=1 / ?off=1.",
                    "GET /ai/probe?target=example.com": "Run direct kernel probe (no proxy) to inspect normal traffic features & connection reuse.",
                    "POST /ai/probe": "Run direct kernel probe. JSON: {\"target\": \"example.com\"} or query ?target=example.com.",
                    "GET/POST /ai/capture": "Wireshark-style packet capture status/toggle (?on=1 / ?off=1 or JSON {\"enabled\": true}).",
                    "GET /ai/packets": "List captured packets with conn_id, iat_ms, L7 info & Hex/ASCII dump (?host=xxx&limit=50&format=text).",
                    "GET /ai/flows": "Per-connection flows with First-N signed packet-size fingerprints ([+517, -1420, ...]) & IAT ms (?host=xxx&limit=50&format=text).",
                    "GET /ai/compare": "Direct vs Proxy A/B comparison per host (connect p50/p95, TTFB, reuse, First-N fingerprint). Optional ?host=xxx&format=text.",
                    "GET /ai/capture.pcap": "Download standard Wireshark .pcap file (?host=xxx).",
                    "POST /ai/capture/clear": "Clear captured packet buffer.",
                    "POST /ai/reset": "Reset all site metrics, events, and probe history."
                }
            });
            json_ok(&help)
        }

        ("GET", "/ai/summary") => {
            let summary = build_summary();
            if query.get("format").map(|s| s.as_str()) == Some("text") {
                let text = format_summary_text(&summary);
                ("200 OK", "text/plain; charset=utf-8", text.into_bytes())
            } else {
                json_ok(&summary)
            }
        }

        ("GET", "/ai/sites") => {
            let host_filter = query.get("host").map(|s| s.as_str());
            let sites = metrics().sites(host_filter);
            json_ok(&sites)
        }

        ("GET", "/ai/resources") => {
            let report: ResourceReport = resources().report();
            json_ok(&report)
        }

        ("GET", "/ai/events") => {
            let events = metrics().recent_events();
            json_ok(&events)
        }

        ("GET", "/ai/probes") => {
            let probes = metrics().recent_probes();
            json_ok(&probes)
        }

        ("GET", "/ai/bypass") => {
            // Allow convenient GET shortcuts like /ai/bypass?on=1 or /ai/bypass?off=1 for simple AI clients
            if query.contains_key("on") || query.contains_key("off") {
                let enabled = query.get("on").map(|v| v != "0" && v != "false").unwrap_or(false)
                    && !query.contains_key("off");
                let domains = query.get("domains").map(|d| {
                    d.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                });
                let cfg = metrics().set_bypass(enabled, domains);
                return json_ok(&cfg);
            }
            let cfg = metrics().bypass_config();
            json_ok(&cfg)
        }

        ("POST", "/ai/bypass") => {
            if let Ok(req) = serde_json::from_slice::<BypassRequest>(body) {
                let cfg = metrics().set_bypass(req.enabled, req.domains);
                json_ok(&cfg)
            } else if query.contains_key("on") || query.contains_key("off") {
                let enabled = query.get("on").map(|v| v != "0" && v != "false").unwrap_or(false)
                    && !query.contains_key("off");
                let domains = query.get("domains").map(|d| {
                    d.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                });
                let cfg = metrics().set_bypass(enabled, domains);
                json_ok(&cfg)
            } else {
                // Toggle if empty body
                let cur = metrics().bypass_config();
                let cfg = metrics().set_bypass(!cur.enabled, None);
                json_ok(&cfg)
            }
        }

        ("GET", "/ai/probe") | ("POST", "/ai/probe") => {
            let target = if let Some(t) = query.get("target").cloned() {
                t
            } else if let Ok(req) = serde_json::from_slice::<ProbeRequest>(body) {
                req.target
            } else {
                return (
                    "400 Bad Request",
                    "application/json",
                    br#"{"error":"missing target; use ?target=example.com or JSON {\"target\":\"example.com\"}"}"#.to_vec(),
                );
            };
            let result = probe::run_direct_probe(&target).await;
            metrics().record_probe(result.clone());
            json_ok(&result)
        }

        ("GET", "/ai/capture") => {
            if query.contains_key("on") || query.contains_key("off") {
                let enabled = query.get("on").map(|v| v != "0" && v != "false").unwrap_or(false)
                    && !query.contains_key("off");
                return json_ok(&capture().set_enabled(enabled));
            }
            json_ok(&capture().status())
        }

        ("POST", "/ai/capture") => {
            if let Ok(req) = serde_json::from_slice::<CaptureToggleRequest>(body) {
                json_ok(&capture().set_enabled(req.enabled))
            } else if query.contains_key("on") || query.contains_key("off") {
                let enabled = query.get("on").map(|v| v != "0" && v != "false").unwrap_or(false)
                    && !query.contains_key("off");
                json_ok(&capture().set_enabled(enabled))
            } else {
                let cur = capture().is_enabled();
                json_ok(&capture().set_enabled(!cur))
            }
        }

        ("GET", "/ai/packets") => {
            let host_filter = query.get("host").map(|s| s.as_str());
            let limit = query
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(100)
                .min(500);
            let pkts = capture().packets(host_filter, limit);
            if query.get("format").map(|s| s.as_str()) == Some("text") {
                let mut out = String::new();
                for p in &pkts {
                    out.push_str(&format!(
                        "#{} conn={} +iat={:.1}ms [{}] {} {} {}B out={} | {}\n",
                        p.seq,
                        p.conn_id,
                        p.iat_ms,
                        p.direction.as_str(),
                        p.host,
                        p.protocol,
                        p.length,
                        p.outbound,
                        p.info
                    ));
                }
                ("200 OK", "text/plain; charset=utf-8", out.into_bytes())
            } else {
                json_ok(&pkts)
            }
        }

        ("GET", "/ai/flows") => {
            let host_filter = query.get("host").map(|s| s.as_str());
            let limit = query
                .get("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(80)
                .min(200);
            let flows = capture().flows(host_filter, limit);
            if query.get("format").map(|s| s.as_str()) == Some("text") {
                let mut out = String::new();
                for f in &flows {
                    out.push_str(&format!(
                        "conn={} host={} out={} bypass={} pkts={} avg_iat={:.1}ms firstN={}\n",
                        f.conn_id,
                        f.host,
                        f.outbound,
                        f.bypassed,
                        f.packet_count,
                        f.avg_iat_ms,
                        f.fingerprint
                    ));
                }
                ("200 OK", "text/plain; charset=utf-8", out.into_bytes())
            } else {
                json_ok(&flows)
            }
        }

        ("GET", "/ai/compare") => {
            let host_filter = query.get("host").map(|s| s.as_str());
            let list = metrics().compare(host_filter);
            if query.get("format").map(|s| s.as_str()) == Some("text") {
                let mut out = String::new();
                for c in &list {
                    out.push_str(&format!(
                        "HOST: {} (both={})\n  DIRECT: new={} reuse={}({:.1}%) avg={:.1}ms p50={:.1}ms p95={:.1}ms ttfb={:.1}ms dur={:.0}ms fp={}\n  PROXY:  new={} reuse={}({:.1}%) avg={:.1}ms p50={:.1}ms p95={:.1}ms ttfb={:.1}ms dur={:.0}ms fp={}\n  DELTA(proxy-direct): avg={:+.1}ms p95={:+.1}ms ttfb={:+.1}ms\n",
                        c.host,
                        c.has_both,
                        c.direct.established,
                        c.direct.reused,
                        c.direct.reuse_rate_pct,
                        c.direct.avg_connect_ms,
                        c.direct.p50_connect_ms,
                        c.direct.p95_connect_ms,
                        c.direct.avg_ttfb_ms,
                        c.direct.avg_duration_ms,
                        c.direct.sample_fingerprint.as_deref().unwrap_or("-"),
                        c.proxy.established,
                        c.proxy.reused,
                        c.proxy.reuse_rate_pct,
                        c.proxy.avg_connect_ms,
                        c.proxy.p50_connect_ms,
                        c.proxy.p95_connect_ms,
                        c.proxy.avg_ttfb_ms,
                        c.proxy.avg_duration_ms,
                        c.proxy.sample_fingerprint.as_deref().unwrap_or("-"),
                        c.delta_avg_connect_ms,
                        c.delta_p95_connect_ms,
                        c.delta_avg_ttfb_ms,
                    ));
                }
                if out.is_empty() {
                    out.push_str("No site comparison data yet.\n");
                }
                ("200 OK", "text/plain; charset=utf-8", out.into_bytes())
            } else {
                json_ok(&list)
            }
        }

        ("GET", "/ai/capture.pcap") => {
            let host_filter = query.get("host").map(|s| s.as_str());
            let bytes = capture().export_pcap(host_filter);
            ("200 OK", "application/vnd.tcpdump.pcap", bytes)
        }

        ("POST", "/ai/capture/clear") | ("GET", "/ai/capture/clear") => {
            capture().clear();
            json_ok(&serde_json::json!({"ok": true, "message": "capture buffer cleared"}))
        }

        ("POST", "/ai/reset") | ("GET", "/ai/reset") => {
            metrics().reset();
            capture().clear();
            json_ok(&serde_json::json!({"ok": true, "message": "metrics reset"}))
        }

        ("GET", "/") => {
            let html = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>xray-rs Debug Panel</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;line-height:1.6}
a{color:#38bdf8}code{background:#1e293b;padding:2px 6px;border-radius:4px}</style></head>
<body>
<h1>xray-rs Debug Panel (debug_assertions only)</h1>
<p>Dioxus 桌面面板启动命令: <code>cargo run --manifest-path debug_panel/dioxus_app/Cargo.toml</code></p>
<h2>极简 AI 接口</h2>
<ul>
<li><a href="/ai">/ai</a> - 接口说明</li>
<li><a href="/ai/summary">/ai/summary</a> (或 <a href="/ai/summary?format=text">/ai/summary?format=text</a>) - 一键汇总</li>
<li><a href="/ai/sites">/ai/sites</a> - 各网站连接数 / 复用数 / ms / 流量特征</li>
<li><a href="/ai/resources">/ai/resources</a> - CPU% &amp; 内存 MB</li>
<li><a href="/ai/bypass">/ai/bypass</a> - 直连内核不代理开关 (<code>?on=1</code> / <code>?off=1</code>)</li>
<li><a href="/ai/probe?target=www.cloudflare.com">/ai/probe?target=www.cloudflare.com</a> - 直连探测正常流量特征</li>
</ul>
</body></html>"#;
            ("200 OK", "text/html; charset=utf-8", html.as_bytes().to_vec())
        }

        _ => (
            "404 Not Found",
            "application/json",
            br#"{"error":"not found","hint":"GET /ai for available endpoints"}"#.to_vec(),
        ),
    }
}

fn build_summary() -> AiSummary {
    let res = resources().sample();
    let bypass = metrics().bypass_config();
    let cap = capture().status();
    let totals = metrics().totals();
    let sites = metrics().sites(None);
    let recent_probes = metrics().recent_probes();

    AiSummary {
        mode: "debug",
        resources: res,
        bypass,
        capture: cap,
        totals,
        sites,
        recent_probes,
    }
}

fn format_summary_text(s: &AiSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "XRAY-RS DEBUG SUMMARY | PID={} | CPU={:.2}% | MEM={:.2}MB (priv={:.2}MB peak={:.2}MB) | UP={}s\n",
        s.resources.pid,
        s.resources.cpu_percent,
        s.resources.memory_rss_mb,
        s.resources.memory_private_mb,
        s.resources.memory_peak_mb,
        s.resources.uptime_secs
    ));
    out.push_str(&format!(
        "DIRECT BYPASS (no-proxy): enabled={} domains={:?}\n",
        s.bypass.enabled, s.bypass.domains
    ));
    out.push_str(&format!(
        "PACKET CAPTURE (Wireshark): enabled={} buffered={} total={} C->S={} S->C={} avg_len={:.1}B buckets(<100:{},100-512:{},512-1400:{},>1400:{})\n",
        s.capture.enabled,
        s.capture.packet_count,
        s.capture.total_captured,
        s.capture.c2s_packets,
        s.capture.s2c_packets,
        s.capture.avg_packet_bytes,
        s.capture.size_buckets.tiny_lt_100,
        s.capture.size_buckets.small_100_512,
        s.capture.size_buckets.medium_512_1400,
        s.capture.size_buckets.large_gt_1400,
    ));
    out.push_str(&format!(
        "TOTALS: sites={} new={} reused={} ({:.1}%) active={} failed={} avg_ms={:.2}ms bypassed={} proxied={}\n",
        s.totals.total_sites,
        s.totals.total_established,
        s.totals.total_reused,
        s.totals.overall_reuse_rate_pct,
        s.totals.total_active,
        s.totals.total_failed,
        s.totals.avg_connect_ms,
        s.totals.total_bypassed,
        s.totals.total_proxied
    ));
    if !s.sites.is_empty() {
        out.push_str("SITES:\n");
        for site in s.sites.iter().take(20) {
            let feat = site
                .last_traffic_features
                .as_ref()
                .map(|f| f.summary.as_str())
                .unwrap_or("-");
            out.push_str(&format!(
                "  - {} | new={} reuse={} ({:.1}%) active={} avg={:.1}ms out={} bypass={} | {}\n",
                site.host,
                site.established,
                site.reused,
                site.reuse_rate_pct,
                site.active,
                site.avg_connect_ms,
                site.last_outbound,
                site.bypassed_count,
                feat
            ));
        }
    }
    if !s.recent_probes.is_empty() {
        out.push_str("RECENT DIRECT PROBES:\n");
        for p in s.recent_probes.iter().take(5) {
            out.push_str(&format!("  - {} | {}\n", p.target, p.feature_summary));
        }
    }
    out
}

fn json_ok<T: Serialize>(val: &T) -> (&'static str, &'static str, Vec<u8>) {
    let body = serde_json::to_vec_pretty(val).unwrap_or_else(|_| b"{}".to_vec());
    ("200 OK", "application/json; charset=utf-8", body)
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn parse_content_length(header_bytes: &[u8]) -> usize {
    let text = String::from_utf8_lossy(header_bytes);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            return n;
        }
    }
    0
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        } else {
            map.insert(percent_decode(pair), "1".into());
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3])
                && let Ok(val) = u8::from_str_radix(hex_str, 16)
            {
                out.push(val);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

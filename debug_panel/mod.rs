//! Debug-only telemetry, direct kernel bypass, traffic feature inspector,
//! and ultra-simple AI API for `xray-rs`.
//!
//! This entire module is gated behind `#[cfg(debug_assertions)]` in `src/lib.rs`,
//! so it has ZERO runtime or binary overhead in `--release` builds.

pub mod capture;
pub mod metrics;
pub mod probe;
pub mod resources;
pub mod server;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

pub use capture::{CaptureStatus, CapturedPacket, Direction, FlowRecord, PacketCaptureStore, SizeBuckets};
pub use metrics::{
    ConnectionEvent, ConnectionTrace, DebugMetricsStore, DirectBypassConfig, ModeStats,
    PageLoadRecord, SiteCompare, SiteMetrics, TotalsSummary, TraceStep, TrafficFeatures,
    inspect_initial_payload,
};
pub use probe::{DirectProbeResult, run_direct_probe};
pub use resources::{
    ResourceMonitor, ResourceReport, ResourceSnapshot, StageStats, ThreadCpuInfo, record_stage,
    stage_stats_snapshot,
};

pub const DEFAULT_DEBUG_ADDR: &str = "127.0.0.1:19876";

static METRICS: OnceLock<DebugMetricsStore> = OnceLock::new();
static RESOURCES: OnceLock<ResourceMonitor> = OnceLock::new();
static CAPTURE: OnceLock<PacketCaptureStore> = OnceLock::new();
static SERVER_STARTED: AtomicBool = AtomicBool::new(false);

pub fn metrics() -> &'static DebugMetricsStore {
    METRICS.get_or_init(DebugMetricsStore::new)
}

pub fn resources() -> &'static ResourceMonitor {
    RESOURCES.get_or_init(ResourceMonitor::new)
}

pub fn capture() -> &'static PacketCaptureStore {
    CAPTURE.get_or_init(PacketCaptureStore::new)
}

pub fn resources_snapshot() -> ResourceSnapshot {
    resources().latest()
}

/// Returns true if direct kernel bypass (no-proxy) mode is active for `host`.
pub fn should_bypass_direct(host: &str) -> bool {
    metrics().should_bypass(host)
}

/// Start the debug HTTP + AI API server once (idempotent).
/// Bind address can be overridden via `XRAY_DEBUG_ADDR` env var (default `127.0.0.1:19876`).
pub fn start_debug_server() -> Option<tokio::task::JoinHandle<()>> {
    if SERVER_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return None;
    }
    let addr = std::env::var("XRAY_DEBUG_ADDR").unwrap_or_else(|_| DEFAULT_DEBUG_ADDR.to_string());
    Some(server::spawn_server(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bypass_domain_matching() {
        let store = DebugMetricsStore::new();
        assert!(!store.should_bypass("example.com"));

        store.set_bypass(true, Some(vec!["cloudflare.com".into()]));
        assert!(store.should_bypass("cloudflare.com"));
        assert!(store.should_bypass("www.cloudflare.com"));
        assert!(!store.should_bypass("github.com"));

        // Empty domain list with enabled=true bypasses everything
        store.set_bypass(true, Some(vec![]));
        assert!(store.should_bypass("github.com"));

        store.set_bypass(false, None);
        assert!(!store.should_bypass("github.com"));
    }

    #[test]
    fn test_http_feature_inspection_and_metrics() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent\r\n\r\n";
        let feat = inspect_initial_payload(req);
        assert_eq!(feat.protocol, "http");
        assert_eq!(feat.http_method.as_deref(), Some("GET"));
        assert_eq!(feat.http_host.as_deref(), Some("example.com"));

        let store = DebugMetricsStore::new();
        store.record_connect_start("example.com", "proxy", false, false, 12.5, Some(feat));
        store.record_ttfb("example.com", false, 35.0);
        store.record_pool_reuse("example.com", "proxy");
        store.record_connect_end("example.com", false, 1024, 4096, 150.0, None);

        let sites = store.sites(Some("example"));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].established, 1);
        assert_eq!(sites[0].reused, 1);
        assert_eq!(sites[0].reuse_rate_pct, 50.0);
        assert_eq!(sites[0].p50_connect_ms, 12.5);
        assert_eq!(sites[0].avg_ttfb_ms, 35.0);
        assert_eq!(sites[0].avg_duration_ms, 150.0);
        assert_eq!(sites[0].active, 0);
        assert_eq!(sites[0].uplink_bytes, 1024);
        assert_eq!(sites[0].downlink_bytes, 4096);

        // Verify page load burst aggregation & CDN companion domain grouping
        store.record_connect_start("www.youtube.com", "proxy", false, false, 120.0, None);
        store.record_ttfb("www.youtube.com", false, 320.0);
        store.record_connect_start("i.ytimg.com", "proxy", false, false, 140.0, None);
        store.record_connect_end("i.ytimg.com", false, 512, 8192, 600.0, None);

        let loads = store.page_loads(Some("youtube"));
        assert_eq!(loads.len(), 1);
        assert_eq!(loads[0].site, "youtube.com");
        assert_eq!(loads[0].conn_count, 2);
        assert_eq!(loads[0].first_connect_ms, 120.0);
        assert_eq!(loads[0].first_byte_ms, 320.0);
        assert!(loads[0].load_time_ms >= 320.0);
        assert_eq!(loads[0].downlink_bytes, 8192);
        assert_eq!(loads[0].hosts.len(), 2);
    }

    #[test]
    fn test_resource_monitor_snapshot() {
        let mon = ResourceMonitor::new();
        let snap = mon.sample();
        assert!(snap.pid > 0);
        assert!(snap.cpu_cores >= 1);
        assert!(snap.memory_rss_mb >= 0.0);
    }

    #[test]
    fn test_packet_capture_and_pcap_export() {
        let cap = PacketCaptureStore::new();
        assert!(!cap.is_enabled());
        cap.set_enabled(true);

        let cid = cap.next_conn_id();
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        cap.record_chunk(
            cid,
            "example.com",
            "127.0.0.1:51234",
            "example.com:80",
            Direction::ClientToServer,
            "debug-direct-bypass",
            true,
            req,
        );
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        cap.record_chunk(
            cid,
            "example.com",
            "127.0.0.1:51234",
            "example.com:80",
            Direction::ServerToClient,
            "debug-direct-bypass",
            true,
            resp,
        );

        let pkts = cap.packets(Some("example"), 10);
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].conn_id, cid);
        assert_eq!(pkts[0].protocol, "HTTP");
        assert_eq!(pkts[1].protocol, "HTTP");

        let flow = cap.flow_snapshot(cid).expect("flow should exist");
        assert_eq!(flow.first_n_sizes, vec![req.len() as i64, -(resp.len() as i64)]);

        let pcap = cap.export_pcap(None);
        assert!(pcap.len() > 24 + 32);
        assert_eq!(&pcap[0..4], &0xa1b2c3d4u32.to_le_bytes());
    }

    #[test]
    fn test_connection_trace_steps() {
        let store = DebugMetricsStore::new();
        let tid = store.start_trace("www.google.com", "www.google.com:443", "tun");
        store.update_trace_meta(tid, Some("www.google.com"), Some("proxy"), Some("proxy"), Some(false));
        store.add_trace_step(tid, "1. 本机嗅探 (Sniff)", 0.0, 1.2, "proto=tls SNI=www.google.com");
        store.add_trace_step(tid, "3. 外层 TCP 建连 (RTT 1)", 1.5, 310.0, "server=cf:443");
        store.add_trace_step(tid, "4. 外层 TLS 握手 (RTT 2)", 311.5, 305.0, "SNI=worker.dev");
        store.add_trace_step(tid, "5. WS 升级握手 (RTT 3)", 616.5, 312.0, "wss://worker.dev/");
        store.add_trace_step(tid, "7. 首包穿透 -> 目标首响应 (TTFB)", 929.0, 420.0, "收到首包 1400B");
        store.finish_trace(tid, 1349.0, None);

        let list = store.traces(Some("google"), 10);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, "ok");
        assert_eq!(list[0].steps.len(), 5);
        assert_eq!(list[0].total_ms, 1349.0);
    }
}

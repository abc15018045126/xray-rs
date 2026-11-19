//! Debug-only direct kernel probe (bypasses proxy completely) to inspect
//! normal traffic characteristics (DNS, TCP, TLS, HTTP, Keep-Alive reuse).
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectProbeResult {
    pub target: String,
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resolved_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    pub dns_ms: f64,
    pub tcp_connect_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_handshake_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    pub peer_cert_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_header: Option<String>,
    pub first_request_ms: f64,
    pub reuse_succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_request_ms: Option<f64>,
    pub total_ms: f64,
    pub cpu_percent_snapshot: f64,
    pub memory_mb_snapshot: f64,
    pub feature_summary: String,
    pub timestamp_ms: u64,
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn parse_target(raw: &str) -> (String, u16, bool, String) {
    let s = raw.trim();
    let (explicit_tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (Some(true), r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (Some(false), r)
    } else {
        (None, s)
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = if let Some(idx) = authority.rfind(':') {
        let maybe_port = &authority[idx + 1..];
        if let Ok(p) = maybe_port.parse::<u16>() {
            (authority[..idx].trim_matches(['[', ']']).to_string(), Some(p))
        } else {
            (authority.trim_matches(['[', ']']).to_string(), None)
        }
    } else {
        (authority.trim_matches(['[', ']']).to_string(), None)
    };

    let use_tls = match (explicit_tls, port) {
        (Some(t), _) => t,
        (None, Some(80)) => false,
        _ => true,
    };
    let final_port = port.unwrap_or(if use_tls { 443 } else { 80 });
    let final_path = if path.is_empty() { "/" } else { path }.to_string();

    (host, final_port, use_tls, final_path)
}

/// Perform a direct kernel (non-proxied) probe against `target` to observe
/// normal traffic characteristics and HTTP Keep-Alive connection reuse.
pub async fn run_direct_probe(target: &str) -> DirectProbeResult {
    let total_start = Instant::now();
    let (host, port, use_tls, path) = parse_target(target);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut res = DirectProbeResult {
        target: target.to_string(),
        host: host.clone(),
        port,
        use_tls,
        success: false,
        error: None,
        resolved_ips: Vec::new(),
        remote_addr: None,
        dns_ms: 0.0,
        tcp_connect_ms: 0.0,
        tls_handshake_ms: None,
        tls_version: None,
        cipher_suite: None,
        alpn: None,
        peer_cert_count: 0,
        http_status: None,
        server_header: None,
        connection_header: None,
        first_request_ms: 0.0,
        reuse_succeeded: false,
        reused_request_ms: None,
        total_ms: 0.0,
        cpu_percent_snapshot: 0.0,
        memory_mb_snapshot: 0.0,
        feature_summary: String::new(),
        timestamp_ms: ts,
    };

    if host.is_empty() {
        res.error = Some("empty target host".into());
        res.feature_summary = "error: empty target host".into();
        return res;
    }

    // 1. Direct OS Kernel DNS Lookup
    let dns_start = Instant::now();
    let addrs = match timeout(PROBE_TIMEOUT, lookup_host((host.as_str(), port))).await {
        Ok(Ok(iter)) => iter.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            res.dns_ms = round2(dns_start.elapsed().as_secs_f64() * 1000.0);
            res.error = Some(format!("DNS lookup failed: {}", e));
            res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
            res.feature_summary = format!("DNS failed ({})", e);
            return res;
        }
        Err(_) => {
            res.dns_ms = round2(dns_start.elapsed().as_secs_f64() * 1000.0);
            res.error = Some("DNS lookup timeout".into());
            res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
            res.feature_summary = "DNS timeout".into();
            return res;
        }
    };
    res.dns_ms = round2(dns_start.elapsed().as_secs_f64() * 1000.0);
    res.resolved_ips = addrs.iter().map(|a| a.ip().to_string()).collect();

    let Some(first_addr) = addrs.first().copied() else {
        res.error = Some("DNS returned no addresses".into());
        res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
        res.feature_summary = "DNS returned 0 IPs".into();
        return res;
    };
    res.remote_addr = Some(first_addr.to_string());

    // 2. Direct OS Kernel TCP Connect (no proxy!)
    let tcp_start = Instant::now();
    let tcp_stream = match timeout(PROBE_TIMEOUT, TcpStream::connect(first_addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => {
            res.tcp_connect_ms = round2(tcp_start.elapsed().as_secs_f64() * 1000.0);
            res.error = Some(format!("Direct TCP connect failed: {}", e));
            res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
            res.feature_summary = format!("TCP connect failed ({})", e);
            return res;
        }
        Err(_) => {
            res.tcp_connect_ms = round2(tcp_start.elapsed().as_secs_f64() * 1000.0);
            res.error = Some("Direct TCP connect timeout".into());
            res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
            res.feature_summary = "TCP connect timeout".into();
            return res;
        }
    };
    res.tcp_connect_ms = round2(tcp_start.elapsed().as_secs_f64() * 1000.0);

    let req_bytes = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray-rs-debug-probe/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        path, host
    );

    // 3. TLS handshake (if HTTPS) + HTTP/1.1 Keep-Alive reuse test
    if use_tls {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = match ServerName::try_from(host.clone()) {
            Ok(sn) => sn,
            Err(e) => {
                res.error = Some(format!("Invalid SNI server name: {}", e));
                res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
                res.feature_summary = format!("Invalid SNI ({})", e);
                return res;
            }
        };

        let tls_start = Instant::now();
        let mut tls_stream = match timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp_stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                res.tls_handshake_ms = Some(round2(tls_start.elapsed().as_secs_f64() * 1000.0));
                res.error = Some(format!("TLS handshake failed: {}", e));
                res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
                res.feature_summary = format!("TLS handshake failed ({})", e);
                return res;
            }
            Err(_) => {
                res.tls_handshake_ms = Some(round2(tls_start.elapsed().as_secs_f64() * 1000.0));
                res.error = Some("TLS handshake timeout".into());
                res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);
                res.feature_summary = "TLS handshake timeout".into();
                return res;
            }
        };
        res.tls_handshake_ms = Some(round2(tls_start.elapsed().as_secs_f64() * 1000.0));

        // Inspect negotiated TLS features
        {
            let (_io, conn) = tls_stream.get_ref();
            res.tls_version = conn.protocol_version().map(|v| format!("{:?}", v));
            res.cipher_suite = conn
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()));
            res.alpn = conn
                .alpn_protocol()
                .map(|a| String::from_utf8_lossy(a).to_string());
            res.peer_cert_count = conn.peer_certificates().map(|c| c.len()).unwrap_or(0);
        }

        // First HTTP HEAD request
        let r1_start = Instant::now();
        if let Ok((status, server, conn_hdr)) = send_http_head(&mut tls_stream, req_bytes.as_bytes()).await {
            res.first_request_ms = round2(r1_start.elapsed().as_secs_f64() * 1000.0);
            res.http_status = Some(status);
            res.server_header = server;
            res.connection_header = conn_hdr.clone();

            let server_closed = conn_hdr
                .as_deref()
                .map(|v| v.to_ascii_lowercase().contains("close"))
                .unwrap_or(false);

            // Second HTTP HEAD request on the SAME connection to verify Keep-Alive reuse!
            if !server_closed {
                let r2_start = Instant::now();
                if send_http_head(&mut tls_stream, req_bytes.as_bytes()).await.is_ok() {
                    res.reuse_succeeded = true;
                    res.reused_request_ms = Some(round2(r2_start.elapsed().as_secs_f64() * 1000.0));
                }
            }
        }
        let _ = tls_stream.shutdown().await;
    } else {
        let mut tcp_stream = tcp_stream;
        let r1_start = Instant::now();
        if let Ok((status, server, conn_hdr)) = send_http_head(&mut tcp_stream, req_bytes.as_bytes()).await {
            res.first_request_ms = round2(r1_start.elapsed().as_secs_f64() * 1000.0);
            res.http_status = Some(status);
            res.server_header = server;
            res.connection_header = conn_hdr.clone();

            let server_closed = conn_hdr
                .as_deref()
                .map(|v| v.to_ascii_lowercase().contains("close"))
                .unwrap_or(false);
            if !server_closed {
                let r2_start = Instant::now();
                if send_http_head(&mut tcp_stream, req_bytes.as_bytes()).await.is_ok() {
                    res.reuse_succeeded = true;
                    res.reused_request_ms = Some(round2(r2_start.elapsed().as_secs_f64() * 1000.0));
                }
            }
        }
        let _ = tcp_stream.shutdown().await;
    }

    res.success = true;
    res.total_ms = round2(total_start.elapsed().as_secs_f64() * 1000.0);

    let snap = crate::debug_panel::resources_snapshot();
    res.cpu_percent_snapshot = snap.cpu_percent;
    res.memory_mb_snapshot = snap.memory_rss_mb;

    let reuse_part = if let Some(rms) = res.reused_request_ms {
        format!("reuse=OK({}ms)", rms)
    } else {
        "reuse=NO".into()
    };

    res.feature_summary = format!(
        "DIRECT ip={} dns={}ms tcp={}ms tls={}ms({}) cipher={} status={} 1st={}ms {}",
        res.remote_addr.as_deref().unwrap_or("-"),
        res.dns_ms,
        res.tcp_connect_ms,
        res.tls_handshake_ms.unwrap_or(0.0),
        res.tls_version.as_deref().unwrap_or("plain"),
        res.cipher_suite.as_deref().unwrap_or("-"),
        res.http_status.as_deref().unwrap_or("-"),
        res.first_request_ms,
        reuse_part
    );

    res
}

async fn send_http_head<S>(
    stream: &mut S,
    req: &[u8],
) -> std::io::Result<(String, Option<String>, Option<String>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    timeout(PROBE_TIMEOUT, stream.write_all(req))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))??;
    stream.flush().await?;

    let mut resp = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        let n = timeout(PROBE_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") || resp.len() >= 8192 {
            break;
        }
    }

    let text = String::from_utf8_lossy(&resp);
    let mut lines = text.lines();
    let status = lines.next().unwrap_or("").trim().to_string();
    if status.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty HTTP response",
        ));
    }
    let mut server = None;
    let mut conn_hdr = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if kl == "server" {
                server = Some(val);
            } else if kl == "connection" {
                conn_hdr = Some(val);
            }
        }
    }
    Ok((status, server, conn_hdr))
}

use base64::Engine;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};
use tokio_tungstenite::{accept_async, client_async};

pub use super::connection::{CombinedStream, PrefixedStream};
use super::connection::bridge_ws_stream;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

pub const PROTOCOL_NAME: &str = "websocket";

pub struct WebSocketStream;

impl WebSocketStream {
    pub async fn client_handshake(url: &str, host_header: Option<&str>, stream: BoxStream) -> Result<BoxStream> {
        Self::client_handshake_with_options(url, host_header, stream, 0, None).await
    }
    pub async fn client_handshake_with_options(
        url: &str,
        host_header: Option<&str>,
        stream: BoxStream,
        heartbeat_period: u32,
        early_data: Option<&[u8]>,
    ) -> Result<BoxStream> {
        Self::client_handshake_with_headers(url, host_header, None, stream, heartbeat_period, early_data).await
    }
    pub async fn client_handshake_with_headers(
        url: &str,
        host_header: Option<&str>,
        extra_headers: Option<&HashMap<String, String>>,
        stream: BoxStream,
        heartbeat_period: u32,
        early_data: Option<&[u8]>,
    ) -> Result<BoxStream> {
        let mut req = url
            .into_client_request().map_err(|e| Error::Protocol(format!("Invalid WebSocket URL '{}': {}", url, e)))?;
        if let Some(host) = host_header && let Ok(val) = host.parse()
        { req.headers_mut().insert(tokio_tungstenite::tungstenite::http::header::HOST, val); }
        if let Some(headers) = extra_headers {
            for (k, v) in headers {
                if !is_reserved_ws_header(k)
                    && let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v))
                { req.headers_mut().insert(name, val); }
            }
        }
        if let Some(ed) = early_data && !ed.is_empty()
        {
            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let host_val = req
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::HOST)
                .and_then(|v| v.to_str().ok()).unwrap_or("localhost");
            let ws_key = req
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_KEY)
                .and_then(|v| v.to_str().ok()).unwrap_or("dGhlIHNhbXBsZSBub25jZQ==");
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ed);
            let mut upgrade_req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {}\r\n",
                pq, host_val, ws_key, encoded
            );
            if let Some(headers) = extra_headers {
                for (k, v) in headers {
                    if !is_reserved_ws_header(k) && !k.contains(['\r', '\n']) && !v.contains(['\r', '\n']) {
                        upgrade_req.push_str(&format!("{}: {}\r\n", k, v));
                    }
                }
            }
            upgrade_req.push_str("\r\n");
            let mut stream = stream;
            stream.write_all(upgrade_req.as_bytes()).await.map_err(|e| Error::Protocol(format!("WebSocket early-data write failed: {}", e)))?;
            stream.flush().await.map_err(|e| Error::Protocol(format!("WebSocket early-data flush failed: {}", e)))?;
            let (resp_buf, hdr_end) = read_http_header(&mut stream, 16384, "WebSocket early-data").await?;
            let status_line = String::from_utf8_lossy(&resp_buf[..hdr_end]).lines().next().unwrap_or("").to_string();
            if !status_line.contains(" 101 ") && !status_line.ends_with(" 101") {
                return Err(Error::Protocol(format!("WebSocket early-data handshake rejected: {}", status_line)));
            }
            let raw_stream = with_prefix(resp_buf[hdr_end..].to_vec(), stream);
            let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
                raw_stream,
                tokio_tungstenite::tungstenite::protocol::Role::Client,
                None,
            )
            .await;
            return Ok(bridge_ws_stream(ws_stream, heartbeat_period));
        }
        let (ws_stream, _) = client_async(req, stream)
            .await.map_err(|e| Error::Protocol(format!("WebSocket client handshake failed: {}", e)))?;
        Ok(bridge_ws_stream(ws_stream, heartbeat_period))
    }
    pub async fn server_handshake(stream: BoxStream) -> Result<BoxStream> {
        let ws_stream = accept_async(stream)
            .await.map_err(|e| Error::Protocol(format!("WebSocket server accept failed: {}", e)))?;
        Ok(bridge_ws_stream(ws_stream, 0))
    }
    pub async fn server_handshake_with_config(
        mut stream: BoxStream,
        expected_path: Option<&str>,
        expected_host: Option<&str>,
    ) -> Result<BoxStream> {
        use sha1::{Digest, Sha1};
        let (req_buf, hdr_end) = read_http_header(&mut stream, 32768, "WebSocket server upgrade").await?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if !matches!(req.parse(&req_buf[..hdr_end]), Ok(httparse::Status::Complete(_))) {
            return Err(Error::Protocol("Invalid HTTP request in WebSocket server handshake".into()));
        }
        let raw_path = req.path.unwrap_or("/");
        let clean_path = raw_path.split('?').next().unwrap_or(raw_path);
        if let Some(exp_path) = expected_path && !exp_path.is_empty() && exp_path != "/"
        {
            let exp_clean = exp_path.split('?').next().unwrap_or(exp_path);
            if clean_path != exp_clean {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                let _ = stream.flush().await;
                return Err(Error::Protocol(format!("WebSocket path mismatch: got '{}', expected '{}'", clean_path, exp_clean)));
            }
        }
        let (mut ws_key, mut host_hdr, mut early_data_hdr) = (None, None, None);
        for h in req.headers.iter() {
            let val = || Some(String::from_utf8_lossy(h.value).trim().to_string());
            if h.name.eq_ignore_ascii_case("sec-websocket-key") {
                ws_key = val();
            } else if h.name.eq_ignore_ascii_case("host") {
                host_hdr = val();
            } else if h.name.eq_ignore_ascii_case("sec-websocket-protocol") {
                early_data_hdr = val();
            }
        }
        if let Some(exp_host) = expected_host && !exp_host.is_empty()
        {
            let got_host = host_hdr.as_deref().unwrap_or("");
            let got_bare = got_host.split(':').next().unwrap_or(got_host);
            let exp_bare = exp_host.split(':').next().unwrap_or(exp_host);
            if !got_bare.eq_ignore_ascii_case(exp_bare) {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                let _ = stream.flush().await;
                return Err(Error::Protocol(format!("WebSocket Host mismatch: got '{}', expected '{}'", got_host, exp_host)));
            }
        }
        let key = ws_key.ok_or_else(|| Error::Protocol("Missing Sec-WebSocket-Key in WebSocket upgrade request".into()))?;
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept_key = base64::engine::general_purpose::STANDARD.encode(sha1.finalize());
        let ed_decoded = early_data_hdr.as_deref().and_then(|ed_raw| {
            if ed_raw.is_empty() { return None; }
            let normalized: String = ed_raw
                .chars()
                .filter(|&c| c != '=')
                .map(|c| match c { '+' => '-', '/' => '_', _ => c })
                .collect();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&normalized)
                .ok()
                .filter(|b| !b.is_empty())
        });
        let resp = match (&early_data_hdr, &ed_decoded) {
            (Some(raw), Some(_)) if !raw.contains(['\r', '\n']) => format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
                accept_key, raw
            ),
            _ => format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept_key
            ),
        };
        stream.write_all(resp.as_bytes()).await.map_err(|e| Error::Protocol(format!("WebSocket 101 write failed: {}", e)))?;
        stream.flush().await.map_err(|e| Error::Protocol(format!("WebSocket 101 flush failed: {}", e)))?;
        let raw_stream = with_prefix(req_buf[hdr_end..].to_vec(), stream);
        let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
            raw_stream,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let bridged = bridge_ws_stream(ws_stream, 0);
        if let Some(ed_bytes) = ed_decoded { return Ok(with_prefix(ed_bytes, bridged)); }
        Ok(bridged)
    }
}

fn is_reserved_ws_header(k: &str) -> bool {
    k.eq_ignore_ascii_case("host")
        || k.eq_ignore_ascii_case("upgrade")
        || k.eq_ignore_ascii_case("connection")
        || k.eq_ignore_ascii_case("sec-websocket-key")
        || k.eq_ignore_ascii_case("sec-websocket-version") || k.eq_ignore_ascii_case("sec-websocket-protocol")
}

async fn read_http_header(stream: &mut BoxStream, max_len: usize, ctx: &str) -> Result<(Vec<u8>, usize)> {
    pingora_timeout::timeout(std::time::Duration::from_secs(8), async {
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await.map_err(|e| Error::Protocol(format!("{} read failed: {}", ctx, e)))?;
            if n == 0 { return Err(Error::Protocol(format!("{} EOF before header end", ctx))); }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") { return Ok((buf, pos + 4)); }
            if buf.len() > max_len { return Err(Error::Protocol(format!("{} header too large", ctx))); }
        }
    })
    .await
    .map_err(|_| Error::Protocol(format!("{} header read timeout", ctx)))?
}

fn with_prefix(prefix: Vec<u8>, inner: BoxStream) -> BoxStream {
    if prefix.is_empty() {
        inner
    } else {
        Box::pin(PrefixedStream { prefix, offset: 0, inner })
    }
}

// Module: transport\internet\websocket\ws.rs
// 1:1 Rust implementation corresponding to Go transport\internet\websocket\ws.go

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
    pub async fn client_handshake(
        url: &str,
        host_header: Option<&str>,
        stream: BoxStream,
    ) -> Result<BoxStream> {
        Self::client_handshake_with_options(url, host_header, stream, 0, None).await
    }

    pub async fn client_handshake_with_options(
        url: &str,
        host_header: Option<&str>,
        stream: BoxStream,
        heartbeat_period: u32,
        early_data: Option<&[u8]>,
    ) -> Result<BoxStream> {
        Self::client_handshake_with_headers(url, host_header, None, stream, heartbeat_period, early_data)
            .await
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
            .into_client_request()
            .map_err(|e| Error::Protocol(format!("Invalid WebSocket URL '{}': {}", url, e)))?;

        if let Some(host) = host_header
            && let Ok(val) = host.parse()
        {
            req.headers_mut()
                .insert(tokio_tungstenite::tungstenite::http::header::HOST, val);
        }

        if let Some(headers) = extra_headers {
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("host")
                    || k.eq_ignore_ascii_case("upgrade")
                    || k.eq_ignore_ascii_case("connection")
                    || k.eq_ignore_ascii_case("sec-websocket-key")
                    || k.eq_ignore_ascii_case("sec-websocket-version")
                    || k.eq_ignore_ascii_case("sec-websocket-protocol")
                {
                    continue;
                }
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    req.headers_mut().insert(name, val);
                }
            }
        }

        if let Some(ed) = early_data
            && !ed.is_empty()
        {
            // Official Xray-core / CF Worker servers accept Early Data in `Sec-WebSocket-Protocol`
            // and reply `101 Switching Protocols` WITHOUT echoing `Sec-WebSocket-Protocol`.
            // `tokio_tungstenite::client_async` strictly rejects that with
            // `SubProtocol error: Server sent no subprotocol`, so perform the RFC 6455
            // HTTP/1.1 Upgrade manually and wrap via `from_raw_socket`.
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let host_val = req
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let ws_key = req
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_KEY)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("dGhlIHNhbXBsZSBub25jZQ==");
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ed);

            let mut upgrade_req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {}\r\n",
                path_and_query, host_val, ws_key, encoded
            );
            if let Some(headers) = extra_headers {
                for (k, v) in headers {
                    if k.eq_ignore_ascii_case("host")
                        || k.eq_ignore_ascii_case("upgrade")
                        || k.eq_ignore_ascii_case("connection")
                        || k.eq_ignore_ascii_case("sec-websocket-key")
                        || k.eq_ignore_ascii_case("sec-websocket-version")
                        || k.eq_ignore_ascii_case("sec-websocket-protocol")
                    {
                        continue;
                    }
                    if !k.contains('\r')
                        && !k.contains('\n')
                        && !v.contains('\r')
                        && !v.contains('\n')
                    {
                        upgrade_req.push_str(&format!("{}: {}\r\n", k, v));
                    }
                }
            }
            upgrade_req.push_str("\r\n");

            let mut stream = stream;
            stream
                .write_all(upgrade_req.as_bytes())
                .await
                .map_err(|e| Error::Protocol(format!("WebSocket early-data write failed: {}", e)))?;
            stream
                .flush()
                .await
                .map_err(|e| Error::Protocol(format!("WebSocket early-data flush failed: {}", e)))?;

            let mut resp_buf = Vec::with_capacity(1024);
            let mut tmp = [0u8; 512];
            let hdr_end = loop {
                let n = stream.read(&mut tmp).await.map_err(|e| {
                    Error::Protocol(format!("WebSocket early-data read failed: {}", e))
                })?;
                if n == 0 {
                    return Err(Error::Protocol(
                        "WebSocket early-data handshake EOF before 101".into(),
                    ));
                }
                resp_buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if resp_buf.len() > 16384 {
                    return Err(Error::Protocol(
                        "WebSocket early-data response header too large".into(),
                    ));
                }
            };

            let status_line = String::from_utf8_lossy(&resp_buf[..hdr_end])
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            if !status_line.contains(" 101 ") && !status_line.ends_with(" 101") {
                return Err(Error::Protocol(format!(
                    "WebSocket early-data handshake rejected: {}",
                    status_line
                )));
            }

            let leftover = resp_buf[hdr_end..].to_vec();
            let raw_stream: BoxStream = if leftover.is_empty() {
                stream
            } else {
                Box::pin(PrefixedStream {
                    prefix: leftover,
                    offset: 0,
                    inner: stream,
                })
            };

            let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
                raw_stream,
                tokio_tungstenite::tungstenite::protocol::Role::Client,
                None,
            )
            .await;
            return Ok(bridge_ws_stream(ws_stream, heartbeat_period));
        }

        let (ws_stream, _) = client_async(req, stream)
            .await
            .map_err(|e| Error::Protocol(format!("WebSocket client handshake failed: {}", e)))?;

        Ok(bridge_ws_stream(ws_stream, heartbeat_period))
    }

    pub async fn server_handshake(stream: BoxStream) -> Result<BoxStream> {
        let ws_stream = accept_async(stream)
            .await
            .map_err(|e| Error::Protocol(format!("WebSocket server accept failed: {}", e)))?;

        Ok(bridge_ws_stream(ws_stream, 0))
    }
}

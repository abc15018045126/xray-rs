// Module: transport\internet\splithttp\hub.rs
// 1:1 Rust implementation corresponding to Go transport\internet\splithttp\hub.go

use super::config::SplitHttpConfig;
use super::connection::SplitConn;
use super::upload_queue::UploadQueue;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};

pub struct HttpSession {
    pub upload_queue: UploadQueue,
}

impl HttpSession {
    pub fn new(max_buffered: usize) -> Self {
        Self {
            upload_queue: UploadQueue::new(max_buffered),
        }
    }
}

/// Reusable XHTTP / SplitHTTP server-side session demultiplexer that operates on any
/// `BoxStream` (raw TCP, TLS, or Pingora L4 stream), aligned with `splithttp/hub.go`.
pub struct SplitHttpServer {
    config: SplitHttpConfig,
    sessions: Arc<Mutex<HashMap<String, Arc<HttpSession>>>>,
}

impl SplitHttpServer {
    pub fn new(config: SplitHttpConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &SplitHttpConfig {
        &self.config
    }

    /// Handles an incoming HTTP/1.1 connection on an XHTTP inbound:
    /// - `POST` (uplink packet): pushes body into the session's `UploadQueue`, replies `200 OK`,
    ///   and returns `Ok(None)`.
    /// - `GET` (downlink stream): writes streaming `200 OK` headers and returns `Ok(Some(SplitConn))`
    ///   ready to be handed to the protocol `InboundHandler` (e.g. VLESS).
    pub async fn accept_stream(
        &self,
        stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<Option<BoxStream>> {
        Self::handle_stream(stream, remote_addr, &self.config, &self.sessions).await
    }

    async fn handle_stream(
        mut stream: BoxStream,
        remote_addr: SocketAddr,
        config: &SplitHttpConfig,
        sessions: &Arc<Mutex<HashMap<String, Arc<HttpSession>>>>,
    ) -> Result<Option<BoxStream>> {
        let mut header_buf = [0u8; 4096];
        let mut n_read = 0;
        let header_end = loop {
            let n = stream.read(&mut header_buf[n_read..]).await?;
            if n == 0 {
                return Ok(None);
            }
            n_read += n;
            if let Some(pos) = header_buf[..n_read]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
            {
                break pos + 4;
            }
            if n_read >= header_buf.len() {
                let _ = stream
                    .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                    .await;
                return Ok(None);
            }
        };

        let header_str = String::from_utf8_lossy(&header_buf[..header_end]);
        let mut lines = header_str.lines();
        let request_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(None);
        }

        let method = parts[0];
        let req_uri = parts[1];

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        if !config.host.is_empty()
            && let Some(host_val) = headers.get("host")
        {
            let got_bare = host_val.split(':').next().unwrap_or(host_val);
            let exp_bare = config.host.split(':').next().unwrap_or(&config.host);
            if !got_bare.eq_ignore_ascii_case(exp_bare) {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
                return Ok(None);
            }
        }

        let norm_path = config.get_normalized_path();
        if !req_uri.starts_with(&norm_path) {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            return Ok(None);
        }

        let uri_parts: Vec<&str> = req_uri.splitn(2, '?').collect();
        let pure_path = uri_parts[0];
        let query_str = if uri_parts.len() > 1 {
            uri_parts[1]
        } else {
            ""
        };

        let mut query_map = HashMap::new();
        for pair in query_str.split('&').filter(|s| !s.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                query_map.insert(k.to_string(), v.to_string());
            }
        }

        let mut cookie_map = HashMap::new();
        if let Some(cookie_hdr) = headers.get("cookie") {
            for c in cookie_hdr.split(';').filter(|s| !s.is_empty()) {
                if let Some((k, v)) = c.split_once('=') {
                    cookie_map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }

        let (mut session_id, mut seq_str) = config.extract_meta_from_request(
            pure_path,
            &norm_path,
            &headers,
            &query_map,
            &cookie_map,
        );

        if session_id.is_empty()
            && let Some(sid) = headers.get("x-session-id")
        {
            session_id = sid.clone();
        }
        if seq_str.is_empty()
            && let Some(sq) = headers.get("x-seq-id")
        {
            seq_str = sq.clone();
        }

        if method == "POST" || !seq_str.is_empty() {
            let content_len: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            let mut body_bytes = Vec::with_capacity(content_len);
            let initial_body = &header_buf[header_end..n_read];
            body_bytes.extend_from_slice(initial_body);

            while body_bytes.len() < content_len {
                let to_read = (content_len - body_bytes.len()).min(4096);
                let mut chunk = vec![0u8; to_read];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..n]);
            }

            let seq = seq_str.parse::<u64>().unwrap_or(0);

            let session = {
                let mut map = sessions.lock().await;
                map.entry(session_id.clone())
                    .or_insert_with(|| {
                        Arc::new(HttpSession::new(
                            config.get_normalized_sc_max_buffered_posts(),
                        ))
                    })
                    .clone()
            };

            let _ = session.upload_queue.push(body_bytes, seq).await;

            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n";
            stream.write_all(resp.as_bytes()).await?;
            stream.flush().await?;
            return Ok(None);
        }

        if method == "GET" {
            let session = {
                let mut map = sessions.lock().await;
                map.entry(session_id.clone())
                    .or_insert_with(|| {
                        Arc::new(HttpSession::new(
                            config.get_normalized_sc_max_buffered_posts(),
                        ))
                    })
                    .clone()
            };

            let resp_headers = "HTTP/1.1 200 OK\r\n\
                Content-Type: application/octet-stream\r\n\
                X-Accel-Buffering: no\r\n\
                Cache-Control: no-store\r\n\r\n";
            stream.write_all(resp_headers.as_bytes()).await?;
            stream.flush().await?;

            let (down_tx, mut down_rx) = tokio::io::duplex(64 * 1024);
            let (stream_read, mut stream_write) = tokio::io::split(stream);

            tokio::spawn(async move {
                let _keep_read = stream_read;
                let mut buf = [0u8; 8192];
                loop {
                    match down_rx.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            if stream_write.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            let (q_tx, q_rx) = tokio::io::duplex(64 * 1024);
            let uq = session.upload_queue.clone();

            tokio::spawn(async move {
                let mut writer = q_tx;
                loop {
                    match uq.pop_wait().await {
                        Some(data) => {
                            if writer.write_all(&data).await.is_err() {
                                break;
                            }
                            if writer.flush().await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            });

            let conn = SplitConn::new(
                Box::pin(q_rx),
                Box::pin(down_tx),
                Some(remote_addr),
                Some(remote_addr),
                None,
            );

            return Ok(Some(Box::pin(conn)));
        }

        Ok(None)
    }
}

pub struct SplitHttpHub {
    local_addr: SocketAddr,
    config: SplitHttpConfig,
    sessions: Arc<Mutex<HashMap<String, Arc<HttpSession>>>>,
    conn_rx: Arc<Mutex<mpsc::Receiver<(BoxStream, SocketAddr)>>>,
}

impl SplitHttpHub {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        Self::listen(addr, SplitHttpConfig::default()).await
    }

    pub async fn listen(addr: SocketAddr, config: SplitHttpConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (conn_tx, conn_rx) = mpsc::channel(64);

        let sessions_clone = Arc::clone(&sessions);
        let config_clone = config.clone();

        tokio::spawn(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => break,
                };

                let sessions_inner = Arc::clone(&sessions_clone);
                let config_inner = config_clone.clone();
                let tx_inner = conn_tx.clone();

                tokio::spawn(async move {
                    if let Ok(Some(conn)) = SplitHttpServer::handle_stream(
                        Box::pin(stream),
                        remote_addr,
                        &config_inner,
                        &sessions_inner,
                    )
                    .await
                    {
                        let _ = tx_inner.send((conn, remote_addr)).await;
                    }
                });
            }
        });

        Ok(Self {
            local_addr,
            config,
            sessions,
            conn_rx: Arc::new(Mutex::new(conn_rx)),
        })
    }

    pub fn sessions(&self) -> &Arc<Mutex<HashMap<String, Arc<HttpSession>>>> {
        &self.sessions
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn config(&self) -> &SplitHttpConfig {
        &self.config
    }

    pub async fn accept(&self) -> Result<(BoxStream, SocketAddr)> {
        let mut guard = self.conn_rx.lock().await;
        guard.recv().await.ok_or(Error::Closed)
    }
}

pub use SplitHttpHub as Listener;

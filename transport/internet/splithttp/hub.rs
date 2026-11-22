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
            if let Some(pos) = header_buf[..n_read].windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if n_read >= header_buf.len() {
                let _ = stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await;
                return Ok(None);
            }
        };

        let header_str = String::from_utf8_lossy(&header_buf[..header_end]);
        let mut lines = header_str.lines();
        let mut req_parts = lines.next().unwrap_or("").split_whitespace();
        let (Some(method), Some(req_uri)) = (req_parts.next(), req_parts.next()) else {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(None);
        };

        let headers: HashMap<String, String> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
            .collect();

        if !config.host.is_empty()
            && let Some(host_val) = headers.get("host")
        {
            let got = host_val.split(':').next().unwrap_or(host_val);
            let exp = config.host.split(':').next().unwrap_or(&config.host);
            if !got.eq_ignore_ascii_case(exp) {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
                return Ok(None);
            }
        }

        let norm_path = config.get_normalized_path();
        if !req_uri.starts_with(&norm_path) {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            return Ok(None);
        }

        let (pure_path, query_str) = req_uri.split_once('?').unwrap_or((req_uri, ""));
        let query_map: HashMap<String, String> = query_str
            .split('&')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let cookie_map: HashMap<String, String> = headers
            .get("cookie")
            .into_iter()
            .flat_map(|h| h.split(';'))
            .filter_map(|c| c.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();

        let (mut session_id, mut seq_str) =
            config.extract_meta_from_request(pure_path, &norm_path, &headers, &query_map, &cookie_map);
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

        let is_post = method == "POST" || !seq_str.is_empty();
        if !is_post && method != "GET" {
            return Ok(None);
        }

        let session = {
            let mut map = sessions.lock().await;
            map.entry(session_id)
                .or_insert_with(|| Arc::new(HttpSession::new(config.get_normalized_sc_max_buffered_posts())))
                .clone()
        };

        if is_post {
            let content_len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
            let mut body_bytes = Vec::with_capacity(content_len);
            body_bytes.extend_from_slice(&header_buf[header_end..n_read]);
            while body_bytes.len() < content_len {
                let mut chunk = vec![0u8; (content_len - body_bytes.len()).min(4096)];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..n]);
            }
            let _ = session.upload_queue.push(body_bytes, seq_str.parse::<u64>().unwrap_or(0)).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n").await?;
            stream.flush().await?;
            return Ok(None);
        }

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\n\r\n")
            .await?;
        stream.flush().await?;

        let (down_tx, mut down_rx) = tokio::io::duplex(64 * 1024);
        let (stream_read, mut stream_write) = tokio::io::split(stream);
        tokio::spawn(async move {
            let _keep_read = stream_read;
            let mut buf = [0u8; 8192];
            while let Ok(n) = down_rx.read(&mut buf).await {
                if n == 0 || stream_write.write_all(&buf[..n]).await.is_err() || stream_write.flush().await.is_err() {
                    break;
                }
            }
        });

        let (mut q_tx, q_rx) = tokio::io::duplex(64 * 1024);
        let uq = session.upload_queue.clone();
        tokio::spawn(async move {
            while let Some(data) = uq.pop_wait().await {
                if q_tx.write_all(&data).await.is_err() || q_tx.flush().await.is_err() {
                    break;
                }
            }
        });

        Ok(Some(Box::pin(SplitConn::new(Box::pin(q_rx), Box::pin(down_tx), Some(remote_addr), Some(remote_addr), None))))
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
        let (sessions_c, config_c) = (Arc::clone(&sessions), config.clone());

        tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = listener.accept().await {
                let (s, c, tx) = (Arc::clone(&sessions_c), config_c.clone(), conn_tx.clone());
                tokio::spawn(async move {
                    if let Ok(Some(conn)) = SplitHttpServer::handle_stream(Box::pin(stream), remote_addr, &c, &s).await {
                        let _ = tx.send((conn, remote_addr)).await;
                    }
                });
            }
        });

        Ok(Self { local_addr, config, sessions, conn_rx: Arc::new(Mutex::new(conn_rx)) })
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

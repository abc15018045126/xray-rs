use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use super::common::*;
use super::config::SplitHttpConfig;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::transport::internet::TlsClient;
use crate::transport::internet::system_dialer::SystemDialer;

#[async_trait]
pub trait DialerClient: Send + Sync {
    fn is_closed(&self) -> bool;
    async fn open_stream(
        &self,
        url: &str,
        session_id: &str,
        body: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
        upload_only: bool,
    ) -> Result<(
        Pin<Box<dyn AsyncRead + Send + Sync>>,
        Option<SocketAddr>,
        Option<SocketAddr>,
    )>;
    async fn post_packet(&self, url: &str, session_id: &str, seq_str: &str, payload: Vec<u8>) -> Result<()>;
}

pub struct DefaultDialerClient {
    pub transport_config: SplitHttpConfig,
    pub dest: Destination,
    pub http_version: String,
    pub closed: Arc<AtomicBool>,
    pub tls_client: Option<(Arc<TlsClient>, String)>,
}

impl DefaultDialerClient {
    pub fn new(transport_config: SplitHttpConfig, dest: Destination, http_version: impl Into<String>) -> Self {
        Self {
            transport_config,
            dest,
            http_version: http_version.into(),
            closed: Arc::new(AtomicBool::new(false)),
            tls_client: None,
        }
    }
    pub fn with_tls(mut self, tls: Arc<TlsClient>, sni: impl Into<String>) -> Self {
        self.tls_client = Some((tls, sni.into()));
        self
    }
    async fn dial_stream(&self) -> Result<(BoxStream, Option<SocketAddr>, Option<SocketAddr>)> {
        let tcp = SystemDialer::dial_tcp(&self.dest).await?;
        let local_addr = tcp.local_addr().ok();
        let remote_addr = tcp.peer_addr().ok();
        let stream: BoxStream = if let Some((ref tls, ref sni)) = self.tls_client {
            tls.connect(sni, Box::pin(tcp)).await?
        } else {
            Box::pin(tcp)
        };
        Ok((stream, local_addr, remote_addr))
    }
}

#[async_trait]
impl DialerClient for DefaultDialerClient {
    fn is_closed(&self) -> bool { self.closed.load(Ordering::SeqCst) }
    async fn open_stream(
        &self,
        _url: &str,
        session_id: &str,
        _body: Option<Pin<Box<dyn AsyncRead + Send + Sync>>>,
        upload_only: bool,
    ) -> Result<(
        Pin<Box<dyn AsyncRead + Send + Sync>>,
        Option<SocketAddr>,
        Option<SocketAddr>,
    )> {
        let (mut stream, local_addr, remote_addr) = self.dial_stream().await?;
        let method = if upload_only { self.transport_config.get_normalized_uplink_http_method() } else { "GET" };
        let norm_path = self.transport_config.get_normalized_path();
        let placement = self.transport_config.get_normalized_session_placement();
        let target_path = if !session_id.is_empty() && placement == PLACEMENT_PATH {
            SplitHttpConfig::append_to_path(&norm_path, session_id)
        } else {
            norm_path
        };
        let host_fallback = self.dest.address.to_string();
        let host = if self.transport_config.host.is_empty() { host_fallback.as_str() } else { self.transport_config.host.as_str() };
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\n", method, target_path, host);
        if !session_id.is_empty() && placement == PLACEMENT_HEADER {
            req.push_str(&format!("{}: {}\r\n", self.transport_config.get_normalized_session_key(), session_id));
        }
        for (k, v) in &self.transport_config.headers { req.push_str(&format!("{}: {}\r\n", k, v)); }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let mut buf = [0u8; 1024];
        let mut n_read = 0;
        loop {
            let n = stream.read(&mut buf[n_read..]).await?;
            if n == 0 { return Err(Error::Closed); }
            n_read += n;
            if let Some(pos) = buf[..n_read].windows(4).position(|w| w == b"\r\n\r\n") {
                let status_line = String::from_utf8_lossy(&buf[..pos]).lines().next().unwrap_or("").to_string();
                if !status_line.contains("200") {
                    return Err(Error::Protocol(format!("unexpected HTTP status: {}", status_line)));
                }
                let rem = buf[pos + 4..n_read].to_vec();
                let reader: Pin<Box<dyn AsyncRead + Send + Sync>> = if rem.is_empty() {
                    Box::pin(stream)
                } else {
                    Box::pin(tokio::io::AsyncReadExt::chain(std::io::Cursor::new(rem), stream))
                };
                return Ok((reader, local_addr, remote_addr));
            }
            if n_read >= buf.len() { return Err(Error::Protocol("HTTP response headers too long".into())); }
        }
    }
    async fn post_packet(&self, _url: &str, session_id: &str, seq_str: &str, payload: Vec<u8>) -> Result<()> {
        let (mut stream, _, _) = self.dial_stream().await?;
        let cfg = &self.transport_config;
        let (s_pl, q_pl) = (cfg.get_normalized_session_placement(), cfg.get_normalized_seq_placement());
        let mut target_path = cfg.get_normalized_path();
        if !session_id.is_empty() && s_pl == PLACEMENT_PATH {
            target_path = SplitHttpConfig::append_to_path(&target_path, session_id);
            if !seq_str.is_empty() && q_pl == PLACEMENT_PATH {
                target_path = SplitHttpConfig::append_to_path(&target_path, seq_str);
            }
        }
        let host = if cfg.host.is_empty() { "localhost" } else { &cfg.host };
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
            cfg.get_normalized_uplink_http_method(), target_path, host, payload.len()
        );
        if !session_id.is_empty() && s_pl == PLACEMENT_HEADER {
            req.push_str(&format!("{}: {}\r\n", cfg.get_normalized_session_key(), session_id));
        }
        if !seq_str.is_empty() && q_pl == PLACEMENT_HEADER {
            req.push_str(&format!("{}: {}\r\n", cfg.get_normalized_seq_key(), seq_str));
        }
        for (k, v) in &cfg.headers { req.push_str(&format!("{}: {}\r\n", k, v)); }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        if !payload.is_empty() { stream.write_all(&payload).await?; }
        stream.flush().await?;
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        if n == 0 { return Err(Error::Closed); }
        let resp = String::from_utf8_lossy(&buf[..n]);
        if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
            return Err(Error::Protocol(format!(
                "post packet failed with response: {}",
                resp.lines().next().unwrap_or("")
            )));
        }
        Ok(())
    }
}

pub struct SplitHttpClient {
    pub config: SplitHttpConfig,
    pub session_id: String,
}

impl SplitHttpClient {
    pub fn new(config: SplitHttpConfig, session_id: impl Into<String>) -> Self {
        Self {
            config,
            session_id: session_id.into(),
        }
    }
    pub fn format_download_request(&self) -> String {
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\nX-Session-Id: {}\r\n",
            self.config.path, self.config.host, self.session_id
        );
        for (k, v) in &self.config.headers { req.push_str(&format!("{}: {}\r\n", k, v)); }
        req.push_str("\r\n");
        req
    }
    pub fn format_upload_request(&self, payload_len: usize) -> String {
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nX-Session-Id: {}\r\n",
            self.config.path, self.config.host, payload_len, self.session_id
        );
        for (k, v) in &self.config.headers { req.push_str(&format!("{}: {}\r\n", k, v)); }
        req.push_str("\r\n");
        req
    }
}

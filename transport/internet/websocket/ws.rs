// Module: transport\internet\websocket\ws.rs
// 1:1 Rust implementation corresponding to Go transport\internet\websocket\ws.go

use base64::Engine;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, accept_async, client_async};

use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

pub struct WebSocketStream;

fn bridge_ws_stream(
    ws_stream: TungsteniteStream<BoxStream>,
    heartbeat_period: u32,
) -> BoxStream {
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut r_client, w_server) = tokio::io::duplex(64 * 1024);
    let (r_server, mut w_client) = tokio::io::duplex(64 * 1024);

    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 4096];
        let mut heartbeat = if heartbeat_period > 0 {
            let mut iv = tokio::time::interval(Duration::from_secs(heartbeat_period as u64));
            iv.tick().await; // consume immediate first tick
            Some(iv)
        } else {
            None
        };

        loop {
            tokio::select! {
                read_res = r_client.read(&mut buf) => {
                    match read_res {
                        Ok(0) => {
                            let close_frame = CloseFrame {
                                code: CloseCode::Normal,
                                reason: "".into(),
                            };
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                ws_sink.send(Message::Close(Some(close_frame))),
                            )
                            .await;
                            let _ = ws_sink.close().await;
                            break;
                        }
                        Ok(n) => {
                            if ws_sink.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = async {
                    match heartbeat.as_mut() {
                        Some(iv) => iv.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if ws_sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(Ok(msg)) = ws_stream.next().await {
            match msg {
                Message::Binary(bin) => {
                    if w_client.write_all(&bin).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    let combined = CombinedStream {
        reader: r_server,
        writer: w_server,
    };
    Box::pin(combined)
}

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
        let mut req = url
            .into_client_request()
            .map_err(|e| Error::Protocol(format!("Invalid WebSocket URL '{}': {}", url, e)))?;

        if let Some(host) = host_header
            && let Ok(val) = host.parse()
        {
            req.headers_mut()
                .insert(tokio_tungstenite::tungstenite::http::header::HOST, val);
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

            let upgrade_req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
                path_and_query, host_val, ws_key, encoded
            );

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

pub struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: BoxStream,
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let rem = &self.prefix[self.offset..];
            let to_copy = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..to_copy]);
            self.offset += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct CombinedStream<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R: tokio::io::AsyncRead + Unpin, W: Unpin> tokio::io::AsyncRead for CombinedStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CombinedStream<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

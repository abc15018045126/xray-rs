// Module: transport\internet\websocket\connection.rs
// 1:1 Rust implementation corresponding to Go transport\internet\websocket\connection.go

use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::WebSocketStream as TungsteniteStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::common::net::BoxStream;

pub struct WebSocketConnection {
    stream: BoxStream,
    remote_addr: String,
}

impl WebSocketConnection {
    pub fn new(stream: BoxStream, remote_addr: impl Into<String>) -> Self {
        Self {
            stream,
            remote_addr: remote_addr.into(),
        }
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    pub fn into_stream(self) -> BoxStream {
        self.stream
    }
}

/// 1:1 Rust equivalent of Go `NewConnection` in `transport/internet/websocket/connection.go`.
/// Bridges a Tungstenite WebSocket stream into a `BoxStream` with optional heartbeat `Ping`
/// and RFC 6455 normal `CloseFrame` handling.
pub(crate) fn bridge_ws_stream(
    ws_stream: TungsteniteStream<BoxStream>,
    heartbeat_period: u32,
) -> BoxStream {
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut r_client, w_server) = tokio::io::duplex(64 * 1024);
    let (r_server, mut w_client) = tokio::io::duplex(64 * 1024);

    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        // Match Xray-core websocket/connection.go (`Write` sends the full slice as a single
        // BinaryMessage) and the 64KB duplex pipe so coalesced `[VLESS header + first payload]`
        // writes > 4KB are never split into multiple WebSocket frames.
        let mut buf = vec![0u8; 64 * 1024];
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

pub struct PrefixedStream {
    pub(crate) prefix: Vec<u8>,
    pub(crate) offset: usize,
    pub(crate) inner: BoxStream,
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

use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, client_async};
use tracing::{debug, warn};

use xray_rs_types::{BoxStream, Error, Result};

const WS_DUPLEX_BUF_SIZE: usize = 256 * 1024;
const WS_READ_CHUNK_SIZE: usize = 32 * 1024;

fn bridge_ws_stream<S>(ws_stream: TungsteniteStream<S>) -> BoxStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut r_client, w_server) = tokio::io::duplex(WS_DUPLEX_BUF_SIZE);
    let (r_server, mut w_client) = tokio::io::duplex(WS_DUPLEX_BUF_SIZE);

    let flush_notify = Arc::new(Notify::new());
    let flush_notify_rx = flush_notify.clone();
    let (close_tx, mut close_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let mut buf = vec![0u8; WS_READ_CHUNK_SIZE];
        let mut client_eof = false;
        loop {
            if client_eof {
                tokio::select! {
                    _ = &mut close_rx => break,
                    _ = flush_notify_rx.notified() => {
                        if let Err(e) = ws_sink.flush().await {
                            debug!("WebSocket sink flush error after client EOF: {}", e);
                            break;
                        }
                    }
                }
                continue;
            }

            tokio::select! {
                _ = &mut close_rx => break,
                _ = flush_notify_rx.notified() => {
                    if let Err(e) = ws_sink.flush().await {
                        debug!("WebSocket sink flush error: {}", e);
                        break;
                    }
                }
                res = r_client.read(&mut buf) => {
                    match res {
                        Ok(0) => client_eof = true,
                        Ok(n) => {
                            if let Err(e) = ws_sink.send(Message::Binary(buf[..n].to_vec())).await {
                                warn!("WebSocket send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("WebSocket duplex read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(item) = ws_stream.next().await {
            match item {
                Ok(Message::Binary(bin)) => {
                    if let Err(e) = w_client.write_all(&bin).await {
                        debug!("WebSocket duplex write error: {}", e);
                        break;
                    }
                }
                Ok(Message::Ping(_)) => {
                    flush_notify.notify_one();
                }
                Ok(Message::Close(frame)) => {
                    debug!("WebSocket closed by peer: {:?}", frame);
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("WebSocket receive error: {}", e);
                    break;
                }
            }
        }
        let _ = w_client.shutdown().await;
        let _ = close_tx.send(());
    });

    Box::pin(CombinedStream {
        reader: r_server,
        writer: w_server,
    })
}

pub struct WebSocketTransport;

impl WebSocketTransport {
    pub async fn client_handshake(
        url: &str,
        host_header: Option<&str>,
        stream: BoxStream,
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

        let (ws_stream, _) = client_async(req, stream)
            .await
            .map_err(|e| Error::Protocol(format!("WebSocket client handshake failed: {}", e)))?;

        Ok(bridge_ws_stream(ws_stream))
    }
}

struct CombinedStream<R, W> {
    reader: R,
    writer: W,
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for CombinedStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for CombinedStream<R, W> {
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

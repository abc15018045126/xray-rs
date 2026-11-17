pub mod client;
pub mod config;
pub mod http;
pub mod server;

use crate::app::pingora_bridge::PingoraHttpInbound;
use crate::common::errors::Result;
use crate::common::net::BoxStream;
use crate::features::inbound::{InboundHandler, InboundResult};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Server {
    inner: PingoraHttpInbound,
}

impl Server {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            inner: PingoraHttpInbound::new(tag),
        }
    }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str {
        self.inner.tag()
    }

    async fn handle_connection(
        &self,
        stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        self.inner.handle_connection(stream, remote_addr).await
    }
}

pub struct PrefixedStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: BoxStream,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: BoxStream) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let to_write = std::cmp::min(self.prefix.len() - self.prefix_pos, buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..self.prefix_pos + to_write]);
            self.prefix_pos += to_write;
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let _ = Pin::new(&mut self.inner).poll_read(cx, buf);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

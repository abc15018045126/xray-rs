use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::proxy::{http, socks};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub struct Server {
    tag: String,
    socks_server: socks::Server,
    http_server: http::Server,
}

impl Server {
    pub fn new(tag: impl Into<String>) -> Self {
        let tag_str = tag.into();
        Self {
            socks_server: socks::Server::new(&tag_str),
            http_server: http::Server::new(&tag_str),
            tag: tag_str,
        }
    }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, mut stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let first = stream.read_u8().await?;
        let prefixed: BoxStream = Box::pin(PrefixedStream::new(vec![first], stream));
        match first {
            0x04 | 0x05 => self.socks_server.handle_connection(prefixed, remote_addr).await,
            b if b.is_ascii_alphabetic() || b == b'/' => self.http_server.handle_connection(prefixed, remote_addr).await,
            b => Err(Error::Protocol(format!("Unsupported protocol byte on mixed port: {}", b))),
        }
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
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let n = (self.prefix.len() - self.prefix_pos).min(buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
            self.prefix_pos += n;
            if buf.remaining() > 0 { let _ = Pin::new(&mut self.inner).poll_read(cx, buf); }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod mixed_test;

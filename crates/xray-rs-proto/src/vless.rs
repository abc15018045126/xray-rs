use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

use xray_rs_types::{Address, Destination, Network, Result};

pub const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

impl From<Network> for RequestCommand {
    fn from(net: Network) -> Self {
        match net {
            Network::Tcp => RequestCommand::Tcp,
            Network::Udp => RequestCommand::Udp,
        }
    }
}

/// VLESS outbound request header.
#[derive(Debug, Clone)]
pub struct VlessRequestHeader {
    pub user_id: Uuid,
    pub command: RequestCommand,
    pub destination: Destination,
    pub flow: Option<String>,
}

impl VlessRequestHeader {
    pub fn new(user_id: Uuid, destination: Destination) -> Self {
        let command = RequestCommand::from(destination.network);
        Self {
            user_id,
            command,
            destination,
            flow: None,
        }
    }

    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = Some(flow.into());
        self
    }

    /// Encodes the VLESS request header into `out`.
    pub fn encode_to(&self, out: &mut BytesMut) {
        out.put_u8(VLESS_VERSION);
        out.put_slice(self.user_id.as_bytes());

        // Addons (protobuf-like length-prefixed flow string when present)
        if let Some(flow) = &self.flow
            && !flow.is_empty()
        {
            let flow_bytes = flow.as_bytes();
            let addons_len = 2 + flow_bytes.len();
            out.put_u8(addons_len as u8);
            out.put_u8(0x0a); // field 1 (Flow), wire type 2 (len-delimited)
            out.put_u8(flow_bytes.len() as u8);
            out.put_slice(flow_bytes);
        } else {
            out.put_u8(0);
        }

        out.put_u8(self.command as u8);
        out.put_u16(self.destination.port);

        match &self.destination.address {
            Address::Ipv4(ip) => {
                out.put_u8(1);
                out.put_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                let d = domain.as_bytes();
                out.put_u8(2);
                out.put_u8(d.len() as u8);
                out.put_slice(d);
            }
            Address::Ipv6(ip) => {
                out.put_u8(3);
                out.put_slice(&ip.octets());
            }
        }
    }

    /// Writes the VLESS request header directly to an async writer.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = BytesMut::with_capacity(64);
        self.encode_to(&mut buf);
        writer.write_all(&buf).await?;
        Ok(())
    }
}

/// Non-blocking stream wrapper that strips the VLESS response header on first read.
pub struct VlessStream<S> {
    inner: S,
    header_parsed: bool,
    pending_buf: Vec<u8>,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header_parsed: false,
            pending_buf: Vec::with_capacity(512),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.header_parsed {
                if !self.pending_buf.is_empty() {
                    let to_write = std::cmp::min(buf.remaining(), self.pending_buf.len());
                    buf.put_slice(&self.pending_buf[..to_write]);
                    self.pending_buf.drain(..to_write);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, buf);
            }

            let mut temp_buf = [0u8; 1024];
            let mut temp_read_buf = ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = temp_read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.pending_buf.extend_from_slice(filled);

                    if self.pending_buf.len() >= 2 {
                        let addons_len = self.pending_buf[1] as usize;
                        let header_len = 2 + addons_len;

                        if self.pending_buf.len() >= header_len {
                            self.header_parsed = true;
                            self.pending_buf.drain(..header_len);

                            if !self.pending_buf.is_empty() {
                                let to_write =
                                    std::cmp::min(buf.remaining(), self.pending_buf.len());
                                buf.put_slice(&self.pending_buf[..to_write]);
                                self.pending_buf.drain(..to_write);
                                return Poll::Ready(Ok(()));
                            }
                            continue;
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
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

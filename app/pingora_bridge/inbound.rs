use std::net::SocketAddr;
use std::str::FromStr;

use async_trait::async_trait;
use pingora_http::RequestHeader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::proxy::http::PrefixedStream;

pub struct PingoraHttpInbound {
    tag: String,
}

impl PingoraHttpInbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl InboundHandler for PingoraHttpInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let mut buf = vec![0u8; 16384];
        let mut total_read = 0;
        let mut header_len = 0;
        let mut is_complete = false;

        while total_read < buf.len() {
            let n = stream.read(&mut buf[total_read..]).await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            total_read += n;

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&buf[..total_read]) {
                Ok(httparse::Status::Complete(len)) => {
                    header_len = len;
                    is_complete = true;
                    break;
                }
                Ok(httparse::Status::Partial) => continue,
                Err(e) => {
                    return Err(Error::Protocol(format!(
                        "PingoraHttpInbound failed to parse HTTP request: {}",
                        e
                    )));
                }
            }
        }

        if !is_complete {
            return Err(Error::Protocol("Incomplete HTTP request header".into()));
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Request::new(&mut headers);
        let _ = parsed
            .parse(&buf[..total_read])
            .map_err(|e| Error::Protocol(format!("Failed to re-parse HTTP request: {}", e)))?;

        let method = parsed
            .method
            .ok_or_else(|| Error::Protocol("Missing HTTP method".into()))?;
        let path = parsed
            .path
            .ok_or_else(|| Error::Protocol("Missing HTTP path".into()))?;

        let mut pg_req = RequestHeader::build(method, path.as_bytes(), None)
            .map_err(|e| Error::Protocol(format!("Invalid HTTP request for Pingora: {}", e)))?;
        for h in parsed.headers.iter() {
            if !h.name.eq_ignore_ascii_case("Proxy-Connection") {
                let _ = pg_req.append_header(h.name.to_string(), h.value);
            }
        }

        let is_connect = method.eq_ignore_ascii_case("CONNECT");
        let destination = if is_connect {
            Destination::from_str(path)?
        } else {
            let host_val = pg_req
                .headers
                .get("Host")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::Protocol("Missing Host header".into()))?;
            if host_val.contains(':') {
                Destination::from_str(host_val)?
            } else {
                Destination::from_str(&format!("{}:80", host_val))?
            }
        };

        if is_connect {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await?;

            let out_stream: BoxStream = if total_read > header_len {
                Box::pin(PrefixedStream::new(
                    buf[header_len..total_read].to_vec(),
                    stream,
                ))
            } else {
                stream
            };

            let mut session = SessionContext::new(&self.tag, destination);
            session.source = Some(remote_addr);
            Ok(InboundResult {
                stream: out_stream,
                session,
            })
        } else {
            let mut normalized = Vec::with_capacity(total_read);
            normalized.extend_from_slice(method.as_bytes());
            normalized.push(b' ');
            normalized.extend_from_slice(path.as_bytes());
            normalized.extend_from_slice(b" HTTP/1.1\r\n");
            for (name, value) in pg_req.headers.iter() {
                normalized.extend_from_slice(name.as_str().as_bytes());
                normalized.extend_from_slice(b": ");
                normalized.extend_from_slice(value.as_bytes());
                normalized.extend_from_slice(b"\r\n");
            }
            normalized.extend_from_slice(b"\r\n");
            if total_read > header_len {
                normalized.extend_from_slice(&buf[header_len..total_read]);
            }

            let out_stream: BoxStream = Box::pin(PrefixedStream::new(normalized, stream));
            let mut session = SessionContext::new(&self.tag, destination);
            session.source = Some(remote_addr);
            Ok(InboundResult {
                stream: out_stream,
                session,
            })
        }
    }
}

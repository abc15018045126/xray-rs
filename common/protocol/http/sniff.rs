use crate::common::errors::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1,
    Http2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffHeader {
    pub version: HttpVersion,
    pub host: String,
    pub path: Option<String>,
    pub method: Option<String>,
}

impl SniffHeader {
    pub fn protocol(&self) -> &'static str {
        match self.version {
            HttpVersion::Http1 => "http1",
            HttpVersion::Http2 => "http2",
        }
    }
    pub fn domain(&self) -> &str { &self.host }
}

const METHODS: [&str; 7] = ["get", "post", "head", "put", "delete", "options", "connect"];

pub fn sniff_http(bytes: &[u8]) -> Result<SniffHeader> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::Protocol("invalid utf8 for http".into()))?;
    let mut lines = s.lines();
    let mut parts = lines.next().ok_or_else(|| Error::Protocol("empty http request".into()))?.split_whitespace();
    let method = parts.next().ok_or_else(|| Error::Protocol("no method".into()))?;
    if !METHODS.iter().any(|m| m.eq_ignore_ascii_case(method)) {
        return Err(Error::Protocol("not http method".into()));
    }
    let path = parts.next().map(str::to_string);
    let host = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':')).find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| {
            let h = v.trim();
            h.rsplit_once(':').map_or(h, |(h_only, _)| h_only).to_string()
        })
        .ok_or_else(|| Error::Protocol("host header not found".into()))?;
    Ok(SniffHeader { version: HttpVersion::Http1, host, path, method: Some(method.to_uppercase()) })
}

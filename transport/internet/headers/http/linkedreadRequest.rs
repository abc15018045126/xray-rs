use crate::common::errors::{Error, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ParsedRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, Vec<String>>,
}

pub fn read_request(data: &[u8]) -> Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            let mut header_map = HashMap::new();
            for h in req.headers {
                header_map.entry(h.name.to_string()).or_insert_with(Vec::new)
                    .push(String::from_utf8_lossy(h.value).to_string());
            }
            Ok(ParsedRequest {
                method: req.method.unwrap_or("GET").to_string(),
                uri: req.path.unwrap_or("/").to_string(),
                version: req.version.map_or_else(|| "1.1".into(), |v| format!("1.{}", v)),
                headers: header_map,
            })
        }
        Ok(httparse::Status::Partial) => Err(Error::Eof),
        Err(e) => Err(Error::Protocol(format!("malformed HTTP request: {}", e))),
    }
}

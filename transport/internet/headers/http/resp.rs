use super::config_pb::{Header, ResponseConfig, Status, Version};

fn make_resp(code: &str, reason: &str) -> ResponseConfig {
    let hdr = |n: &str, v: &str| Header { name: n.into(), value: vec![v.into()] };
    ResponseConfig {
        version: Some(Version { value: "1.1".into() }),
        status: Some(Status { code: code.into(), reason: reason.into() }),
        header: vec![hdr("Connection", "close"), hdr("Cache-Control", "private"), hdr("Content-Length", "0")],
    }
}

pub fn resp400() -> ResponseConfig { make_resp("400", "Bad Request") }

pub fn resp404() -> ResponseConfig {
    ResponseConfig {
        version: Some(Version {
            value: "1.1".into(),
        }),
        status: Some(Status {
            code: "404".into(),
            reason: "Not Found".into(),
        }),
        header: vec![
            Header {
                name: "Connection".into(),
                value: vec!["close".into()],
            },
            Header {
                name: "Cache-Control".into(),
                value: vec!["private".into()],
            },
            Header {
                name: "Content-Length".into(),
                value: vec!["0".into()],
            },
        ],
    }
}

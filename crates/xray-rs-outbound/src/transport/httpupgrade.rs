use tokio::io::{AsyncReadExt, AsyncWriteExt};

use xray_rs_types::{BoxStream, Error, Result};

/// HTTPUpgrade transport (`Upgrade: websocket` + `Connection: Upgrade` without WebSocket framing).
pub struct HttpUpgradeTransport;

impl HttpUpgradeTransport {
    pub async fn client_handshake(
        path: &str,
        host: &str,
        mut stream: BoxStream,
    ) -> Result<BoxStream> {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            path, host
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = [0u8; 4096];
        let mut total = 0;
        loop {
            let n = stream.read(&mut buf[total..]).await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            total += n;
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf[..total]) {
                Ok(httparse::Status::Complete(_)) => {
                    if resp.code == Some(101) {
                        return Ok(stream);
                    }
                    return Err(Error::Protocol(format!(
                        "HTTPUpgrade rejected with status {:?}",
                        resp.code
                    )));
                }
                Ok(httparse::Status::Partial) if total < buf.len() => continue,
                _ => {
                    return Err(Error::Protocol("Invalid HTTPUpgrade response".into()));
                }
            }
        }
    }
}

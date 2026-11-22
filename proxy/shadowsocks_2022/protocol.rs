use crate::common::errors::{Error, Result};
use crate::common::net::Destination;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HEADER_TYPE_CLIENT: u8 = 0;
pub const HEADER_TYPE_SERVER: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeader {
    pub header_type: u8,
    pub timestamp: u64,
    pub session_id: u64,
    pub destination: Option<Destination>,
}

impl SessionHeader {
    pub fn new_client(destination: Destination) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let session_id = rand::thread_rng().r#gen();
        Self {
            header_type: HEADER_TYPE_CLIENT,
            timestamp: now,
            session_id,
            destination: Some(destination),
        }
    }
    pub fn new_server(session_id: u64) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            header_type: HEADER_TYPE_SERVER,
            timestamp: now,
            session_id,
            destination: None,
        }
    }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.header_type).await?;
        writer.write_u64(self.timestamp).await?;
        writer.write_u64(self.session_id).await?;
        if self.header_type == HEADER_TYPE_CLIENT {
            let s = self.destination.as_ref().map(ToString::to_string).unwrap_or_default();
            writer.write_u16(s.len() as u16).await?;
            if !s.is_empty() { writer.write_all(s.as_bytes()).await?; }
        }
        Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let (header_type, timestamp, session_id) = (reader.read_u8().await?, reader.read_u64().await?, reader.read_u64().await?);
        let destination = if header_type == HEADER_TYPE_CLIENT {
            let len = reader.read_u16().await? as usize;
            if len > 0 {
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                use std::str::FromStr;
                Some(Destination::from_str(&String::from_utf8(buf).map_err(|e| Error::Protocol(e.to_string()))?)?)
            } else { None }
        } else { None };
        Ok(Self { header_type, timestamp, session_id, destination })
    }
}

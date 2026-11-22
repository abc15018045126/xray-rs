use crate::common::errors::Result;
use tokio::io::{AsyncRead, AsyncReadExt};

pub trait Drainer: Send + Sync {
    fn acknowledge_receive(&mut self, size: usize);
}

pub async fn drain_read_n<R: AsyncRead + Unpin>(reader: &mut R, mut n: usize) -> Result<usize> {
    let mut buf = [0u8; 4096];
    let mut drained = 0;
    while n > 0 {
        let to_read = n.min(buf.len());
        let read = reader.read(&mut buf[..to_read]).await?;
        if read == 0 { break; }
        drained += read;
        n -= read;
    }
    Ok(drained)
}

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::io::{Reader, TimeoutReader, Writer};
use crate::app::stats::Counter;
use crate::common::errors::{Error, Result};
use crate::common::signal::ActivityTimer;

#[derive(Clone, Default)]
pub struct CopyOptions {
    pub timer: Option<Arc<ActivityTimer>>,
    pub counter: Option<Arc<Counter>>,
    pub size_counter: Option<Arc<AtomicI64>>,
}

impl CopyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timer(mut self, timer: Arc<ActivityTimer>) -> Self {
        self.timer = Some(timer);
        self
    }

    pub fn with_counter(mut self, counter: Arc<Counter>) -> Self {
        self.counter = Some(counter);
        self
    }

    pub fn with_size_counter(mut self, size: Arc<AtomicI64>) -> Self {
        self.size_counter = Some(size);
        self
    }
}

pub async fn copy<R: Reader, W: Writer>(reader: &mut R, writer: &mut W, options: &CopyOptions) -> Result<u64> {
    let mut total = 0u64;
    loop {
        match reader.read_multi_buffer().await {
            Ok(mb) if mb.is_empty() => break,
            Ok(mb) => {
                let len = mb.len();
                total += len as u64;
                if let Some(t) = &options.timer { t.update(); }
                if let Some(c) = &options.counter { c.add(len as i64); }
                if let Some(s) = &options.size_counter { s.fetch_add(len as i64, Ordering::Relaxed); }
                writer.write_multi_buffer(mb).await?;
            }
            Err(Error::Io(ref io_err)) if io_err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

pub async fn copy_once_timeout<R: TimeoutReader, W: Writer>(
    reader: &mut R,
    writer: &mut W,
    d: Duration,
) -> Result<usize> {
    let mb = reader.read_multi_buffer_timeout(d).await?;
    let len = mb.len();
    writer.write_multi_buffer(mb).await?;
    Ok(len)
}

pub async fn copy_stream<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_size: usize,
    options: CopyOptions,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buffer_size.max(4096)];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n]).await.map_err(Error::Io)?;
        total += n as u64;

        if let Some(timer) = &options.timer {
            timer.update();
        }
        if let Some(counter) = &options.counter {
            counter.add(n as i64);
        }
        if let Some(size) = &options.size_counter {
            size.fetch_add(n as i64, Ordering::Relaxed);
        }
    }

    writer.flush().await.map_err(Error::Io)?;
    Ok(total)
}

pub async fn copy_one_way<R: AsyncRead + Unpin, W: AsyncWrite + Unpin, F: FnMut(&[u8])>(
    mut reader: R,
    mut writer: W,
    activity_tx: tokio::sync::mpsc::Sender<()>,
    counter: Option<Arc<crate::features::stats::Counter>>,
    mut on_chunk: F,
) -> std::io::Result<u64> {
    let mut buf = [0u8; super::buffer::DEFAULT_BUFFER_SIZE];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => { let _ = writer.flush().await; let _ = writer.shutdown().await; return Ok(total); }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = writer.flush().await; let _ = writer.shutdown().await; return Ok(total);
            }
            Err(e) => { let _ = writer.shutdown().await; return Err(e); }
            Ok(n) => {
                total += n as u64;
                if let Some(c) = &counter { c.add(n as i64); }
                let _ = activity_tx.try_send(());
                on_chunk(&buf[..n]);
                if let Err(e) = writer.write_all(&buf[..n]).await { let _ = writer.shutdown().await; return Err(e); }
            }
        }
    }
}

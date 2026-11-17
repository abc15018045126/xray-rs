use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

async fn copy_one_dir<R, W>(
    mut reader: R,
    mut writer: W,
    active: Arc<AtomicBool>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32768];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(n) => {
                total += n as u64;
                active.store(true, Ordering::Relaxed);
                if let Err(e) = writer.write_all(&buf[..n]).await {
                    let _ = writer.shutdown().await;
                    return Err(e);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Err(e) => {
                let _ = writer.shutdown().await;
                return Err(e);
            }
        }
    }
}

/// Bidirectional streaming with low-CPU periodic activity check (matches Go Xray-core) and graceful half-close.
pub async fn copy_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let timeout_duration = if idle_timeout.is_zero() {
        Duration::from_secs(300)
    } else {
        idle_timeout
    };

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let active = Arc::new(AtomicBool::new(false));
    let active_a = active.clone();
    let active_b = active.clone();

    let timer_task = async move {
        // Check once per timeout_duration instead of resetting a timer on every packet (near-zero CPU).
        loop {
            tokio::time::sleep(timeout_duration).await;
            if !active.swap(false, Ordering::Relaxed) {
                break;
            }
        }
    };

    tokio::select! {
        (res_a, res_b) = async {
            let fut_a = copy_one_dir(&mut a_read, &mut b_write, active_a);
            let fut_b = copy_one_dir(&mut b_read, &mut a_write, active_b);
            tokio::join!(fut_a, fut_b)
        } => {
            match (res_a, res_b) {
                (Ok(from_client), Ok(from_server)) => Ok((from_client, from_server)),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
        _ = timer_task => {
            debug!("Session idle for {:?}, terminating connection", timeout_duration);
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "session idle timeout"))
        }
    }
}

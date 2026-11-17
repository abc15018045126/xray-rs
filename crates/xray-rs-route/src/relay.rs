use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

async fn copy_one_dir<R, W>(
    mut reader: R,
    mut writer: W,
    activity_tx: tokio::sync::mpsc::Sender<()>,
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
                let _ = activity_tx.try_send(());
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

/// Bidirectional streaming with activity-based idle timeout and graceful half-close.
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

    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(1);
    let activity_tx_b = activity_tx.clone();

    let timer_task = async {
        let sleep = tokio::time::sleep(timeout_duration);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                msg = activity_rx.recv() => {
                    match msg {
                        Some(()) => {
                            sleep.as_mut().reset(tokio::time::Instant::now() + timeout_duration);
                        }
                        None => break,
                    }
                }
            }
        }
    };

    tokio::select! {
        (res_a, res_b) = async {
            let fut_a = copy_one_dir(&mut a_read, &mut b_write, activity_tx);
            let fut_b = copy_one_dir(&mut b_read, &mut a_write, activity_tx_b);
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

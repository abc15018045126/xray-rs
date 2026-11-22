use crate::common::errors::{Error, Result};

pub const TUN_FD_ENV_KEY: &str = "xray.tun.fd";
pub const TUN_FD_ENV_ALT_KEY: &str = "XRAY_TUN_FD";

pub fn read_android_tun_fd_from_env() -> Result<i32> {
    let raw = std::env::var(TUN_FD_ENV_KEY)
        .or_else(|_| std::env::var(TUN_FD_ENV_ALT_KEY))
        .map_err(|_| {
            Error::Config(format!(
                "Android TUN fd not set (expected env '{}' or '{}')",
                TUN_FD_ENV_KEY, TUN_FD_ENV_ALT_KEY
            ))
        })?;
    let fd: i32 = raw
        .trim()
        .parse()
        .map_err(|e| Error::Config(format!("Invalid Android TUN fd '{}': {}", raw, e)))?;
    if fd <= 0 {
        return Err(Error::Config(format!(
            "Android TUN fd must be positive, got {}",
            fd
        )));
    }
    Ok(fd)
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub struct AndroidTunDevice {
        inner: AsyncFd<OwnedFd>,
    }

    impl AndroidTunDevice {
        pub fn from_env() -> Result<Self> {
            let fd = read_android_tun_fd_from_env()?;
            Self::from_raw_fd(fd)
        }

        pub fn from_raw_fd(fd: i32) -> Result<Self> {
            let dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if dup_fd < 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }
            let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL) };
            if flags < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(dup_fd) };
                return Err(Error::Io(err));
            }
            if unsafe { libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(dup_fd) };
                return Err(Error::Io(err));
            }
            let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
            #[allow(deprecated)]
            let async_fd = AsyncFd::new(owned).map_err(Error::Io)?;
            Ok(Self { inner: async_fd })
        }

        pub fn raw_fd(&self) -> i32 {
            self.inner.as_raw_fd()
        }
    }

    impl AsyncRead for AndroidTunDevice {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            loop {
                let mut guard = match self.inner.poll_read_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                let dst = buf.initialize_unfilled();
                match guard.try_io(|inner| {
                    let n = unsafe { libc::read(inner.as_raw_fd(), dst.as_mut_ptr() as *mut libc::c_void, dst.len()) };
                    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
                }) {
                    Ok(Ok(n)) => { buf.advance(n); return Poll::Ready(Ok(())); }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_) => continue,
                }
            }
        }
    }

    impl AsyncWrite for AndroidTunDevice {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = match self.inner.poll_write_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                match guard.try_io(|inner| {
                    let n = unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len()) };
                    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
                }) {
                    Ok(res) => return Poll::Ready(res),
                    Err(_) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(target_os = "android")]
pub use imp::AndroidTunDevice;

use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const TUN_FD_ENV_KEY: &str = "xray.tun.fd";
pub const TUN_FD_ENV_ALT_KEY: &str = "XRAY_TUN_FD";

pub type AndroidTunOpenerFn = Arc<dyn Fn(i32) -> Result<BoxStream> + Send + Sync>;

static ANDROID_TUN_OPENER: RwLock<Option<AndroidTunOpenerFn>> = RwLock::new(None);

pub fn register_android_tun_opener(opener: Option<AndroidTunOpenerFn>) {
    if let Ok(mut guard) = ANDROID_TUN_OPENER.write() {
        *guard = opener;
    }
}

pub fn read_android_tun_fd_from_env() -> Result<i32> {
    let raw = std::env::var(TUN_FD_ENV_KEY)
        .or_else(|_| std::env::var(TUN_FD_ENV_ALT_KEY))
        .map_err(|_| Error::Config(format!("Android TUN fd not set (expected env '{}' or '{}')", TUN_FD_ENV_KEY, TUN_FD_ENV_ALT_KEY)))?;
    let fd: i32 = raw.trim().parse().map_err(|e| Error::Config(format!("Invalid Android TUN fd '{}': {}", raw, e)))?;
    if fd <= 0 {
        return Err(Error::Config(format!("Android TUN fd must be positive, got {}", fd)));
    }
    Ok(fd)
}

pub struct AndroidTunDevice {
    fd: i32,
    inner: BoxStream,
}

impl AndroidTunDevice {
    pub fn from_env() -> Result<Self> {
        let fd = read_android_tun_fd_from_env()?;
        Self::from_raw_fd(fd)
    }

    pub fn from_raw_fd(fd: i32) -> Result<Self> {
        let opener = ANDROID_TUN_OPENER
            .read()
            .ok()
            .and_then(|g| g.clone())
            .ok_or_else(|| Error::Config("Android TUN opener not registered".into()))?;
        let inner = opener(fd)?;
        Ok(Self { fd, inner })
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd
    }
}

impl AsyncRead for AndroidTunDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AndroidTunDevice {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

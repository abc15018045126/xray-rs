use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use super::config::WebSocketConfig;
use super::ws::WebSocketStream;
use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination};
use crate::transport::internet::tcp::TcpDialer;

pub fn parse_ws_early_data(raw_path: &str) -> (String, usize) {
    let Some((base, query)) = raw_path.split_once('?') else { return (raw_path.to_string(), 0); };
    let (mut ed, mut kept) = (0usize, Vec::new());
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some(("ed", v)) = pair.split_once('=') && let Ok(n) = v.parse::<usize>() { ed = n; }
        else { kept.push(pair); }
    }
    let clean = if kept.is_empty() { if base.is_empty() { "/".into() } else { base.into() } }
        else { format!("{}?{}", base, kept.join("&")) };
    (clean, ed)
}

pub type DialWsFn =
    Arc<dyn Fn(Option<Vec<u8>>) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send>> + Send + Sync>;

enum DelayDialState {
    Idle,
    Dialing {
        rx: oneshot::Receiver<Result<BoxStream>>,
        handle: tokio::task::JoinHandle<()>,
        sent_as_ed: bool,
        ed_len: usize,
    },
    Connected(BoxStream),
    Failed(String),
    Closed,
}

pub struct DelayDialConn {
    dial_fn: DialWsFn,
    max_ed: usize,
    state: DelayDialState,
    wakers: Vec<Waker>,
}

impl DelayDialConn {
    pub fn new(dial_fn: DialWsFn, max_ed: usize) -> Self {
        Self {
            dial_fn,
            max_ed,
            state: DelayDialState::Idle,
            wakers: Vec::new(),
        }
    }
    fn register_waker(&mut self, waker: &Waker) {
        if !self.wakers.iter().any(|w| w.will_wake(waker)) { self.wakers.push(waker.clone()); }
    }
    fn wake_all(&mut self) { for w in self.wakers.drain(..) { w.wake(); } }
}

impl AsyncRead for DelayDialConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            DelayDialState::Connected(stream) => Pin::new(stream).poll_read(cx, buf),
            DelayDialState::Failed(msg) => Poll::Ready(Err(std::io::Error::other(msg.clone()))),
            DelayDialState::Closed => Poll::Ready(Ok(())),
            DelayDialState::Idle | DelayDialState::Dialing { .. } => {
                self.register_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for DelayDialConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        loop {
            match &mut self.state {
                DelayDialState::Idle => {
                    let use_ed = !buf.is_empty() && buf.len() <= self.max_ed;
                    let ed_bytes = use_ed.then(|| buf.to_vec());
                    let dial_fn = self.dial_fn.clone();
                    let (tx, rx) = oneshot::channel();
                    let handle = tokio::spawn(async move {
                        let _ = tx.send(dial_fn(ed_bytes).await);
                    });
                    self.state = DelayDialState::Dialing { rx, handle, sent_as_ed: use_ed, ed_len: buf.len() };
                }
                DelayDialState::Dialing { rx, sent_as_ed, ed_len, .. } => match Pin::new(rx).poll(cx) {
                    Poll::Pending => {
                        self.register_waker(cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(Ok(stream))) => {
                        let (was_ed, n) = (*sent_as_ed, *ed_len);
                        self.state = DelayDialState::Connected(stream);
                        self.wake_all();
                        if was_ed { return Poll::Ready(Ok(n.min(buf.len()))); }
                    }
                    Poll::Ready(res) => {
                        let msg = match res {
                            Ok(Err(e)) => e.to_string(),
                            _ => "WebSocket early-data dial task cancelled".into(),
                        };
                        self.state = DelayDialState::Failed(msg.clone());
                        self.wake_all();
                        return Poll::Ready(Err(std::io::Error::other(msg)));
                    }
                },
                DelayDialState::Connected(stream) => return Pin::new(stream).poll_write(cx, buf),
                DelayDialState::Failed(msg) => return Poll::Ready(Err(std::io::Error::other(msg.clone()))),
                DelayDialState::Closed => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "delayDialConn closed")));
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            DelayDialState::Connected(stream) => Pin::new(stream).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let DelayDialState::Connected(stream) = &mut self.state { return Pin::new(stream).poll_shutdown(cx); }
        if let DelayDialState::Dialing { handle, .. } = &self.state { handle.abort(); }
        self.state = DelayDialState::Closed;
        self.wake_all();
        Poll::Ready(Ok(()))
    }
}

impl Drop for DelayDialConn {
    fn drop(&mut self) { if let DelayDialState::Dialing { handle, .. } = &self.state { handle.abort(); } }
}

pub struct WebSocketDialer;

impl WebSocketDialer {
    pub async fn dial(dest: &Destination, config: &WebSocketConfig) -> Result<BoxStream> {
        let tcp_stream = TcpDialer::dial(dest).await?;
        let host = dest.address.to_string();
        let path = if config.path.is_empty() {
            "/"
        } else {
            &config.path
        };
        let url = format!("ws://{}{}", host, path);
        WebSocketStream::client_handshake(&url, Some(&host), tcp_stream).await
    }
}

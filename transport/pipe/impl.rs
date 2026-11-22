use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use pingora_timeout::timeout;
use crate::common::buf::MultiBuffer;
use crate::common::errors::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Errord,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PipeOption {
    pub limit: i32,
    pub discard_overflow: bool,
}

impl PipeOption {
    pub fn new() -> Self {
        Self {
            limit: -1,
            discard_overflow: false,
        }
    }
    pub fn is_full(&self, cur_size: usize) -> bool { self.limit >= 0 && (cur_size as i32) > self.limit }
}

pub struct PipeInner {
    pub data: MultiBuffer,
    pub state: State,
    pub option: PipeOption,
    pub pending_error: Option<Error>,
}

pub struct Pipe {
    pub inner: Mutex<PipeInner>,
    pub read_signal: Notify,
    pub write_signal: Notify,
    pub done_notify: Notify,
}

impl Pipe {
    pub fn new(option: PipeOption) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PipeInner {
                data: MultiBuffer::new(),
                state: State::Open,
                option,
                pending_error: None,
            }),
            read_signal: Notify::new(),
            write_signal: Notify::new(),
            done_notify: Notify::new(),
        })
    }
    pub async fn len(&self) -> usize {
        let guard = self.inner.lock().await;
        guard.data.len()
    }
    pub async fn is_empty(&self) -> bool {
        let guard = self.inner.lock().await;
        guard.data.is_empty()
    }
    fn check_read_state(inner: &PipeInner) -> Result<bool> {
        match inner.state {
            State::Open => Ok(false),
            State::Closed => {
                if !inner.data.is_empty() {
                    Ok(false)
                } else {
                    Err(Error::Eof)
                }
            }
            State::Errord => Err(Error::Closed),
        }
    }
    pub async fn read_multi_buffer(&self) -> Result<MultiBuffer> {
        loop {
            {
                let mut guard = self.inner.lock().await;
                if let Some(err) = guard.pending_error.take() { return Err(err); }
                Self::check_read_state(&guard)?;
                if !guard.data.is_empty() {
                    let data = std::mem::take(&mut guard.data);
                    self.write_signal.notify_waiters();
                    return Ok(data);
                }
            }
            tokio::select! {
                _ = self.read_signal.notified() => continue,
                _ = self.done_notify.notified() => {
                    let guard = self.inner.lock().await;
                    if guard.state == State::Errord { return Err(Error::Closed); }
                    if guard.data.is_empty() { return Err(Error::Eof); }
                }
            }
        }
    }
    pub async fn read_multi_buffer_timeout(&self, d: Duration) -> Result<MultiBuffer> {
        match timeout(d, self.read_multi_buffer()).await {
            Ok(res) => res,
            Err(_) => Err(Error::Timeout),
        }
    }
    pub async fn write_multi_buffer(&self, mut mb: MultiBuffer) -> Result<()> {
        if mb.is_empty() { return Ok(()); }
        loop {
            {
                let mut guard = self.inner.lock().await;
                if guard.state != State::Open { return Err(Error::Closed); }
                if !guard.option.is_full(guard.data.len() + mb.len()) {
                    guard.data.append(&mut mb);
                    self.read_signal.notify_waiters();
                    return Ok(());
                }
                if guard.option.discard_overflow { return Ok(()); }
            }
            tokio::select! {
                _ = self.write_signal.notified() => continue,
                _ = self.done_notify.notified() => return Err(Error::Closed),
            }
        }
    }
    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if guard.state == State::Closed || guard.state == State::Errord { return Ok(()); }
        guard.state = State::Closed;
        self.done_notify.notify_waiters();
        self.read_signal.notify_waiters();
        self.write_signal.notify_waiters();
        Ok(())
    }
    pub async fn interrupt(&self) {
        let mut guard = self.inner.lock().await;
        guard.data.clear();
        guard.state = State::Errord;
        self.done_notify.notify_waiters();
        self.read_signal.notify_waiters();
        self.write_signal.notify_waiters();
    }
}

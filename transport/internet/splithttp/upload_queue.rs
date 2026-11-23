use crate::common::errors::{Error, Result};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Packet {
    pub payload: Vec<u8>,
    pub seq: u64,
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering { other.seq.cmp(&self.seq) }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

pub struct UploadQueueInner {
    pub heap: BinaryHeap<Packet>,
    pub next_seq: u64,
    pub closed: bool,
    pub max_packets: usize,
}

#[derive(Clone)]
pub struct UploadQueue {
    inner: Arc<Mutex<UploadQueueInner>>,
    notify: Arc<Notify>,
}

impl UploadQueue {
    pub fn new(max_packets: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(UploadQueueInner {
                heap: BinaryHeap::new(),
                next_seq: 0,
                closed: false,
                max_packets,
            })),
            notify: Arc::new(Notify::new()),
        }
    }
    pub async fn push(&self, payload: Vec<u8>, seq: u64) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.closed { return Err(Error::Closed); }
        if inner.heap.len() >= inner.max_packets { return Err(Error::Protocol("packet queue is too large".into())); }
        inner.heap.push(Packet { payload, seq });
        drop(inner);
        self.notify.notify_waiters();
        Ok(())
    }
    pub async fn push_bytes(&self, data: Vec<u8>) -> Result<()> {
        let seq = {
            let inner = self.inner.lock().await;
            inner.next_seq
        };
        self.push(data, seq).await
    }
    pub async fn pop(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let n = self.read(&mut buf).await.ok()?;
        if n == 0 {
            None
        } else {
            buf.truncate(n);
            Some(buf)
        }
    }
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock().await;
        let mut written = 0;
        while written < buf.len() {
            let Some(seq) = inner.heap.peek().map(|p| p.seq) else { break; };
            if seq < inner.next_seq { inner.heap.pop(); continue; }
            if seq != inner.next_seq { break; }
            let mut packet = inner.heap.pop().unwrap();
            let take = (buf.len() - written).min(packet.payload.len());
            buf[written..written + take].copy_from_slice(&packet.payload[..take]);
            written += take;
            if take < packet.payload.len() {
                packet.payload.drain(..take);
                inner.heap.push(packet);
                break;
            }
            inner.next_seq += 1;
        }
        Ok(written)
    }
    pub async fn pop_wait(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let n = self.read(&mut buf).await.ok()?;
            if n > 0 {
                buf.truncate(n);
                return Some(buf);
            }
            if self.is_closed().await { return None; }
            notified.await;
        }
    }
    pub async fn close(&self) {
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        drop(inner);
        self.notify.notify_waiters();
    }
    pub async fn is_closed(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.closed
    }
}

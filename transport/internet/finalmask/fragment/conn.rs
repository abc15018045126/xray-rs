use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use super::config_pb::Config;
use crate::common::net::BoxStream;

pub struct FragmentConn {
    pub stream: BoxStream,
    pub config: Config,
    pub count: u64,
    pub server: bool,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl FragmentConn {
    pub fn new_client(config: Config, stream: BoxStream) -> Self {
        Self {
            stream,
            config,
            count: 0,
            server: false,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }
    pub fn new_server(config: Config, stream: BoxStream) -> Self {
        Self {
            stream,
            config,
            count: 0,
            server: true,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }
    fn rand_between(min: i64, max: i64) -> i64 {
        if min >= max { return min; }
        let mut rng = rand::thread_rng();
        rng.gen_range(min..=max)
    }
    fn split_tls_record(&self, p: &[u8], record_len: usize) -> Vec<Vec<u8>> {
        let data = &p[5..record_len];
        let max_split = Self::rand_between(self.config.max_split_min, self.config.max_split_max);
        let (mut split_num, mut from, mut chunks) = (0i64, 0, Vec::new());
        while from < data.len() {
            let chunk_len = Self::rand_between(self.config.length_min, self.config.length_max).max(1) as usize;
            split_num += 1;
            let to = if from + chunk_len > data.len() || (max_split > 0 && split_num >= max_split) {
                data.len()
            } else {
                from + chunk_len
            };
            let l = to - from;
            let mut buff = vec![0u8; 5 + l];
            buff[..3].copy_from_slice(&p[..3]);
            buff[3..5].copy_from_slice(&(l as u16).to_be_bytes());
            buff[5..].copy_from_slice(&data[from..to]);
            chunks.push(buff);
            from = to;
        }
        chunks
    }
    pub async fn write_fragmented(&mut self, p: &[u8]) -> io::Result<usize> {
        self.count += 1;
        if self.config.packets_from == 0 && self.config.packets_to == 1 {
            let record_len = if p.len() > 5 { 5 + u16::from_be_bytes([p[3], p[4]]) as usize } else { 0 };
            if self.count != 1 || p.len() <= 5 || p[0] != 22 || p.len() < record_len {
                self.stream.write_all(p).await?;
                return Ok(p.len());
            }
            let chunks = self.split_tls_record(p, record_len);
            if self.config.delay_max == 0 {
                let hello: Vec<u8> = chunks.into_iter().flatten().collect();
                if !hello.is_empty() { self.stream.write_all(&hello).await?; }
            } else {
                for buff in chunks {
                    self.stream.write_all(&buff).await?;
                    let delay = Self::rand_between(self.config.delay_min, self.config.delay_max);
                    if delay > 0 { tokio::time::sleep(tokio::time::Duration::from_millis(delay as u64)).await; }
                }
            }
            if p.len() > record_len { self.stream.write_all(&p[record_len..]).await?; }
            return Ok(p.len());
        }
        if self.config.packets_from != 0
            && (self.count < self.config.packets_from as u64 || self.count > self.config.packets_to as u64)
        {
            self.stream.write_all(p).await?;
            return Ok(p.len());
        }
        let max_split = Self::rand_between(self.config.max_split_min, self.config.max_split_max);
        let (mut split_num, mut from) = (0i64, 0);
        while from < p.len() {
            let chunk_len = Self::rand_between(self.config.length_min, self.config.length_max).max(1) as usize;
            split_num += 1;
            let to = if from + chunk_len > p.len() || (max_split > 0 && split_num >= max_split) {
                p.len()
            } else {
                from + chunk_len
            };
            self.stream.write_all(&p[from..to]).await?;
            from = to;
            let delay = Self::rand_between(self.config.delay_min, self.config.delay_max);
            if delay > 0 && from < p.len() {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay as u64)).await;
            }
        }
        Ok(p.len())
    }
    pub fn splice(&self) -> bool { !self.server }
}

impl crate::transport::internet::finalmask::finalmask::TcpMaskConn for FragmentConn {
    fn splice(&self) -> bool { !self.server }
}

impl AsyncRead for FragmentConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while this.pending_offset < this.pending.len() {
            match Pin::new(&mut this.stream).poll_write(cx, &this.pending[this.pending_offset..]) {
                Poll::Ready(Ok(n)) => this.pending_offset += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.pending.clear();
        this.pending_offset = 0;
        this.count += 1;
        if this.config.packets_from == 0 && this.config.packets_to == 1 {
            let record_len = if buf.len() > 5 { 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize } else { 0 };
            if this.count != 1 || buf.len() <= 5 || buf[0] != 22 || buf.len() < record_len {
                return Pin::new(&mut this.stream).poll_write(cx, buf);
            }
            for (idx, chunk) in this.split_tls_record(buf, record_len).into_iter().enumerate() {
                if idx > 0 && this.config.delay_max > 0 {
                    let delay = Self::rand_between(this.config.delay_min, this.config.delay_max);
                    if delay > 0 { std::thread::sleep(std::time::Duration::from_millis(delay as u64)); }
                }
                this.pending.extend_from_slice(&chunk);
            }
            this.pending.extend_from_slice(&buf[record_len..]);
            while this.pending_offset < this.pending.len() {
                match Pin::new(&mut this.stream).poll_write(cx, &this.pending[this.pending_offset..]) {
                    Poll::Ready(Ok(n)) => this.pending_offset += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => break,
                }
            }
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pending_offset < this.pending.len() {
            match Pin::new(&mut this.stream).poll_write(cx, &this.pending[this.pending_offset..]) {
                Poll::Ready(Ok(n)) => { this.pending_offset += n; }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

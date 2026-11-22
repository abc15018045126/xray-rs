use rand::Rng;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Sleep;
use super::config_pb::Config;
use crate::common::net::BoxStream;

pub struct FragmentConn {
    pub stream: BoxStream,
    pub config: Config,
    pub count: u64,
    pub server: bool,
    pending_chunks: VecDeque<(Vec<u8>, usize, u64)>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl FragmentConn {
    pub fn new_client(config: Config, stream: BoxStream) -> Self {
        Self {
            stream,
            config,
            count: 0,
            server: false,
            pending_chunks: VecDeque::new(),
            sleep: None,
        }
    }
    pub fn new_server(config: Config, stream: BoxStream) -> Self {
        Self {
            stream,
            config,
            count: 0,
            server: true,
            pending_chunks: VecDeque::new(),
            sleep: None,
        }
    }
    fn rand_between(min: i64, max: i64) -> i64 {
        if min >= max { return min; }
        rand::thread_rng().gen_range(min..=max)
    }
    fn sample_delay(&self, seg_idx: usize) -> u64 {
        let (d_min, d_max) = self.config.delay_for_segment(seg_idx);
        if d_max > 0 { Self::rand_between(d_min, d_max).max(0) as u64 } else { 0 }
    }
    fn split_tls_record(&self, p: &[u8], record_len: usize) -> Vec<(Vec<u8>, u64)> {
        let data = &p[5..record_len];
        let max_split = Self::rand_between(self.config.max_split_min, self.config.max_split_max);
        let (mut split_num, mut from, mut chunks) = (0i64, 0, Vec::new());
        while from < data.len() {
            let seg_idx = split_num as usize;
            let (l_min, l_max) = self.config.length_for_segment(seg_idx);
            let chunk_len = Self::rand_between(l_min, l_max).max(1) as usize;
            let to = if from + chunk_len > data.len() || (max_split > 0 && split_num + 1 >= max_split) {
                data.len()
            } else {
                from + chunk_len
            };
            let l = to - from;
            let mut buff = Vec::with_capacity(5 + l);
            buff.extend_from_slice(&p[..3]);
            buff.extend_from_slice(&(l as u16).to_be_bytes());
            buff.extend_from_slice(&data[from..to]);
            chunks.push((buff, self.sample_delay(seg_idx)));
            from = to;
            split_num += 1;
        }
        chunks
    }
    fn split_raw_packet(&self, p: &[u8]) -> Vec<(Vec<u8>, u64)> {
        let max_split = Self::rand_between(self.config.max_split_min, self.config.max_split_max);
        let (mut split_num, mut from, mut chunks) = (0i64, 0, Vec::new());
        while from < p.len() {
            let seg_idx = split_num as usize;
            let (l_min, l_max) = self.config.length_for_segment(seg_idx);
            let chunk_len = Self::rand_between(l_min, l_max).max(1) as usize;
            let to = if from + chunk_len > p.len() || (max_split > 0 && split_num + 1 >= max_split) {
                p.len()
            } else {
                from + chunk_len
            };
            chunks.push((p[from..to].to_vec(), self.sample_delay(seg_idx)));
            from = to;
            split_num += 1;
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
            if self.config.merge_tls_hello_segments() {
                let hello: Vec<u8> = chunks.into_iter().flat_map(|(b, _)| b).collect();
                if !hello.is_empty() { self.stream.write_all(&hello).await?; }
            } else {
                for (buff, delay) in chunks {
                    self.stream.write_all(&buff).await?;
                    let _ = self.stream.flush().await;
                    if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
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
        for (chunk, delay) in self.split_raw_packet(p) {
            self.stream.write_all(&chunk).await?;
            let _ = self.stream.flush().await;
            if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
        }
        Ok(p.len())
    }
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(timer) = self.sleep.as_mut() {
                match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => self.sleep = None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            let Some((chunk, offset, delay)) = self.pending_chunks.front_mut() else {
                return Poll::Ready(Ok(()));
            };
            while *offset < chunk.len() {
                match Pin::new(&mut self.stream).poll_write(cx, &chunk[*offset..]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "fragment write zero"))),
                    Poll::Ready(Ok(n)) => *offset += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let delay_ms = *delay;
            self.pending_chunks.pop_front();
            let _ = Pin::new(&mut self.stream).poll_flush(cx);
            if delay_ms > 0 {
                self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(delay_ms))));
            }
        }
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
        match this.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        this.count += 1;
        if this.config.packets_from == 0 && this.config.packets_to == 1 {
            let record_len = if buf.len() > 5 { 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize } else { 0 };
            if this.count != 1 || buf.len() <= 5 || buf[0] != 22 || buf.len() < record_len {
                return Pin::new(&mut this.stream).poll_write(cx, buf);
            }
            let chunks = this.split_tls_record(buf, record_len);
            if this.config.merge_tls_hello_segments() {
                let hello: Vec<u8> = chunks.into_iter().flat_map(|(b, _)| b).collect();
                if !hello.is_empty() { this.pending_chunks.push_back((hello, 0, 0)); }
            } else {
                for (chunk, delay) in chunks {
                    this.pending_chunks.push_back((chunk, 0, delay));
                }
            }
            if buf.len() > record_len {
                this.pending_chunks.push_back((buf[record_len..].to_vec(), 0, 0));
            }
            if let Poll::Ready(Err(e)) = this.poll_drain_pending(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        if this.config.packets_from != 0
            && (this.count < this.config.packets_from as u64 || this.count > this.config.packets_to as u64)
        {
            return Pin::new(&mut this.stream).poll_write(cx, buf);
        }
        for (chunk, delay) in this.split_raw_packet(buf) {
            this.pending_chunks.push_back((chunk, 0, delay));
        }
        if let Poll::Ready(Err(e)) = this.poll_drain_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream).poll_flush(cx),
            other => other,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut().poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.stream).poll_shutdown(cx),
            other => other,
        }
    }
}

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::common::errors::Result;
use crate::proxy::proxy::{
    COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, TrafficState,
    is_complete_record, xtls_filter_tls, xtls_padding, xtls_unpadding,
};

pub const FLOW_VISION: &str = "xtls-rprx-vision";
pub const FLOW_VISION_UDP443: &str = "xtls-rprx-vision-udp443";

#[derive(Debug, Clone)]
pub struct VisionContext {
    pub is_tls: Arc<AtomicBool>,
    pub direct_copy: Arc<AtomicBool>,
    pub traffic_state: Arc<Mutex<TrafficState>>,
    pub is_uplink: bool,
}

impl VisionContext {
    pub fn new(user_uuid: Vec<u8>, is_uplink: bool) -> Self {
        Self {
            is_tls: Arc::new(AtomicBool::new(false)),
            direct_copy: Arc::new(AtomicBool::new(false)),
            traffic_state: Arc::new(Mutex::new(TrafficState::new(&user_uuid))),
            is_uplink,
        }
    }
    pub fn is_direct_copy(&self) -> bool { self.direct_copy.load(Ordering::SeqCst) }
    pub fn set_direct_copy(&self, val: bool) { self.direct_copy.store(val, Ordering::SeqCst); }
    pub fn is_tls(&self) -> bool { self.is_tls.load(Ordering::SeqCst) }
    pub fn set_tls(&self, val: bool) { self.is_tls.store(val, Ordering::SeqCst); }
}

impl Default for VisionContext {
    fn default() -> Self { Self::new(vec![0u8; 16], true) }
}

pub struct VisionFilter;

impl VisionFilter {
    pub fn inspect_tls_record_length(buf: &[u8]) -> Option<usize> {
        if buf.len() < 5 { return None; }
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        Some(length + 5)
    }
    pub async fn write_padded<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8], padding_len: usize) -> Result<()> {
        writer.write_all(data).await?;
        if padding_len > 0 {
            let padding = vec![0u8; padding_len];
            writer.write_all(&padding).await?;
        }
        writer.flush().await?;
        Ok(())
    }
}

pub struct VisionStream<S> {
    inner: S,
    pub context: VisionContext,
    is_inbound: bool,
    read_direct: bool,
    write_direct: bool,
    write_uuid_sent: bool,
    raw_read_buf: Vec<u8>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, context: VisionContext, is_inbound: bool) -> Self {
        Self {
            inner,
            context,
            is_inbound,
            read_direct: false,
            write_direct: false,
            write_uuid_sent: false,
            raw_read_buf: Vec::new(),
            read_buf: Vec::with_capacity(4096),
            write_buf: Vec::with_capacity(4096),
        }
    }
    pub fn into_inner(self) -> S { self.inner }
    pub fn get_ref(&self) -> &S { &self.inner }
    pub fn get_mut(&mut self) -> &mut S { &mut self.inner }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if this.read_direct || this.context.is_direct_copy() { return Pin::new(&mut this.inner).poll_read(cx, buf); }
        let mut raw = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut raw);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    if !this.raw_read_buf.is_empty() {
                        let leftover = std::mem::take(&mut this.raw_read_buf);
                        let n = buf.remaining().min(leftover.len());
                        buf.put_slice(&leftover[..n]);
                        this.read_buf.extend_from_slice(&leftover[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                let (unpadded, switch_direct) = {
                    let mut state = this.context.traffic_state.lock().unwrap();
                    let need_first_hdr = if this.is_inbound {
                        state.inbound.remaining_command == -1
                    } else {
                        state.outbound.remaining_command == -1
                    };
                    let input_owned;
                    let input: &[u8] = if need_first_hdr {
                        this.raw_read_buf.extend_from_slice(filled);
                        if this.raw_read_buf.len() < 21 {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        input_owned = std::mem::take(&mut this.raw_read_buf);
                        &input_owned
                    } else {
                        filled
                    };
                    let data = xtls_unpadding(input, &mut state, this.is_inbound);
                    if !data.is_empty() { xtls_filter_tls(&data, &mut state); }
                    let (cmd, direct_flag, rem_c, rem_p) = if this.is_inbound {
                        let s = &state.inbound;
                        (s.current_command, s.uplink_reader_direct_copy, s.remaining_content, s.remaining_padding)
                    } else {
                        let s = &state.outbound;
                        (s.current_command, s.downlink_reader_direct_copy, s.remaining_content, s.remaining_padding)
                    };
                    let should_direct = (cmd == COMMAND_PADDING_DIRECT as i32 || cmd == COMMAND_PADDING_END as i32 || direct_flag)
                        && rem_c <= 0 && rem_p <= 0;
                    (data, should_direct)
                };
                if switch_direct {
                    this.read_direct = true;
                    if this.write_direct { this.context.set_direct_copy(true); }
                }
                if unpadded.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = buf.remaining().min(unpadded.len());
                buf.put_slice(&unpadded[..n]);
                this.read_buf.extend_from_slice(&unpadded[n..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "vision inner write zero")));
                }
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                other => return other,
            }
        }
        if this.write_direct || this.context.is_direct_copy() { return Pin::new(&mut this.inner).poll_write(cx, buf); }
        const MAX_VISION_CHUNK: usize = 2048 - 21;
        let chunk = &buf[..buf.len().min(MAX_VISION_CHUNK)];
        let (padded_frame, switch_direct) = {
            let mut state = this.context.traffic_state.lock().unwrap();
            xtls_filter_tls(chunk, &mut state);
            let is_complete_app_data = chunk.len() >= 3
                && chunk[0] == 0x17
                && chunk[1] == 0x03
                && chunk[2] == 0x03
                && is_complete_record(chunk);
            let cmd = if (state.is_tls && is_complete_app_data)
                || (!state.is_tls12_or_above && state.number_of_packet_to_filter <= 1)
            {
                COMMAND_PADDING_END
            } else {
                COMMAND_PADDING_CONTINUE
            };
            let uuid = (!this.write_uuid_sent).then(|| {
                this.write_uuid_sent = true;
                state.user_uuid.as_slice()
            });
            let long_padding = state.is_tls;
            let frame = xtls_padding(Some(chunk), cmd, uuid, long_padding, None);
            (frame, cmd == COMMAND_PADDING_DIRECT || cmd == COMMAND_PADDING_END)
        };
        if switch_direct {
            this.write_direct = true;
            if this.read_direct { this.context.set_direct_copy(true); }
        }
        this.write_buf = padded_frame;
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "vision inner write zero")));
                }
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(chunk.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let s = self.get_mut();
        while !s.write_buf.is_empty() {
            match Pin::new(&mut s.inner).poll_write(cx, &s.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "vision flush write zero")));
                }
                Poll::Ready(Ok(n)) => { s.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut s.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let s = self.get_mut();
        while !s.write_buf.is_empty() {
            match Pin::new(&mut s.inner).poll_write(cx, &s.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "vision shutdown write zero")));
                }
                Poll::Ready(Ok(n)) => { s.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut s.inner).poll_shutdown(cx)
    }
}

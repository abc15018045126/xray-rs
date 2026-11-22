use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use rand::Rng;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::common::errors::{Error, Result};

pub const ENCRYPTION_VERSION: u8 = 0x01;
pub const MAX_NONCE: [u8; 12] = [0xFF; 12];
pub const MAX_CHUNK_SIZE: usize = 8192;
pub const HEADER_LEN: usize = 5;
pub const TAG_LEN: usize = 16;

pub fn increase_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        let idx = 11 - i;
        nonce[idx] = nonce[idx].wrapping_add(1);
        if nonce[idx] != 0 { break; }
    }
}

pub fn encode_header(h: &mut [u8], l: usize) {
    h[0] = 23;
    h[1] = 3;
    h[2] = 3;
    h[3] = (l >> 8) as u8;
    h[4] = l as u8;
}

pub fn decode_header(h: &[u8]) -> Result<usize> {
    if h.len() < HEADER_LEN { return Err(Error::Protocol("Header too short".into())); }
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        return Err(Error::Protocol(format!("Invalid record type in header: {:?}", &h[..3])));
    }
    let l = ((h[3] as usize) << 8) | (h[4] as usize);
    if !(17..=16640).contains(&l) { return Err(Error::Protocol(format!("Invalid header length: {}", l))); }
    Ok(l)
}

pub enum VlessCipher {
    AesGcm(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}

pub struct VlessAead {
    cipher: VlessCipher,
    pub nonce: [u8; 12],
}

impl VlessAead {
    pub fn new(key: &[u8; 32], use_aes: bool) -> Self {
        let cipher = if use_aes {
            let k = aes_gcm::Key::<Aes128Gcm>::from_slice(&key[..16]);
            VlessCipher::AesGcm(Box::new(Aes128Gcm::new(k)))
        } else {
            let k = chacha20poly1305::Key::from_slice(key);
            VlessCipher::ChaCha(ChaCha20Poly1305::new(k))
        };
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        increase_nonce(&mut self.nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => {
                let n = AesNonce::from_slice(&self.nonce);
                c.encrypt(n, payload).map_err(|e| Error::Crypto(format!("AES-GCM seal error: {}", e)))
            }
            VlessCipher::ChaCha(c) => {
                let n = ChaChaNonce::from_slice(&self.nonce);
                c.encrypt(n, payload).map_err(|e| Error::Crypto(format!("ChaCha seal error: {}", e)))
            }
        }
    }
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        increase_nonce(&mut self.nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => {
                let n = AesNonce::from_slice(&self.nonce);
                c.decrypt(n, payload).map_err(|e| Error::Crypto(format!("AES-GCM open error: {}", e)))
            }
            VlessCipher::ChaCha(c) => {
                let n = ChaChaNonce::from_slice(&self.nonce);
                c.decrypt(n, payload).map_err(|e| Error::Crypto(format!("ChaCha open error: {}", e)))
            }
        }
    }
}

pub fn parse_padding(padding: &str) -> Result<(Vec<[i32; 3]>, Vec<[i32; 3]>)> {
    let (mut lens, mut gaps) = (Vec::new(), Vec::new());
    if padding.is_empty() { return Ok((lens, gaps)); }
    for (i, s) in padding.split('.').enumerate() {
        let x: Vec<&str> = s.split('-').collect();
        if x.len() < 3 || x[..3].iter().any(|p| p.is_empty()) {
            return Err(Error::Config(format!("Invalid padding parameter: {}", s)));
        }
        let mut y = [0i32; 3];
        for j in 0..3 { y[j] = x[j].parse().map_err(|_| Error::Config("Invalid number".into()))?; }
        if i % 2 == 0 { lens.push(y); } else { gaps.push(y); }
    }
    Ok((lens, gaps))
}

pub fn create_padding(padding_lens: &[[i32; 3]], padding_gaps: &[[i32; 3]]) -> (usize, Vec<usize>, Vec<Duration>) {
    let mut rng = rand::thread_rng();
    let sample = |rng: &mut rand::rngs::ThreadRng, y: &[i32; 3]| {
        if y[0] >= rng.gen_range(0..=100) {
            let (lo, hi) = (y[1].min(y[2]), y[1].max(y[2]));
            if hi > lo { rng.gen_range(lo..=hi) } else { lo }
        } else { 0 }
    };
    let lens_in = if padding_lens.is_empty() { &[[100, 111, 1111], [50, 0, 3333]][..] } else { padding_lens };
    let gaps_in = if padding_gaps.is_empty() { &[[75, 0, 111]][..] } else { padding_gaps };
    let lens: Vec<usize> = lens_in.iter().map(|y| sample(&mut rng, y) as usize).collect();
    let gaps: Vec<Duration> = gaps_in.iter().map(|y| Duration::from_millis(sample(&mut rng, y) as u64)).collect();
    (lens.iter().sum(), lens, gaps)
}

pub struct CommonConn<S> {
    pub inner: S,
    pub aead_write: VlessAead,
    pub aead_read: VlessAead,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<S> CommonConn<S> {
    pub fn new(inner: S, key: &[u8; 32], use_aes: bool) -> Self {
        Self {
            inner,
            aead_write: VlessAead::new(key, use_aes),
            aead_read: VlessAead::new(key, use_aes),
            read_buf: Vec::with_capacity(MAX_CHUNK_SIZE),
            write_buf: Vec::with_capacity(MAX_CHUNK_SIZE + HEADER_LEN + TAG_LEN),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CommonConn<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        let mut raw_chunk = [0u8; MAX_CHUNK_SIZE + HEADER_LEN + TAG_LEN];
        let mut raw_buf = ReadBuf::new(&mut raw_chunk);
        match Pin::new(&mut this.inner).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(())) => {
                let filled = raw_buf.filled();
                if filled.is_empty() { return Poll::Ready(Ok(())); }
                if filled.len() < HEADER_LEN + TAG_LEN {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Truncated encrypted packet")));
                }
                let inv = |e: crate::common::errors::Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string());
                let l = match decode_header(&filled[..HEADER_LEN]) {
                    Ok(len) => len,
                    Err(e) => return Poll::Ready(Err(inv(e))),
                };
                let plaintext = match this.aead_read.open(&filled[HEADER_LEN..(HEADER_LEN + l).min(filled.len())], &filled[..HEADER_LEN]) {
                    Ok(pt) => pt,
                    Err(e) => return Poll::Ready(Err(inv(e))),
                };
                let n = buf.remaining().min(plaintext.len());
                buf.put_slice(&plaintext[..n]);
                this.read_buf.extend_from_slice(&plaintext[n..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CommonConn<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                other => return other,
            }
        }
        let chunk_size = buf.len().min(MAX_CHUNK_SIZE);
        let mut header = [0u8; HEADER_LEN];
        encode_header(&mut header, chunk_size + TAG_LEN);
        let ciphertext = match this.aead_write.seal(&buf[..chunk_size], &header) {
            Ok(ct) => ct,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        };
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ciphertext);
        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                this.write_buf.extend_from_slice(&frame[n..]);
                Poll::Ready(Ok(chunk_size))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

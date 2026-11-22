use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use crate::common::errors::{Error, Result};

#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    pub prioritize_ipv6: bool,
    pub interleave: u32,
    pub try_delay_ms: u64,
    pub max_concurrent_try: usize,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 250,
            max_concurrent_try: 4,
        }
    }
}

pub trait IntoInterleave {
    fn into_interleave(self) -> u32;
}

impl IntoInterleave for u32 {
    fn into_interleave(self) -> u32 { self }
}

impl IntoInterleave for usize {
    fn into_interleave(self) -> u32 { self as u32 }
}

impl IntoInterleave for bool {
    fn into_interleave(self) -> u32 { if self { 1 } else { 0 } }
}

pub fn sort_ips(ips: &[IpAddr], prioritize_ipv6: bool, interleave: impl IntoInterleave) -> Vec<IpAddr> {
    let (ip4, ip6): (Vec<_>, Vec<_>) = ips.iter().copied().partition(IpAddr::is_ipv4);
    if ip4.is_empty() || ip6.is_empty() { return ips.to_vec(); }
    let (mut first, second) = if prioritize_ipv6 { (ip6, ip4) } else { (ip4, ip6) };
    let stride = interleave.into_interleave() as usize;
    if stride == 0 {
        first.extend(second);
        return first;
    }
    let mut out = Vec::with_capacity(ips.len());
    let (mut a, mut b) = (first.as_slice(), second.as_slice());
    while !a.is_empty() && !b.is_empty() {
        let take = stride.min(a.len());
        out.extend_from_slice(&a[..take]);
        a = &a[take..];
        std::mem::swap(&mut a, &mut b);
    }
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

pub async fn tcp_race_dial(
    ips: &[IpAddr],
    port: u16,
    config: &HappyEyeballsConfig,
    _domain: &str,
) -> Result<TcpStream> {
    if ips.is_empty() { return Err(Error::Other("at least 1 ip is required to dial".into())); }
    if ips.len() == 1 { return TcpStream::connect(SocketAddr::new(ips[0], port)).await.map_err(Error::Io); }
    let sorted = sort_ips(ips, config.prioritize_ipv6, config.interleave);
    let (tx, mut rx) = mpsc::channel(sorted.len());
    let cancelled = Arc::new(AtomicBool::new(false));
    let try_delay = Duration::from_millis(config.try_delay_ms);
    let max_concurrent = config.max_concurrent_try.max(1);
    let spawn_next = |ip: IpAddr, tx: mpsc::Sender<std::io::Result<TcpStream>>, cancelled: Arc<AtomicBool>| {
        tokio::spawn(async move {
            let res = TcpStream::connect(SocketAddr::new(ip, port)).await;
            if !cancelled.load(Ordering::Relaxed) { let _ = tx.send(res).await; }
        });
    };
    spawn_next(sorted[0], tx.clone(), cancelled.clone());
    let (mut next_idx, mut active) = (1usize, 1usize);
    let mut delay_fut = Box::pin(sleep(try_delay));
    loop {
        tokio::select! {
            Some(result) = rx.recv() => {
                active -= 1;
                match result {
                    Ok(conn) => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(conn);
                    }
                    Err(_) if next_idx < sorted.len() && active < max_concurrent => {
                        spawn_next(sorted[next_idx], tx.clone(), cancelled.clone());
                        active += 1;
                        next_idx += 1;
                        delay_fut = Box::pin(sleep(try_delay));
                    }
                    Err(e) if active == 0 => return Err(Error::Io(e)),
                    Err(_) => {}
                }
            }
            _ = &mut delay_fut, if next_idx < sorted.len() && active < max_concurrent => {
                spawn_next(sorted[next_idx], tx.clone(), cancelled.clone());
                active += 1;
                next_idx += 1;
                delay_fut = Box::pin(sleep(try_delay));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[test]
    fn test_sort_ips_rfc8305() {
        let v4_1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let v4_2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let v6_1 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
        let v6_2 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001));
        let ips = vec![v4_1, v4_2, v6_1, v6_2];
        let sorted = sort_ips(&ips, false, 1u32);
        assert_eq!(sorted, vec![v4_1, v6_1, v4_2, v6_2]);
        let sorted_v6 = sort_ips(&ips, true, 1u32);
        assert_eq!(sorted_v6, vec![v6_1, v4_1, v6_2, v4_2]);
        let sorted_int2 = sort_ips(&ips, false, 2u32);
        assert_eq!(sorted_int2, vec![v4_1, v4_2, v6_1, v6_2]);
        let no_interleave = sort_ips(&ips, false, false);
        assert_eq!(no_interleave, vec![v4_1, v4_2, v6_1, v6_2]);
    }
    #[tokio::test]
    async fn test_tcp_race_dial_single() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = HappyEyeballsConfig::default();
        let stream = tcp_race_dial(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], port, &cfg, "localhost").await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }
}

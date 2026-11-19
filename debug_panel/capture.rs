//! Debug-only Wireshark-style packet capture, L7 info dissection, Hex/ASCII dump,
//! and standard `.pcap` (LINKTYPE_RAW IPv4+TCP) exporter.
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_CAPTURED_PACKETS: usize = 500;
const MAX_PAYLOAD_STORE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[serde(rename = "C->S")]
    ClientToServer,
    #[serde(rename = "S->C")]
    ServerToClient,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::ClientToServer => "C->S",
            Direction::ServerToClient => "S->C",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub host: String,
    pub src: String,
    pub dst: String,
    pub direction: Direction,
    pub outbound: String,
    pub bypassed: bool,
    pub protocol: String,
    pub length: usize,
    pub captured_len: usize,
    pub info: String,
    pub hex_dump: String,
    #[serde(skip_serializing)]
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub enabled: bool,
    pub packet_count: usize,
    pub total_captured: u64,
    pub max_packets: usize,
    pub c2s_packets: u64,
    pub s2c_packets: u64,
    pub avg_packet_bytes: f64,
    pub size_buckets: SizeBuckets,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SizeBuckets {
    pub tiny_lt_100: u64,
    pub small_100_512: u64,
    pub medium_512_1400: u64,
    pub large_gt_1400: u64,
}

pub struct PacketCaptureStore {
    enabled: AtomicBool,
    seq_counter: AtomicU64,
    packets: RwLock<VecDeque<CapturedPacket>>,
}

impl Default for PacketCaptureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCaptureStore {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            seq_counter: AtomicU64::new(0),
            packets: RwLock::new(VecDeque::with_capacity(MAX_CAPTURED_PACKETS)),
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) -> CaptureStatus {
        self.enabled.store(on, Ordering::SeqCst);
        self.status()
    }

    pub fn clear(&self) {
        self.packets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.seq_counter.store(0, Ordering::SeqCst);
    }

    pub fn record_chunk(
        &self,
        host: &str,
        src: &str,
        dst: &str,
        direction: Direction,
        outbound: &str,
        bypassed: bool,
        data: &[u8],
    ) {
        if !self.is_enabled() || data.is_empty() {
            return;
        }
        let seq = self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let cap_len = data.len().min(MAX_PAYLOAD_STORE_BYTES);
        let raw_slice = &data[..cap_len];
        let (protocol, info) = dissect_l7(raw_slice, data.len(), direction);
        let hex_dump = format_hex_ascii(&data[..data.len().min(256)]);

        let pkt = CapturedPacket {
            seq,
            timestamp_ms: now_epoch_ms(),
            host: host.to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            direction,
            outbound: outbound.to_string(),
            bypassed,
            protocol,
            length: data.len(),
            captured_len: cap_len,
            info,
            hex_dump,
            raw_bytes: raw_slice.to_vec(),
        };

        let mut guard = self.packets.write().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= MAX_CAPTURED_PACKETS {
            guard.pop_front();
        }
        guard.push_back(pkt);
    }

    pub fn status(&self) -> CaptureStatus {
        let guard = self.packets.read().unwrap_or_else(|e| e.into_inner());
        let mut c2s = 0u64;
        let mut s2c = 0u64;
        let mut total_bytes = 0u64;
        let mut buckets = SizeBuckets::default();

        for p in guard.iter() {
            match p.direction {
                Direction::ClientToServer => c2s += 1,
                Direction::ServerToClient => s2c += 1,
            }
            total_bytes += p.length as u64;
            if p.length < 100 {
                buckets.tiny_lt_100 += 1;
            } else if p.length < 512 {
                buckets.small_100_512 += 1;
            } else if p.length <= 1400 {
                buckets.medium_512_1400 += 1;
            } else {
                buckets.large_gt_1400 += 1;
            }
        }
        let avg = if !guard.is_empty() {
            ((total_bytes as f64 / guard.len() as f64) * 100.0).round() / 100.0
        } else {
            0.0
        };

        CaptureStatus {
            enabled: self.is_enabled(),
            packet_count: guard.len(),
            total_captured: self.seq_counter.load(Ordering::Relaxed),
            max_packets: MAX_CAPTURED_PACKETS,
            c2s_packets: c2s,
            s2c_packets: s2c,
            avg_packet_bytes: avg,
            size_buckets: buckets,
        }
    }

    pub fn packets(&self, host_filter: Option<&str>, limit: usize) -> Vec<CapturedPacket> {
        let guard = self.packets.read().unwrap_or_else(|e| e.into_inner());
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());
        guard
            .iter()
            .rev()
            .filter(|p| match &filter_lc {
                Some(f) if !f.is_empty() => p.host.to_ascii_lowercase().contains(f),
                _ => true,
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Export captured packets as a standard Wireshark `.pcap` file (LINKTYPE_RAW = 101, IPv4 + TCP).
    pub fn export_pcap(&self, host_filter: Option<&str>) -> Vec<u8> {
        let guard = self.packets.read().unwrap_or_else(|e| e.into_inner());
        let filter_lc = host_filter.map(|s| s.to_ascii_lowercase());

        let mut out = Vec::with_capacity(64 * 1024);
        // PCAP Global Header (24 bytes, little-endian)
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
        out.extend_from_slice(&2u16.to_le_bytes()); // major version
        out.extend_from_slice(&4u16.to_le_bytes()); // minor version
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&101u32.to_le_bytes()); // LINKTYPE_RAW (Raw IPv4/IPv6)

        // Maintain synthetic TCP sequence numbers per (host, direction) so Wireshark can follow streams
        let mut seq_map: HashMap<(String, u8), u32> = HashMap::new();

        for pkt in guard.iter() {
            if let Some(f) = &filter_lc
                && !f.is_empty()
                && !pkt.host.to_ascii_lowercase().contains(f)
            {
                continue;
            }

            let (src_ip, src_port) = parse_ipv4_port(&pkt.src, Ipv4Addr::new(127, 0, 0, 1), 50000);
            let (dst_ip, dst_port) = parse_ipv4_port(&pkt.dst, hash_host_to_ip(&pkt.host), 443);

            let (ip_s, port_s, ip_d, port_d, dir_key) = match pkt.direction {
                Direction::ClientToServer => (src_ip, src_port, dst_ip, dst_port, 0u8),
                Direction::ServerToClient => (dst_ip, dst_port, src_ip, src_port, 1u8),
            };

            let tcp_seq = *seq_map
                .entry((pkt.host.clone(), dir_key))
                .or_insert(1);
            let tcp_ack = *seq_map
                .entry((pkt.host.clone(), 1 - dir_key))
                .or_insert(1);

            let payload = &pkt.raw_bytes;
            let frame = build_ipv4_tcp_packet(ip_s, port_s, ip_d, port_d, tcp_seq, tcp_ack, payload);

            *seq_map.entry((pkt.host.clone(), dir_key)).or_insert(1) =
                tcp_seq.wrapping_add(payload.len() as u32);

            let ts_sec = (pkt.timestamp_ms / 1000) as u32;
            let ts_usec = ((pkt.timestamp_ms % 1000) * 1000) as u32;
            let incl_len = frame.len() as u32;
            let orig_len = (40 + pkt.length) as u32;

            // PCAP Packet Record Header (16 bytes)
            out.extend_from_slice(&ts_sec.to_le_bytes());
            out.extend_from_slice(&ts_usec.to_le_bytes());
            out.extend_from_slice(&incl_len.to_le_bytes());
            out.extend_from_slice(&orig_len.to_le_bytes());
            out.extend_from_slice(&frame);
        }

        out
    }
}

fn dissect_l7(data: &[u8], full_len: usize, dir: Direction) -> (String, String) {
    if data.len() >= 5 {
        // TLS Record Header: ContentType 20..=23, Version 0x03 0x00..=0x04
        if (20..=23).contains(&data[0]) && data[1] == 0x03 && data[2] <= 0x04 {
            let rec_len = u16::from_be_bytes([data[3], data[4]]);
            let info = match data[0] {
                20 => format!("Change Cipher Spec (rec={}B, total={}B)", rec_len, full_len),
                21 => format!("Alert (rec={}B)", rec_len),
                22 => {
                    let hs = data.get(5).copied().unwrap_or(0);
                    match hs {
                        1 => {
                            let feat = crate::debug_panel::inspect_initial_payload(data);
                            format!("Client Hello ({})", feat.summary)
                        }
                        2 => format!("Server Hello (rec={}B, total={}B)", rec_len, full_len),
                        11 => format!("Certificate (rec={}B, total={}B)", rec_len, full_len),
                        _ => format!("Handshake type=0x{:02x} (rec={}B, total={}B)", hs, rec_len, full_len),
                    }
                }
                23 => format!("Application Data (rec={}B, total={}B)", rec_len, full_len),
                _ => format!("TLS record (total={}B)", full_len),
            };
            return ("TLS".into(), info);
        }
    }

    if let Ok(text) = std::str::from_utf8(&data[..data.len().min(256)]) {
        let first_line = text.lines().next().unwrap_or("").trim();
        let is_http_req = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "]
            .iter()
            .any(|m| first_line.starts_with(m));
        if is_http_req || first_line.starts_with("HTTP/") {
            let preview: String = first_line.chars().take(80).collect();
            return ("HTTP".into(), format!("{} ({}B)", preview, full_len));
        }
    }

    (
        "TCP".into(),
        format!(
            "{} payload {}B (head={:02x?})",
            dir.as_str(),
            full_len,
            &data[..data.len().min(8)]
        ),
    )
}

fn format_hex_ascii(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:04x}  ", i * 16));
        for j in 0..16 {
            if let Some(b) = chunk.get(j) {
                out.push_str(&format!("{:02x} ", b));
            } else {
                out.push_str("   ");
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        for &b in chunk {
            let c = if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('\n');
    }
    out
}

fn parse_ipv4_port(s: &str, default_ip: Ipv4Addr, default_port: u16) -> (Ipv4Addr, u16) {
    if let Ok(sa) = s.parse::<std::net::SocketAddrV4>() {
        return (*sa.ip(), sa.port());
    }
    if let Some((h, p)) = s.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        if let Ok(ip) = h.parse::<Ipv4Addr>() {
            return (ip, port);
        }
        return (default_ip, port);
    }
    (default_ip, default_port)
}

fn hash_host_to_ip(host: &str) -> Ipv4Addr {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    host.hash(&mut hasher);
    let h = hasher.finish();
    // Deterministic RFC 5737 / 198.18.0.0/15 benchmark synthetic IP for domain-only destinations
    Ipv4Addr::new(198, 18, ((h >> 8) & 0xff) as u8, ((h & 0xfe) as u8) | 1)
}

fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 20 + payload.len()).min(u16::MAX as usize) as u16;
    let payload_len = (total_len as usize).saturating_sub(40);
    let mut pkt = Vec::with_capacity(total_len as usize);

    // IPv4 Header (20 bytes)
    pkt.push(0x45); // Version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Identification
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    pkt.push(64); // TTL
    pkt.push(6); // Protocol = TCP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    let ip_csum = internet_checksum(&pkt[0..20]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = (ip_csum & 0xff) as u8;

    // TCP Header (20 bytes)
    let tcp_start = pkt.len();
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ack.to_be_bytes());
    pkt.push(0x50); // Data offset = 5 (20 bytes)
    pkt.push(0x18); // PSH + ACK
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // Window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Urgent ptr
    pkt.extend_from_slice(&payload[..payload_len]);

    let tcp_csum = tcp_checksum(src_ip, dst_ip, &pkt[tcp_start..]);
    pkt[tcp_start + 16] = (tcp_csum >> 8) as u8;
    pkt[tcp_start + 17] = (tcp_csum & 0xff) as u8;

    pkt
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let s = src_ip.octets();
    let d = dst_ip.octets();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += 6u32; // TCP protocol
    sum += tcp_segment.len() as u32;

    let mut chunks = tcp_segment.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

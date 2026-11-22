use super::config::XIcmpConfig;
use crate::common::errors::{Error, Result};
use std::collections::HashMap;

pub const ICMP_TYPE_ECHO_V4: u8 = 8;
pub const ICMP_TYPE_ECHO_REPLY_V4: u8 = 0;
pub const ICMP_TYPE_ECHO_V6: u8 = 128;
pub const ICMP_TYPE_ECHO_REPLY_V6: u8 = 129;

pub const WINDOW_SIZE: u16 = 1000;

#[derive(Debug, Clone, Copy)]
pub struct SeqStatus {
    pub need_seq_byte: bool,
    pub seq_byte: u8,
}

pub struct XIcmpClient {
    pub config: XIcmpConfig,
    pub id: u16,
    pub seq: u16,
    pub is_ipv6: bool,
    seq_status: HashMap<u16, SeqStatus>,
}

impl XIcmpClient {
    pub fn new(config: XIcmpConfig) -> Self {
        let is_ipv6 = config.ip.contains(':');
        let id = if config.id != 0 {
            config.id
        } else {
            rand::random::<u16>()
        };
        let seq = if config.sequence != 0 {
            config.sequence
        } else {
            1
        };
        Self {
            config,
            id,
            seq,
            is_ipv6,
            seq_status: HashMap::new(),
        }
    }

    pub fn wrap_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        self.encode_request(Some(payload)).unwrap_or_default()
    }

    pub fn encode_request(&mut self, payload: Option<&[u8]>) -> Result<Vec<u8>> {
        let (need_seq_byte, seq_byte) = match payload {
            Some(p) if !p.is_empty() => (true, p[0]),
            _ => (false, 0),
        };

        let typ = if self.is_ipv6 {
            ICMP_TYPE_ECHO_V6
        } else {
            ICMP_TYPE_ECHO_V4
        };

        let data = payload.unwrap_or(&[]);
        let mut pkt = Vec::with_capacity(8 + data.len());
        pkt.push(typ);
        pkt.push(0);
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&self.id.to_be_bytes());
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        pkt.extend_from_slice(data);

        let csum = calculate_checksum(&pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());

        self.seq_status.insert(
            self.seq,
            SeqStatus {
                need_seq_byte,
                seq_byte,
            },
        );

        let old_seq = self.seq.wrapping_sub(WINDOW_SIZE);
        self.seq_status.remove(&old_seq);

        if self.seq == 65535 {
            self.seq = 1;
        } else {
            self.seq += 1;
        }

        Ok(pkt)
    }

    pub fn unwrap_packet(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        self.decode_reply(packet).ok().flatten()
    }

    pub fn decode_reply(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if packet.len() < 8 {
            return Err(Error::Protocol("ICMP packet too short (< 8 bytes)".into()));
        }
        if packet[1] != 0 {
            return Err(Error::Protocol("ICMP reply code non-zero".into()));
        }
        let expected_typ = if self.is_ipv6 { ICMP_TYPE_ECHO_REPLY_V6 } else { ICMP_TYPE_ECHO_REPLY_V4 };
        if packet[0] != expected_typ {
            return Err(Error::Protocol(format!("ICMP type mismatch: expected reply {}, got {}", expected_typ, packet[0])));
        }
        if !verify_checksum(packet) {
            return Err(Error::Protocol("ICMP checksum verification failed".into()));
        }
        if u16::from_be_bytes([packet[4], packet[5]]) != self.id {
            return Ok(None);
        }
        let Some(status) = self.seq_status.remove(&u16::from_be_bytes([packet[6], packet[7]])) else {
            return Ok(None);
        };
        let mut data = &packet[8..];
        if status.need_seq_byte {
            if data.len() <= 1 || data[0] == status.seq_byte {
                return Ok(None);
            }
            data = &data[1..];
        }
        Ok((!data.is_empty()).then(|| data.to_vec()))
    }
}

pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn verify_checksum(data: &[u8]) -> bool {
    calculate_checksum(data) == 0
}

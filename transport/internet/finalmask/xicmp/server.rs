use super::client::{
    ICMP_TYPE_ECHO_REPLY_V4, ICMP_TYPE_ECHO_REPLY_V6, ICMP_TYPE_ECHO_V4, ICMP_TYPE_ECHO_V6,
    calculate_checksum, verify_checksum,
};
use super::config::XIcmpConfig;
use crate::common::errors::{Error, Result};

#[derive(Debug, Clone)]
pub struct XIcmpServerRequest {
    pub id: u16,
    pub seq: u16,
    pub need_seq_byte: bool,
    pub seq_byte: u8,
    pub payload: Vec<u8>,
}

pub struct XIcmpServer {
    pub config: XIcmpConfig,
    pub is_ipv6: bool,
}

impl XIcmpServer {
    pub fn new(config: XIcmpConfig) -> Self {
        let is_ipv6 = config.ip.contains(':');
        Self { config, is_ipv6 }
    }

    pub fn unwrap_packet<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        if packet.len() < 8 {
            return None;
        }
        let icmp_type = packet[0];
        if icmp_type != ICMP_TYPE_ECHO_V4
            && icmp_type != ICMP_TYPE_ECHO_REPLY_V4
            && icmp_type != ICMP_TYPE_ECHO_V6
            && icmp_type != ICMP_TYPE_ECHO_REPLY_V6
        {
            return None;
        }
        Some(&packet[8..])
    }

    pub fn decode_request(&self, packet: &[u8]) -> Result<Option<XIcmpServerRequest>> {
        if packet.len() < 8 { return Err(Error::Protocol("ICMP request too short (< 8 bytes)".into())); }
        if packet[1] != 0 { return Err(Error::Protocol("ICMP request code non-zero".into())); }
        if packet[0] != if self.is_ipv6 { ICMP_TYPE_ECHO_V6 } else { ICMP_TYPE_ECHO_V4 } { return Ok(None); }
        if !verify_checksum(packet) { return Err(Error::Protocol("ICMP request checksum invalid".into())); }
        let id = u16::from_be_bytes([packet[4], packet[5]]);
        if self.config.id != 0 && id != self.config.id { return Ok(None); }
        let (seq, data) = (u16::from_be_bytes([packet[6], packet[7]]), &packet[8..]);
        Ok(Some(XIcmpServerRequest {
            id, seq, need_seq_byte: !data.is_empty(), seq_byte: data.first().copied().unwrap_or(0), payload: data.to_vec(),
        }))
    }

    pub fn encode_reply(
        &self,
        req: &XIcmpServerRequest,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let typ = if self.is_ipv6 {
            ICMP_TYPE_ECHO_REPLY_V6
        } else {
            ICMP_TYPE_ECHO_REPLY_V4
        };

        let mut data = Vec::new();
        if req.need_seq_byte {
            let mut b2 = rand::random::<u8>();
            while b2 == req.seq_byte {
                b2 = rand::random::<u8>();
            }
            data.push(b2);
        }

        if let Some(p) = payload {
            data.extend_from_slice(p);
        }

        let mut pkt = Vec::with_capacity(8 + data.len());
        pkt.push(typ);
        pkt.push(0);
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&req.id.to_be_bytes());
        pkt.extend_from_slice(&req.seq.to_be_bytes());
        pkt.extend_from_slice(&data);

        let csum = calculate_checksum(&pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());

        Ok(pkt)
    }
}

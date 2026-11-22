use super::dns::{
    CLASS_IN, Message, Name, Question, RCODE_NO_ERROR, RR_TYPE_OPT, RR_TYPE_TXT, ResourceRecord,
    base32_encode, decode_rdata_txt,
};
use crate::common::errors::{Error, Result};
use rand::RngCore;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const NUM_PADDING: usize = 3;
pub const NUM_PADDING_FOR_POLL: usize = 8;
pub const MAX_PAYLOAD_LEN: usize = 224;

#[derive(Clone)]
pub struct XDnsClient {
    pub client_id: [u8; 8],
    pub domain: Name,
    closed: Arc<AtomicBool>,
}

impl XDnsClient {
    pub fn new(domain_str: &str) -> Result<Self> {
        let mut client_id = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut client_id);
        let domain = Name::parse(domain_str)?;
        Ok(Self {
            client_id,
            domain,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn from_config(config: &super::config::XDnsConfig) -> Result<Self> {
        Self::new(&config.domain)
    }

    pub fn new_with_id(domain_str: &str, client_id: [u8; 8]) -> Result<Self> {
        let domain = Name::parse(domain_str)?;
        Ok(Self {
            client_id,
            domain,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn encode_packet(&self, payload: Option<&[u8]>) -> Result<Vec<u8>> {
        if payload.is_some_and(|p| p.len() >= MAX_PAYLOAD_LEN) {
            return Err(Error::Protocol("payload too long for xdns query (>= 224 bytes)".into()));
        }

        let mut decoded = Vec::with_capacity(32 + payload.map_or(0, <[u8]>::len));
        decoded.extend_from_slice(&self.client_id);
        let n = if payload.is_some_and(|p| !p.is_empty()) { NUM_PADDING } else { NUM_PADDING_FOR_POLL };
        decoded.push((224 + n) as u8);
        let pad_start = decoded.len();
        decoded.resize(pad_start + n, 0);
        rand::thread_rng().fill_bytes(&mut decoded[pad_start..]);

        if let Some(p) = payload.filter(|p| !p.is_empty()) {
            decoded.push(p.len() as u8);
            decoded.extend_from_slice(p);
        }

        let base32_str = base32_encode(&decoded).to_ascii_lowercase();
        let mut labels: Vec<Vec<u8>> = base32_str.as_bytes().chunks(63).map(<[u8]>::to_vec).collect();
        labels.extend(self.domain.labels.clone());

        Message {
            id: rand::random(),
            flags: 0x0100,
            questions: vec![Question { name: Name::new(labels)?, qtype: RR_TYPE_TXT, qclass: CLASS_IN }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: vec![ResourceRecord {
                name: Name::default(),
                rrtype: RR_TYPE_OPT,
                class: 4096,
                ttl: 0,
                data: Vec::new(),
            }],
        }
        .to_wire_format()
    }

    pub fn decode_packet(&self, wire: &[u8]) -> Result<Vec<Vec<u8>>> {
        let resp = Message::from_wire_format(wire)?;

        if (resp.flags & 0x8000) != 0x8000 || (resp.flags & 0x000F) != RCODE_NO_ERROR {
            return Err(Error::Protocol("DNS response flag or rcode invalid".into()));
        }

        if resp.answers.len() != 1 {
            return Err(Error::Protocol(
                "DNS response must contain exactly 1 answer".into(),
            ));
        }

        let answer = &resp.answers[0];
        if answer.name.trim_suffix(&self.domain).is_none() {
            return Err(Error::Protocol(
                "DNS response name suffix does not match configured domain".into(),
            ));
        }

        if answer.rrtype != RR_TYPE_TXT {
            return Err(Error::Protocol(
                "DNS response answer type is not TXT".into(),
            ));
        }

        let payload = decode_rdata_txt(&answer.data)?;
        let mut packets = Vec::new();
        let mut offset = 0;

        while offset + 2 <= payload.len() {
            let n = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            if offset + n > payload.len() {
                return Err(Error::Protocol(
                    "unexpected eof in DNS response subpacket stream".into(),
                ));
            }
            packets.push(payload[offset..offset + n].to_vec());
            offset += n;
        }

        Ok(packets)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

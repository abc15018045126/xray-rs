use super::dns::{
    EXTENDED_RCODE_BAD_VERS, Message, Name, RCODE_FORMAT_ERROR, RCODE_NAME_ERROR, RCODE_NO_ERROR,
    RCODE_NOT_IMPLEMENTED, RR_TYPE_OPT, RR_TYPE_TXT, ResourceRecord, base32_decode,
    encode_rdata_txt,
};
use crate::common::errors::{Error, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const RESPONSE_TTL: u32 = 60;
pub const MAX_UDP_PAYLOAD: usize = 1280 - 40 - 8;

#[derive(Debug, Clone)]
pub struct XDnsServerQuery {
    pub client_id: [u8; 8],
    pub packets: Vec<Vec<u8>>,
    pub rcode: u16,
}

#[derive(Clone)]
pub struct XDnsServer {
    pub domain: Name,
    closed: Arc<AtomicBool>,
}

impl XDnsServer {
    pub fn new(domain_str: &str) -> Result<Self> {
        let domain = Name::parse(domain_str)?;
        Ok(Self {
            domain,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn from_config(config: &super::config::XDnsConfig) -> Result<Self> { Self::new(&config.domain) }
    pub fn client_id_to_addr(client_id: &[u8; 8]) -> [u8; 16] {
        let mut ip = [0u8; 16];
        ip[0] = 0xfd;
        ip[8..16].copy_from_slice(client_id);
        ip
    }
    pub fn decode_query(&self, wire: &[u8]) -> Result<(XDnsServerQuery, Message)> {
        let query = Message::from_wire_format(wire)?;
        if (query.flags & 0x8000) != 0 {
            return Err(Error::Protocol("incoming message is a DNS response, not a query".into()));
        }
        let mut resp = Message {
            id: query.id,
            flags: 0x8000,
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };
        let err_resp = |mut resp: Message, rcode: u16| {
            resp.flags |= rcode;
            Ok((XDnsServerQuery { client_id: [0u8; 8], packets: Vec::new(), rcode }, resp))
        };
        let mut payload_size = 512usize;
        for rr in query.additional.iter().filter(|rr| rr.rrtype == RR_TYPE_OPT) {
            if !resp.additional.is_empty() { return err_resp(resp, RCODE_FORMAT_ERROR); }
            let mut opt_rr = ResourceRecord {
                name: Name::default(),
                rrtype: RR_TYPE_OPT,
                class: 4096,
                ttl: 0,
                data: Vec::new(),
            };
            if ((rr.ttl >> 16) & 0xff) != 0 {
                opt_rr.ttl = ((EXTENDED_RCODE_BAD_VERS as u32) >> 4) << 24;
                resp.additional.push(opt_rr);
                return err_resp(resp, EXTENDED_RCODE_BAD_VERS & 0x0f);
            }
            payload_size = payload_size.max(rr.class as usize);
            resp.additional.push(opt_rr);
        }
        if query.questions.len() != 1 { return err_resp(resp, RCODE_FORMAT_ERROR); }
        let question = &query.questions[0];
        let Some(prefix) = question.name.trim_suffix(&self.domain) else { return err_resp(resp, RCODE_NAME_ERROR); };
        resp.flags |= 0x0400;
        if query.opcode() != 0 { return err_resp(resp, RCODE_NOT_IMPLEMENTED); }
        if question.qtype != RR_TYPE_TXT { return err_resp(resp, RCODE_NAME_ERROR); }
        let concat: String = prefix.labels.iter().map(|l| String::from_utf8_lossy(l).to_ascii_uppercase()).collect();
        let Ok(payload) = base32_decode(&concat) else { return err_resp(resp, RCODE_NAME_ERROR); };
        if payload.len() < 8 { return err_resp(resp, RCODE_NAME_ERROR); }
        let mut client_id = [0u8; 8];
        client_id.copy_from_slice(&payload[..8]);
        let mut packets = Vec::new();
        let mut offset = 8;
        while offset < payload.len() {
            let b = payload[offset];
            offset += 1;
            if b >= 224 {
                offset += (b - 224) as usize;
            } else {
                let pkt_len = b as usize;
                if offset + pkt_len > payload.len() { break; }
                packets.push(payload[offset..offset + pkt_len].to_vec());
                offset += pkt_len;
            }
        }
        let rcode = if payload_size < MAX_UDP_PAYLOAD {
            resp.flags |= RCODE_FORMAT_ERROR;
            RCODE_FORMAT_ERROR
        } else {
            RCODE_NO_ERROR
        };
        Ok((XDnsServerQuery { client_id, packets, rcode }, resp))
    }
    pub fn encode_response(&self, resp: &mut Message, outgoing_packets: &[&[u8]]) -> Result<Vec<u8>> {
        if resp.rcode() == RCODE_NO_ERROR && resp.questions.len() == 1 {
            let mut payload = Vec::new();
            for pkt in outgoing_packets.iter().filter(|p| p.len() <= 65535) {
                payload.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
                payload.extend_from_slice(pkt);
            }
            let q = &resp.questions[0];
            resp.answers = vec![ResourceRecord {
                name: q.name.clone(), rrtype: q.qtype, class: q.qclass, ttl: RESPONSE_TTL, data: encode_rdata_txt(&payload),
            }];
        }
        let mut wire = resp.to_wire_format()?;
        if wire.len() > MAX_UDP_PAYLOAD { wire.truncate(MAX_UDP_PAYLOAD); wire[2] |= 0x02; }
        Ok(wire)
    }
    pub fn close(&self) { self.closed.store(true, Ordering::SeqCst); }
    pub fn is_closed(&self) -> bool { self.closed.load(Ordering::SeqCst) }
}

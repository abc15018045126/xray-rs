use crate::app::dns::fakedns::FakeDnsHolder;
use crate::common::errors::{Error, Result};
use crate::common::net::Network;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffResult {
    pub protocol: String,
    pub domain: String,
}

impl SniffResult {
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn composite_result(domain_res: SniffResult, proto_res: SniffResult) -> Self {
        Self {
            protocol: proto_res.protocol,
            domain: domain_res.domain,
        }
    }
}

pub struct Sniffer {
    fakedns: Option<Arc<FakeDnsHolder>>,
}

impl Sniffer {
    pub fn new(fakedns: Option<Arc<FakeDnsHolder>>) -> Self {
        Self { fakedns }
    }

    pub fn new_sniffer(fakedns: Option<Arc<FakeDnsHolder>>) -> Self {
        Self::new(fakedns)
    }

    pub fn sniff_metadata(&self, ip: IpAddr) -> Option<SniffResult> {
        self.sniff_ip(ip).map(|domain| SniffResult {
            protocol: "fakedns".into(),
            domain,
        })
    }

    pub fn sniff_ip(&self, ip: IpAddr) -> Option<String> {
        if let Some(fdns) = &self.fakedns {
            match ip {
                IpAddr::V4(ref v4) => fdns.get_domain_for_fake_ip(v4),
                IpAddr::V6(_) => None,
            }
        } else {
            None
        }
    }

    pub fn is_in_fake_ip_pool(&self, ip: &IpAddr) -> bool {
        if let Some(fdns) = &self.fakedns {
            fdns.is_fake_ip(ip)
        } else {
            false
        }
    }

    pub fn sniff(&self, payload: &[u8], network: Network) -> Result<SniffResult> {
        if network == Network::Tcp
            && payload.len() >= 5
            && payload[0] == 0x16
            && payload[1] == 0x03
            && let Some(domain) = Self::sniff_tls_sni(payload)
        {
            return Ok(SniffResult {
                protocol: "tls".into(),
                domain,
            });
        }

        if network == Network::Tcp
            && payload.len() >= 10
            && let Some(domain) = Self::sniff_http_host(payload)
        {
            return Ok(SniffResult {
                protocol: "http".into(),
                domain,
            });
        }

        if network == Network::Udp
            && payload.len() >= 12
            && let Some(domain) = Self::sniff_quic_sni(payload)
        {
            return Ok(SniffResult {
                protocol: "quic".into(),
                domain,
            });
        }

        if let Ok(proto) = crate::common::protocol::bittorrent::BittorrentSniffer::sniff(payload) {
            return Ok(SniffResult {
                protocol: proto,
                domain: String::new(),
            });
        }

        Err(Error::Protocol("unknown content".into()))
    }

    pub fn sniff_tls_sni(payload: &[u8]) -> Option<String> {
        let u16_be = |i: usize| u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
        if payload.len() < 43 || payload[5] != 0x01 {
            return None;
        }
        let mut pos = 43;
        if pos >= payload.len() {
            return None;
        }
        pos += 1 + payload[pos] as usize;
        if pos + 2 > payload.len() {
            return None;
        }
        pos += 2 + u16_be(pos);
        if pos + 1 > payload.len() {
            return None;
        }
        pos += 1 + payload[pos] as usize;
        if pos + 2 > payload.len() {
            return None;
        }
        let end_ext = (pos + 2 + u16_be(pos)).min(payload.len());
        pos += 2;

        while pos + 4 <= end_ext {
            let (ext_type, ext_len) = (u16_be(pos), u16_be(pos + 2));
            pos += 4;
            if ext_type == 0x0000 && pos + 5 <= end_ext && payload[pos + 2] == 0 {
                let nlen = u16_be(pos + 3);
                if pos + 5 + nlen <= end_ext {
                    return std::str::from_utf8(&payload[pos + 5..pos + 5 + nlen]).ok().map(str::to_string);
                }
            }
            pos += ext_len;
        }
        None
    }

    pub fn sniff_http_host(payload: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(payload).ok()?;
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                let host = line[5..].trim();
                let domain = host.split(':').next()?.trim();
                if !domain.is_empty() {
                    return Some(domain.to_string());
                }
            }
        }
        None
    }

    pub fn sniff_quic_sni(payload: &[u8]) -> Option<String> {
        if payload.len() > 100 && (payload[0] & 0x80 != 0) {
            return Self::sniff_tls_sni(&payload[40..]);
        }
        None
    }
}

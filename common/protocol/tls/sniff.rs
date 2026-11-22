use crate::common::errors::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSniffHeader {
    pub domain: String,
}

impl TlsSniffHeader {
    pub fn protocol(&self) -> &'static str { "tls" }
    pub fn domain(&self) -> &str { &self.domain }
}

pub fn sniff_tls(b: &[u8]) -> Result<TlsSniffHeader> {
    if b.len() < 5 { return Err(Error::Protocol("TLS payload too short".into())); }
    if b[0] != 0x16
    /* TLS Handshake */
    { return Err(Error::Protocol("not TLS handshake".into())); }
    let major = b[1];
    if major != 3 { return Err(Error::Protocol("not valid TLS version".into())); }
    let header_len = u16::from_be_bytes([b[3], b[4]]) as usize;
    if 5 + header_len > b.len() { return Err(Error::Protocol("incomplete TLS record".into())); }
    let data = &b[5..5 + header_len];
    let domain = read_client_hello(data)?;
    Ok(TlsSniffHeader { domain })
}

pub fn read_client_hello(mut data: &[u8]) -> Result<String> {
    let err = |m: &str| Error::Protocol(m.into());
    let u16_be = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]) as usize;
    if data.len() < 42 { return Err(err("client hello too short")); }
    let sid_len = data[38] as usize;
    if sid_len > 32 || data.len() < 39 + sid_len { return Err(err("invalid session id len")); }
    data = &data[39 + sid_len..];
    if data.len() < 2 { return Err(err("no cipher suite len")); }
    let cs_len = u16_be(data);
    data = data.get(2 + cs_len..).ok_or_else(|| err("invalid cipher suite len"))?;
    let comp_len = *data.first().ok_or_else(|| err("no compression method len"))? as usize;
    data = data.get(1 + comp_len..).ok_or_else(|| err("invalid compression method len"))?;
    if data.len() < 2 { return Err(err("no extensions len")); }
    let ext_len = u16_be(data);
    data = &data[2..];
    if ext_len != data.len() { return Err(err("extensions length mismatch")); }
    while data.len() >= 4 {
        let (ext_type, len) = (u16_be(data), u16_be(&data[2..]));
        data = &data[4..];
        if data.len() < len { return Err(err("extension truncated")); }
        if ext_type == 0x00 {
            let mut sni = &data[..len];
            if sni.len() < 2 { return Err(err("sni data too short")); }
            let names_len = u16_be(sni);
            sni = &sni[2..];
            if sni.len() < names_len { return Err(err("sni names len mismatch")); }
            while sni.len() >= 3 {
                let (ntype, nlen) = (sni[0], u16_be(&sni[1..]));
                sni = &sni[3..];
                if sni.len() < nlen { return Err(err("sni name truncated")); }
                if ntype == 0 {
                    return Ok(std::str::from_utf8(&sni[..nlen]).map_err(|_| err("invalid utf8 sni"))?.to_string());
                }
                sni = &sni[nlen..];
            }
        }
        data = &data[len..];
    }
    Err(err("SNI extension not found"))
}

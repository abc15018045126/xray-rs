use crate::common::errors::{Error, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl Certificate {
    pub fn new(certificate: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            certificate,
            private_key,
        }
    }
    pub fn sha256_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.certificate);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }
    pub fn to_pem(&self) -> (String, String) {
        let enc = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        (
            format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", enc(&self.certificate)),
            format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", enc(&self.private_key)),
        )
    }
}

pub fn parse_certificate(cert_pem: &str, key_pem: &str) -> Result<Certificate> {
    let dec = |pem: &str| {
        let b64: String = pem.lines().map(str::trim).filter(|l| !l.starts_with("-----")).collect();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .map_err(|e| Error::Protocol(format!("failed to decode pem base64: {}", e)))
    };
    Ok(Certificate::new(dec(cert_pem)?, dec(key_pem)?))
}

use sha2::{Digest, Sha256};

pub fn generate_cert_hash(raw_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_der);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn generate_cert_hash_hex(raw_der: &[u8]) -> String {
    let hash = generate_cert_hash(raw_der);
    hex::encode(hash)
}

pub fn verify_peer_cert(raw_certs: &[&[u8]], pinned_hashes: &[[u8; 32]]) -> bool {
    if pinned_hashes.is_empty() { return true; }
    for cert in raw_certs {
        let hash = generate_cert_hash(cert);
        for pinned in pinned_hashes { if &hash == pinned { return true; } }
    }
    false
}

pub fn verify_peer_cert_hex(raw_certs: &[&[u8]], pinned_hex_hashes: &[String]) -> bool {
    if pinned_hex_hashes.is_empty() { return true; }
    for cert in raw_certs {
        let hex_hash = generate_cert_hash_hex(cert);
        for pinned in pinned_hex_hashes { if hex_hash.eq_ignore_ascii_case(pinned) { return true; } }
    }
    false
}

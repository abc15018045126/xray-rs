use super::config::*;

pub struct CipherValidator;

impl CipherValidator {
    pub fn is_valid_method(method: &str) -> bool {
        matches!(
            method,
            CIPHER_2022_BLAKE3_AES_128_GCM
                | CIPHER_2022_BLAKE3_AES_256_GCM
                | CIPHER_2022_BLAKE3_CHACHA20_POLY1305
        )
    }
}

pub mod aes;
pub mod auth;
pub mod chacha20;
pub mod chunk;
pub mod crypto;
pub mod internal;
pub mod io;

#[cfg(test)]
pub mod aes_test;
#[cfg(test)]
pub mod auth_test;
#[cfg(test)]
pub mod benchmark_test;
#[cfg(test)]
pub mod chacha20_test;
#[cfg(test)]
pub mod chunk_test;
#[cfg(test)]
pub mod io_test;

pub use aes::{new_aes_gcm, AesGcmCipher};
pub use auth::Authentication;
pub use chacha20::ChaCha20Cipher;
pub use chunk::{
    AeadChaCha20ChunkReader, AeadChaCha20ChunkWriter, IncreasingNonce, PlainChunk,
};
pub use crypto::{rand_between, rand_bytes_between, StreamCipher};
pub use internal::chacha::ChaChaCore;
pub use io::{xor_buffers, CryptionReader, CryptionWriter};

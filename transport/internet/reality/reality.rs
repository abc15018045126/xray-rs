use super::config::RealityConfig;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::transport::internet::tls::TlsServer;
use crate::transport::internet::websocket::ws::PrefixedStream;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub fn decode_reality_key32(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed)
            .map_err(|e| Error::Config(format!("Invalid REALITY hex key: {}", e)))?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(trimmed.trim_end_matches('='))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
            .map_err(|e| Error::Config(format!("Invalid REALITY key (base64url/hex): {}", e)))?
    };
    if bytes.len() != 32 {
        return Err(Error::Config(format!(
            "REALITY key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityAuthSession {
    pub version: (u8, u8, u8),
    pub timestamp: u32,
    pub short_id: Vec<u8>,
}

pub fn derive_auth_key(shared_secret: &[u8; 32], random_salt_20: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(random_salt_20), shared_secret);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .expect("32 bytes is valid length for HKDF-SHA256");
    auth_key
}

pub fn seal_session_id(
    auth_key: &[u8; 32],
    nonce_12: &[u8],
    version: (u8, u8, u8),
    timestamp: u32,
    short_id: &[u8],
    client_hello_raw: &[u8],
) -> Result<[u8; 32]> {
    let mut pt = [0u8; 16];
    pt[0] = version.0;
    pt[1] = version.1;
    pt[2] = version.2;
    pt[3] = 0;
    pt[4..8].copy_from_slice(&timestamp.to_be_bytes());

    let sid_len = std::cmp::min(8, short_id.len());
    pt[8..8 + sid_len].copy_from_slice(&short_id[..sid_len]);

    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|e| Error::Protocol(format!("Invalid AES-GCM key: {:?}", e)))?;
    let nonce = Nonce::from_slice(nonce_12);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &pt,
                aad: client_hello_raw,
            },
        )
        .map_err(|e| Error::Protocol(format!("REALITY SessionId seal error: {:?}", e)))?;

    if ciphertext.len() != 32 {
        return Err(Error::Protocol("Sealed session ID must be 32 bytes".into()));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_session_id(
    auth_key: &[u8; 32],
    nonce_12: &[u8],
    sealed_session_id: &[u8; 32],
    client_hello_raw: &[u8],
) -> Result<RealityAuthSession> {
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|e| Error::Protocol(format!("Invalid AES-GCM key: {:?}", e)))?;
    let nonce = Nonce::from_slice(nonce_12);

    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: sealed_session_id,
                aad: client_hello_raw,
            },
        )
        .map_err(|e| Error::Protocol(format!("REALITY SessionId open auth error: {:?}", e)))?;

    if pt.len() != 16 {
        return Err(Error::Protocol(
            "Decrypted session plaintext must be 16 bytes".into(),
        ));
    }

    let version = (pt[0], pt[1], pt[2]);
    let timestamp = u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]);
    let short_id = pt[8..16].to_vec();

    Ok(RealityAuthSession {
        version,
        timestamp,
        short_id,
    })
}

pub struct RealityServer {
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<Vec<u8>>,
    pub private_key: Option<StaticSecret>,
    pub dest: Option<String>,
    pub max_time_diff_sec: u32,
}

struct ParsedClientHello {
    client_random: [u8; 32],
    session_id: [u8; 32],
    client_pub: [u8; 32],
    sni: String,
    aad_zeroed_handshake: Vec<u8>,
}

fn parse_tls_client_hello(record: &[u8]) -> Option<ParsedClientHello> {
    let u16_be = |s: &[u8], i: usize| u16::from_be_bytes([s[i], s[i + 1]]) as usize;
    if record.len() < 44 || record[0] != 0x16 {
        return None;
    }
    let hs = &record[5..];
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs[0] != 0x01 || hs.len() < 4 + hs_len {
        return None;
    }
    let body = &hs[4..4 + hs_len];
    if body.len() < 67 || body[34] != 32 {
        return None;
    }
    let client_random: [u8; 32] = body[2..34].try_into().ok()?;
    let session_id: [u8; 32] = body[35..67].try_into().ok()?;
    let mut aad_zeroed_handshake = hs[..4 + hs_len].to_vec();
    aad_zeroed_handshake[39..71].fill(0);

    let mut pos = 67;
    if pos + 2 > body.len() {
        return None;
    }
    pos += 2 + u16_be(body, pos);
    if pos + 1 > body.len() {
        return None;
    }
    pos += 1 + body[pos] as usize;
    if pos + 2 > body.len() {
        return None;
    }
    let ext_end = (pos + 2 + u16_be(body, pos)).min(body.len());
    pos += 2;

    let (mut sni, mut client_pub) = (String::new(), None);
    while pos + 4 <= ext_end {
        let (ext_type, ext_len) = (u16_be(body, pos), u16_be(body, pos + 2));
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        let ext = &body[pos..pos + ext_len];
        pos += ext_len;

        if ext_type == 0x0000 && ext.len() >= 5 {
            let nlen = u16_be(ext, 3);
            if ext.len() >= 5 + nlen {
                sni = String::from_utf8_lossy(&ext[5..5 + nlen]).to_string();
            }
        } else if ext_type == 0x0033 && ext.len() >= 2 {
            let (mut sp, sp_end) = (2usize, (2 + u16_be(ext, 0)).min(ext.len()));
            while sp + 4 <= sp_end {
                let (group, klen) = (u16_be(ext, sp), u16_be(ext, sp + 2));
                sp += 4;
                if sp + klen > sp_end {
                    break;
                }
                if group == 0x001d && klen == 32 {
                    client_pub = ext[sp..sp + 32].try_into().ok();
                    break;
                }
                sp += klen;
            }
        }
    }

    Some(ParsedClientHello { client_random, session_id, client_pub: client_pub?, sni, aad_zeroed_handshake })
}

impl RealityServer {
    pub fn new(config: &RealityConfig) -> Result<Self> {
        let server_names = config.server_names.iter().cloned().collect();
        let mut short_ids = HashSet::new();

        for sid in &config.short_ids {
            if let Ok(bytes) = hex::decode(sid) {
                short_ids.insert(bytes);
            }
        }

        let private_key = if let Some(pk_str) = &config.private_key {
            Some(StaticSecret::from(decode_reality_key32(pk_str)?))
        } else {
            None
        };

        let max_time_diff_sec = match config.max_time_diff {
            Some(0) | None => 60,
            Some(ms) if ms > 1000 => (ms / 1000) as u32,
            Some(s) => s as u32,
        };

        Ok(Self {
            server_names,
            short_ids,
            private_key,
            dest: config.dest.clone(),
            max_time_diff_sec,
        })
    }

    pub async fn accept(&self, mut stream: BoxStream) -> Result<Option<BoxStream>> {
        let mut hdr = [0u8; 5];
        if stream.read_exact(&mut hdr).await.is_err() {
            return Ok(None);
        }
        let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if hdr[0] != 0x16 || rec_len == 0 || rec_len > 16384 {
            let mut initial = hdr.to_vec();
            return self.mirror_to_dest(&mut initial, stream).await;
        }

        let mut record = vec![0u8; 5 + rec_len];
        record[..5].copy_from_slice(&hdr);
        if stream.read_exact(&mut record[5..]).await.is_err() {
            return Ok(None);
        }

        let auth_sni = parse_tls_client_hello(&record).and_then(|parsed| {
            if !self.validate_server_name(&parsed.sni) {
                return None;
            }
            self.verify_client_hello(
                &parsed.client_pub,
                &parsed.client_random,
                &parsed.session_id,
                &parsed.aad_zeroed_handshake,
                self.max_time_diff_sec,
            )
            .ok()
            .map(|_| parsed.sni)
        });

        if let Some(sni) = auth_sni {
            let cert_name = if sni.is_empty() {
                "localhost".to_string()
            } else {
                sni
            };
            let ck = rcgen::generate_simple_self_signed(vec![cert_name])
                .map_err(|e| Error::Protocol(format!("REALITY temp cert generation failed: {}", e)))?;
            let tls_server = TlsServer::from_pem(
                ck.cert.pem().as_bytes(),
                ck.key_pair.serialize_pem().as_bytes(),
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            )?;
            let replayed: BoxStream = Box::pin(PrefixedStream {
                prefix: record,
                offset: 0,
                inner: stream,
            });
            let tls_stream = tls_server.accept(replayed).await?;
            Ok(Some(tls_stream))
        } else {
            self.mirror_to_dest(&mut record, stream).await
        }
    }

    async fn mirror_to_dest(
        &self,
        initial_bytes: &mut [u8],
        mut client: BoxStream,
    ) -> Result<Option<BoxStream>> {
        let Some(ref dest) = self.dest else {
            return Err(Error::AuthFailed(
                "REALITY authentication failed and no fallback dest configured".into(),
            ));
        };
        if let Ok(mut target) = tokio::net::TcpStream::connect(dest.as_str()).await {
            let _ = target.set_nodelay(true);
            if target.write_all(initial_bytes).await.is_ok() {
                let _ = target.flush().await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
            }
        }
        Ok(None)
    }

    pub fn validate_short_id(&self, short_id: &[u8]) -> bool {
        if self.short_ids.is_empty() {
            return true;
        }
        self.short_ids.contains(short_id)
    }

    pub fn validate_server_name(&self, sni: &str) -> bool {
        if self.server_names.is_empty() {
            return true;
        }
        self.server_names.contains(sni)
    }

    pub fn verify_client_hello(
        &self,
        client_pub: &[u8; 32],
        client_random: &[u8; 32],
        session_id: &[u8; 32],
        client_hello_raw: &[u8],
        max_time_diff_sec: u32,
    ) -> Result<RealityAuthSession> {
        let server_secret = self.private_key.as_ref().ok_or_else(|| {
            Error::Protocol("REALITY server has no private key configured".into())
        })?;

        let peer_public = PublicKey::from(*client_pub);
        let shared_secret = server_secret.diffie_hellman(&peer_public);

        let auth_key = derive_auth_key(shared_secret.as_bytes(), &client_random[..20]);
        let session = open_session_id(
            &auth_key,
            &client_random[20..],
            session_id,
            client_hello_raw,
        )?;

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let diff = now_unix.abs_diff(session.timestamp);

        if diff > max_time_diff_sec {
            return Err(Error::Protocol(format!(
                "REALITY handshake timestamp expired: diff {}s > max {}s",
                diff, max_time_diff_sec
            )));
        }

        if !self.short_ids.is_empty() {
            let matched = self.short_ids.iter().any(|sid| {
                if sid.is_empty() {
                    return true;
                }
                session.short_id.starts_with(sid)
            });
            if !matched {
                return Err(Error::Protocol("REALITY short ID not recognized".into()));
            }
        }

        Ok(session)
    }
}

pub struct RealityClient {
    pub public_key: PublicKey,
    pub short_id: Vec<u8>,
    pub server_name: String,
}

impl RealityClient {
    pub fn new(server_name: &str, public_key_str: &str, short_id_hex: &str) -> Result<Self> {
        let arr = decode_reality_key32(public_key_str)?;
        let public_key = PublicKey::from(arr);

        let short_id = hex::decode(short_id_hex).unwrap_or_default();

        Ok(Self {
            public_key,
            short_id,
            server_name: server_name.to_string(),
        })
    }

    pub fn auth_client_hello(
        &self,
        client_secret: EphemeralSecret,
        client_random: &[u8; 32],
        client_hello_raw: &[u8],
    ) -> Result<[u8; 32]> {
        let shared_secret = client_secret.diffie_hellman(&self.public_key);
        let auth_key = derive_auth_key(shared_secret.as_bytes(), &client_random[..20]);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        seal_session_id(
            &auth_key,
            &client_random[20..],
            (1, 26, 3),
            now_unix,
            &self.short_id,
            client_hello_raw,
        )
    }

    pub fn generate_auth(&self) -> ([u8; 32], [u8; 32]) {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&secret);
        let shared_secret = secret.diffie_hellman(&self.public_key);
        (*client_pub.as_bytes(), *shared_secret.as_bytes())
    }
}

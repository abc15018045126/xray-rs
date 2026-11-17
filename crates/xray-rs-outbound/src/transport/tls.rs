use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio_rustls::TlsConnector;

use xray_rs_types::{BoxStream, Error, Result};

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn apply_fingerprint(provider: &mut rustls::crypto::CryptoProvider, fingerprint: &str) {
    match fingerprint.trim().to_ascii_lowercase().as_str() {
        "firefox" => {
            provider.cipher_suites.sort_by_key(|cs| match cs.suite() {
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 1,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 2,
                _ => 10,
            });
        }
        "chrome" | "edge" | "android" => {
            provider.cipher_suites.sort_by_key(|cs| match cs.suite() {
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
                _ => 10,
            });
        }
        _ => {}
    }
}

/// TLS client transport built on `tokio-rustls` + `webpki-roots`.
pub struct TlsTransport {
    connector: TlsConnector,
}

impl TlsTransport {
    pub fn new(allow_insecure: bool, alpn: Vec<Vec<u8>>, fingerprint: &str) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut provider = rustls::crypto::ring::default_provider();
        if !fingerprint.is_empty() {
            apply_fingerprint(&mut provider, fingerprint);
        }

        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Config(format!("TLS protocol version error: {}", e)))?;

        let mut config = if allow_insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        config.alpn_protocols = alpn;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    pub async fn connect(&self, server_name: &str, stream: BoxStream) -> Result<BoxStream> {
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|e| Error::InvalidAddress(format!("Invalid TLS SNI '{}': {}", server_name, e)))?;
        let tls_stream = self.connector.connect(name, stream).await?;
        Ok(Box::pin(tls_stream))
    }
}

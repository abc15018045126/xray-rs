// Module: transport\internet\tls\tls.rs
// Standard official Rust TLS implementation (rustls + ring + webpki_roots)

use std::sync::Arc;
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

#[derive(Debug)]
pub struct NoCertificateVerification;

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

pub struct TlsClient {
    connector: TlsConnector,
}

impl TlsClient {
    pub fn new(_server_name: &str, allow_insecure: bool, alpn: Vec<Vec<u8>>) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = rustls::crypto::ring::default_provider();
        let mut config = if allow_insecure {
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::Protocol(format!("TLS config protocol version error: {}", e)))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        } else {
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| Error::Protocol(format!("TLS config protocol version error: {}", e)))?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let mut alpn_protocols = alpn;
        if alpn_protocols.is_empty() {
            alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        config.alpn_protocols = alpn_protocols;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    pub async fn connect(&self, domain: &str, stream: BoxStream) -> Result<BoxStream> {
        let clean_domain = domain.trim();
        let server_name = ServerName::try_from(clean_domain.to_string()).map_err(|e| {
            Error::Protocol(format!("Invalid TLS server name '{}': {}", clean_domain, e))
        })?;
        let tls_stream = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|e| {
                Error::Protocol(format!(
                    "TLS handshake failed with '{}': {}",
                    clean_domain, e
                ))
            })?;
        Ok(Box::pin(tls_stream))
    }
}

pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn new(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self> {
        let certs = vec![CertificateDer::from(cert_der)];
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(key_der),
        );

        let provider = rustls::crypto::ring::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Protocol(format!("TLS server protocol error: {}", e)))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Protocol(format!("TLS server single cert error: {}", e)))?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub async fn accept(&self, stream: BoxStream) -> Result<BoxStream> {
        let tls_stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Protocol(format!("TLS accept failed: {}", e)))?;
        Ok(Box::pin(tls_stream))
    }
}

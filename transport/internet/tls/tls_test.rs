use super::TlsClient;

#[test]
fn test_tls_client_fingerprints() {
    assert!(TlsClient::new("example.com", false, vec![]).is_ok());
    assert!(TlsClient::new_with_fingerprint("example.com", false, vec![], "chrome").is_ok());
    assert!(TlsClient::new_with_fingerprint("example.com", true, vec![b"h2".to_vec()], "firefox").is_ok());
}

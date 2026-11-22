use super::RealityConfig;

#[test]
fn test_reality_client_config_aliases() {
    let raw = r#"{"serverName":"www.apple.com","password":"abc","shortId":"01ab","fingerprint":"chrome","spiderX":"/"}"#;
    let cfg: RealityConfig = serde_json::from_str(raw).unwrap();
    assert_eq!(cfg.server_name.as_deref(), Some("www.apple.com"));
    assert_eq!(cfg.public_key.as_deref(), Some("abc"));
    assert_eq!(cfg.short_id.as_deref(), Some("01ab"));
    assert_eq!(cfg.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(cfg.spider_x.as_deref(), Some("/"));
}

use super::config::TcpConfig;

#[test]
fn test_tcp_config_default() {
    let cfg = TcpConfig::new();
    assert!(!cfg.accept_proxy_protocol);
    assert!(cfg.header_type.is_none());
}

use super::config::StreamConfig;

#[test]
fn test_stream_config_default() {
    let cfg = StreamConfig::default();
    assert!(cfg.protocol_name.is_empty());
}

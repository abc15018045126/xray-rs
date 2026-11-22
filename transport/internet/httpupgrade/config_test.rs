use super::config::HttpUpgradeConfig;

#[test]
fn test_httpupgrade_config_normalized_path() {
    assert_eq!(HttpUpgradeConfig::default().get_normalized_path(), "/");
    assert_eq!(HttpUpgradeConfig::new("example.com", "ws").get_normalized_path(), "/ws");
}

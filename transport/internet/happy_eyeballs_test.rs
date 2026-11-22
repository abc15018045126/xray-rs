use super::happy_eyeballs::HappyEyeballsConfig;

#[test]
fn test_happy_eyeballs_config_default() {
    let cfg = HappyEyeballsConfig::default();
    assert!(cfg.try_delay_ms <= 10_000);
}

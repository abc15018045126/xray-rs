#[cfg(test)]
mod tests {
    use super::super::config::{BlackholeConfig, ResponseType};

    #[test]
    fn test_blackhole_config_defaults() {
        let cfg = BlackholeConfig::default();
        assert_eq!(cfg.response, ResponseType::None);
    }
}

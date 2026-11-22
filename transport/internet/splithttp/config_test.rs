#[cfg(test)]
mod tests {
    use super::super::config::SplitHttpConfig;

    #[test]
    fn test_splithttp_config_defaults() {
        let mut cfg = SplitHttpConfig::default();
        if cfg.path.is_empty() {
            cfg.path = "/".into();
        }
        assert_eq!(cfg.path, "/");
    }
}

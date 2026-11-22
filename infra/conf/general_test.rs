#[cfg(test)]
mod tests {
    use super::super::Config;

    #[test]
    fn test_empty_config_parse() {
        let json = "{}";
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.inbounds.is_empty());
        assert!(cfg.outbounds.is_empty());
    }
}

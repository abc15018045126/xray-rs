#[cfg(test)]
mod tests {
    use super::super::reverse::ReverseConfig;

    #[test]
    fn test_reverse_config_parsing() {
        let json = r#"{"bridges": [{"tag": "bridge", "domain": "reverse.xray"}]}"#;
        let cfg: ReverseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.bridges.len(), 1);
    }
}

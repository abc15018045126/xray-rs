#[cfg(test)]
mod tests {
    use super::super::socks::SocksServerConfig;

    #[test]
    fn test_socks_config_parsing() {
        let json = r#"{"auth": "noauth", "udp": true}"#;
        let cfg: SocksServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.udp);
    }
}

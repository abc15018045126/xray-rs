#[cfg(test)]
mod tests {
    use super::super::http::HttpServerConfig;

    #[test]
    fn test_http_config_parsing() {
        let json = r#"{"allow_transparent": true}"#;
        let cfg: HttpServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.allow_transparent);
    }
}

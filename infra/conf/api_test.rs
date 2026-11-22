#[cfg(test)]
mod tests {
    use super::super::api::ApiConfig;

    #[test]
    fn test_api_config_builder() {
        let cfg = ApiConfig::new("api-inbound")
            .with_service("HandlerService")
            .with_service("StatsService");
        assert_eq!(cfg.tag, "api-inbound");
        assert_eq!(cfg.services.len(), 2);
    }
}

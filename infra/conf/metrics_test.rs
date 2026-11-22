#[cfg(test)]
mod tests {
    use super::super::metrics::MetricsConfig;

    #[test]
    fn test_metrics_config() {
        let cfg = MetricsConfig::new("metrics-tag");
        assert_eq!(cfg.tag, "metrics-tag");
    }
}

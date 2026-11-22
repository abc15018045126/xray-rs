#[cfg(test)]
mod tests {
    use super::super::loopback::LoopbackConfig;

    #[test]
    fn test_loopback_config() {
        let cfg = LoopbackConfig::new("tag-loop");
        assert_eq!(cfg.inbound_tag, "tag-loop");
    }
}

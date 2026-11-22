#[cfg(test)]
mod tests {
    use super::super::duration::parse_duration;
    use std::time::Duration;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
    }
}

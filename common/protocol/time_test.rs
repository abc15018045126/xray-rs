#[cfg(test)]
mod tests {
    use super::super::time::Timestamp;

    #[test]
    fn test_timestamp_jitter_and_validity() {
        let ts = Timestamp::now();
        assert!(ts.is_valid(10));

        let jittered = ts.with_jitter(5);
        assert!((jittered.0 - ts.0).abs() <= 5);
    }
}

#[cfg(test)]
mod tests {
    use crate::common::antireplay::ReplayFilter;

    #[test]
    fn test_antireplay_filter_detection() {
        let filter = ReplayFilter::new(10);

        let hash1 = [1u8; 16];
        let hash2 = [2u8; 16];

        assert!(filter.check(hash1));
        assert!(filter.check(hash2));

        assert!(!filter.check(hash1));
        assert!(!filter.check(hash2));

        let hash3 = [3u8; 16];
        assert!(filter.check(hash3));
    }
}

#[cfg(test)]
mod tests {
    use super::super::mapfilter::ReplayFilter;

    #[test]
    fn test_map_filter() {
        let filter = ReplayFilter::<[u8; 16]>::new(120);
        let mut sample = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut sample);

        assert!(filter.check(sample));
        assert!(!filter.check(sample), "Unexpected true negative");

        sample[0] = sample[0].wrapping_add(1);
        assert!(filter.check(sample), "Unexpected false positive");
    }

    #[test]
    fn test_map_filter_rotation() {
        let filter = ReplayFilter::<String>::new(0);
        assert!(filter.check("item1".to_string()));
        assert!(!filter.check("item1".to_string()));
    }
}

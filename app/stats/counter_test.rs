#[cfg(test)]
mod tests {
    use super::super::counter::Counter;

    #[test]
    fn test_counter_operations() {
        let c = Counter::new();
        assert_eq!(c.value(), 0);
        assert_eq!(c.add(10), 10);
        assert_eq!(c.add(5), 15);
        c.set(100);
        assert_eq!(c.value(), 100);
    }
}

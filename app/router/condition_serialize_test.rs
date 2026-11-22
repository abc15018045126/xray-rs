#[cfg(test)]
mod tests {
    use super::super::condition::DomainMatcher;

    #[test]
    fn test_domain_condition_match() {
        let m = DomainMatcher::parse("domain:google.com");
        assert!(m.matches("www.google.com"));
        assert!(!m.matches("example.com"));
    }
}

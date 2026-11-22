#[cfg(test)]
mod tests {
    use super::super::condition_geoip::Cidr;

    #[test]
    fn test_geoip_condition_check() {
        let cidr = Cidr::parse("1.0.1.0/24").unwrap();
        assert!(cidr.contains(&"1.0.1.5".parse().unwrap()));
        assert!(!cidr.contains(&"8.8.8.8".parse().unwrap()));
    }
}

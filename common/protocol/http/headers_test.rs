#[cfg(test)]
mod tests {
    #[test]
    fn test_http_header_keys() {
        let host_header = "Host";
        assert_eq!(host_header.to_lowercase(), "host");
    }
}

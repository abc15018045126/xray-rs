#[cfg(test)]
mod tests {
    use super::super::sniff::sniff_quic;

    #[test]
    fn test_quic_sniff_empty() {
        assert!(sniff_quic(&[]).is_err());
    }
}

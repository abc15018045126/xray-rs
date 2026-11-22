#[cfg(test)]
mod tests {
    use super::super::nameserver_quic::QuicNameServer;

    #[test]
    fn test_quic_nameserver_creation() {
        let quic = QuicNameServer::new("dns.adguard.com:853");
        assert_eq!(quic.url(), "dns.adguard.com:853");
    }
}

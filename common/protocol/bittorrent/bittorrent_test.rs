#[cfg(test)]
mod tests {
    use super::super::bittorrent::BittorrentSniffer;

    #[test]
    fn test_bittorrent_sniff_valid() {
        let mut packet = vec![19u8];
        packet.extend_from_slice(b"BitTorrent protocol");
        packet.extend_from_slice(&[0u8; 8]);
        packet.extend_from_slice(&[0xabu8; 20]);
        packet.extend_from_slice(&[0xcdu8; 20]);

        let res = BittorrentSniffer::sniff(&packet);
        assert_eq!(res.unwrap(), "bittorrent");
    }

    #[test]
    fn test_utp_sniff_valid() {
        let packet = vec![
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let res = BittorrentSniffer::sniff(&packet);
        assert_eq!(res.unwrap(), "utp");
    }

    #[test]
    fn test_bittorrent_sniff_invalid() {
        let packet = b"GET /index.html HTTP/1.1\r\n\r\n";
        assert!(BittorrentSniffer::sniff(packet).is_err());
    }
}

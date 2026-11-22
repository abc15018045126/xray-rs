#[cfg(test)]
mod tests {
    use super::super::trojan::*;

    #[test]
    fn test_trojan_protocol_constants() {
        assert_eq!(PROTOCOL_NAME, "trojan");
        assert_eq!(COMMAND_TCP, 0x01);
        assert_eq!(COMMAND_UDP, 0x03);
        assert_eq!(COMMAND_MUX, 0x7f);
    }
}

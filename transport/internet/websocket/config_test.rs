use super::parse_ws_early_data;

#[test]
fn test_parse_ws_early_data() {
    assert_eq!(parse_ws_early_data("/ws?ed=2048"), ("/ws".to_string(), 2048));
    assert_eq!(parse_ws_early_data("/ws"), ("/ws".to_string(), 0));
}

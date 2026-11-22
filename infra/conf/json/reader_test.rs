#[cfg(test)]
mod tests {
    use super::super::reader::parse_json_value;

    #[test]
    fn test_json_reader() {
        let v = parse_json_value(r#"{"key": "value"}"#).unwrap();
        assert_eq!(v["key"], "value");
    }
}

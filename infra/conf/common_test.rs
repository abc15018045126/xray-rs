#[cfg(test)]
mod tests {
    use super::super::common::StringList;

    #[test]
    fn test_string_list() {
        let list = StringList(vec!["a".into(), "b".into()]);
        assert_eq!(list.0.len(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::super::r#type::type_of;

    #[test]
    fn test_type_of() {
        let x = 42u64;
        assert_eq!(type_of(&x), "u64");
    }
}

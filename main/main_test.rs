#[cfg(test)]
mod tests {
    use super::super::version::version;

    #[test]
    fn test_main_version() {
        assert_eq!(version(), "26.3.27");
    }
}

#[cfg(test)]
mod tests {
    use super::super::sockopt_linux::is_fastopen_supported;

    #[test]
    fn test_linux_fastopen_support() {
        assert!(is_fastopen_supported());
    }
}

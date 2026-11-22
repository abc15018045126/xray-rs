pub const DISTRO: &str = "all";

pub fn is_all_distro() -> bool {
    DISTRO == "all"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distro_all() {
        assert!(is_all_distro());
    }
}

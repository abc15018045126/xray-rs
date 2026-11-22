#[cfg(test)]
mod tests {
    use super::super::addons::Addons;

    #[test]
    fn test_vless_addons() {
        let addons = Addons::new("xtls-rprx-vision");
        assert_eq!(addons.flow, "xtls-rprx-vision");
    }
}

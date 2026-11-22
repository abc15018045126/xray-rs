#[cfg(test)]
mod tests {
    use crate::common::dice::roll;

    #[test]
    fn test_regular_dice() {
        assert!(roll(10) < 10);
    }
}

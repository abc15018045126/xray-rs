pub trait Buildable {
    type Output;
    fn build(self) -> crate::common::errors::Result<Self::Output>;
}

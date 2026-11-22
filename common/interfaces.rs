pub trait Runnable: Send + Sync {
    fn start(&self) -> crate::common::errors::Result<()>;
    fn close(&self) -> crate::common::errors::Result<()>;
}

pub trait HasType {
    fn type_name(&self) -> &'static str;
}

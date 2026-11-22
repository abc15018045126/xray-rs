pub trait Account: Send + Sync {
    fn equals(&self, other: &dyn Account) -> bool;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait AsAccount {
    fn as_account(&self) -> Option<Box<dyn Account>>;
}

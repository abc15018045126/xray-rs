use crate::common::protocol::SessionContext;

pub trait ContextReceiver: Send + Sync {
    fn receive_context(&self, context: &SessionContext);
    fn inject_context(&self, _tag: &str) {}
}

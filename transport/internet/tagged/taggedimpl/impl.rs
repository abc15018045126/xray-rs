use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::routing::Dispatcher;
use crate::transport::internet::tagged::{DialFunc, set_dialer};
use std::sync::Arc;

pub async fn dial_tagged_outbound(dispatcher: Option<Arc<dyn Dispatcher>>, dest: Destination, tag: String) -> Result<BoxStream> {
    let d = dispatcher.ok_or_else(|| Error::Other("dispatcher required for tagged outbound dial".into()))?;
    let (client, server) = tokio::io::duplex(65536);
    tokio::spawn(async move { let _ = d.dispatch(SessionContext::new(tag, dest), Box::pin(server)).await; });
    Ok(Box::pin(client))
}

pub async fn register_tagged_dialer() {
    let dialer: DialFunc = Arc::new(|d, dest, tag| Box::pin(dial_tagged_outbound(d, dest, tag)));
    set_dialer(dialer).await;
}

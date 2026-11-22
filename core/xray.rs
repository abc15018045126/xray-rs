use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::task::JoinHandle;

use crate::app::dispatcher::DefaultDispatcher;
use crate::app::proxyman::InboundManager;
use crate::common::errors::{Error, Result};
use crate::features::feature::Feature;
use crate::features::stats::DefaultStatsManager;
use crate::infra::conf::Config;
use crate::proxy::tun::WindowsTunDevice;

pub trait Server: Send + Sync {
    fn start(&self) -> Result<Vec<JoinHandle<()>>>;
    fn close(&self) -> Result<()>;
}

pub fn server_type() -> &'static str {
    "xray.core.Instance"
}

pub struct Instance {
    pub dispatcher: Arc<DefaultDispatcher>,
    pub inbound_manager: InboundManager,
    pub tun_devices: Vec<Arc<WindowsTunDevice>>,
    pub stats_manager: Arc<DefaultStatsManager>,
    pub running: Arc<AtomicBool>,
    features: RwLock<Vec<Arc<dyn Feature>>>,
}

impl Instance {
    pub fn new(config: Config) -> Result<Self> {
        Self::from_config(config)
    }

    pub fn new_with_context(config: Config) -> Result<Self> {
        Self::from_config(config)
    }

    pub fn from_config(config: Config) -> Result<Self> {
        let built = config.build()?;
        let stats_manager = Arc::new(DefaultStatsManager::new());
        let dispatcher = Arc::new(
            DefaultDispatcher::new(built.outbounds, Arc::new(built.router))
                .with_stats(stats_manager.clone()),
        );
        let features: Vec<Arc<dyn Feature>> = vec![dispatcher.clone(), stats_manager.clone()];
        Ok(Self {
            dispatcher,
            inbound_manager: InboundManager::new(built.inbounds),
            tun_devices: built.tun_devices,
            stats_manager,
            running: Arc::new(AtomicBool::new(false)),
            features: RwLock::new(features),
        })
    }

    pub fn add_feature(&self, feature: Arc<dyn Feature>) -> Result<()> {
        let mut guard = self.features.write().map_err(|_| Error::Other("feature lock".into()))?;
        let ftype = feature.feature_type();
        guard.retain(|f| f.feature_type() != ftype);
        guard.push(feature);
        Ok(())
    }

    pub fn get_feature(&self, feature_type: &str) -> Option<Arc<dyn Feature>> {
        self.features
            .read()
            .ok()?
            .iter()
            .find(|f| f.feature_type() == feature_type)
            .cloned()
    }

    pub fn require_features<F>(&self, types: &[&str], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<Arc<dyn Feature>>) -> Result<()>,
    {
        let mut resolved = Vec::with_capacity(types.len());
        for t in types {
            let f = self
                .get_feature(t)
                .ok_or_else(|| Error::Other(format!("missing required feature: {}", t)))?;
            resolved.push(f);
        }
        callback(resolved)
    }

    pub fn optional_features<F>(&self, types: &[&str], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<Option<Arc<dyn Feature>>>) -> Result<()>,
    {
        let resolved = types.iter().map(|t| self.get_feature(t)).collect();
        callback(resolved)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn r#type(&self) -> &'static str {
        server_type()
    }

    pub fn type_name(&self) -> &'static str {
        server_type()
    }

    pub async fn start(&self) -> Result<Vec<JoinHandle<()>>> {
        self.running.store(true, Ordering::SeqCst);
        crate::proxy::tun::init_net_config(None).await;
        let mut tasks = self.inbound_manager.start(self.dispatcher.clone()).await?;
        for dev in &self.tun_devices {
            tasks.push(dev.start(self.dispatcher.clone()).await?);
        }
        #[cfg(debug_assertions)]
        if let Some(debug_task) = crate::debug_panel::start_debug_server() {
            tasks.push(debug_task);
        }
        Ok(tasks)
    }

    pub fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        for dev in &self.tun_devices {
            dev.shutdown();
        }
        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

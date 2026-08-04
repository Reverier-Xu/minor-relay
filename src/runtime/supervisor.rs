use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch};

use crate::{
  Clock, Entropy, Error, ExtensionRegistry, KeyProvider, NodeConfig, Result, StorageFactory,
  runtime::{LifecycleSnapshot, RuntimeClient},
};

pub(crate) struct RuntimeDependencies {
  pub(crate) _storage: Arc<dyn StorageFactory>,
  pub(crate) _keys: Arc<dyn KeyProvider>,
  pub(crate) _config: NodeConfig,
  pub(crate) _extensions: ExtensionRegistry,
  pub(crate) _clock: Arc<dyn Clock>,
  pub(crate) _entropy: Arc<dyn Entropy>,
  pub(crate) _runtime_seed: [u8; 32],
}

pub(crate) async fn spawn_runtime(dependencies: RuntimeDependencies) -> Result<RuntimeClient> {
  let (control_tx, mut control_rx) = mpsc::channel::<()>(1);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();

  tokio::spawn(async move {
    let _dependencies = dependencies;
    state_tx.send_replace(LifecycleSnapshot::running());
    let _ = ready_tx.send(());

    while control_rx.recv().await.is_some() {}
    state_tx.send_replace(LifecycleSnapshot::stopped());
  });

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(RuntimeClient::new(control_tx, state_rx))
}

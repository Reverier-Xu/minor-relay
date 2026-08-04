use std::sync::Arc;

use tokio::{
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};

use crate::{
  Clock, Entropy, Error, ExtensionRegistry, KeyProvider, NodeConfig, Result, ShutdownOutcome,
  ShutdownReason, StorageFactory,
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
};

const CONTROL_CAPACITY: usize = 32;

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
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();

  tokio::spawn(supervise(dependencies, control_rx, state_tx, ready_tx));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(RuntimeClient::new(control_tx, state_rx))
}

async fn supervise(
  dependencies: RuntimeDependencies, mut control: mpsc::Receiver<Control>,
  state: watch::Sender<LifecycleSnapshot>, ready: oneshot::Sender<()>,
) {
  let _dependencies = dependencies;
  let mut tasks = JoinSet::new();
  state.send_replace(LifecycleSnapshot::running());
  if ready.send(()).is_err() {
    finish_shutdown(&mut control, &mut tasks, &state).await;
    return;
  }

  match control.recv().await {
    Some(Control::Shutdown { reply }) => {
      finish_shutdown(&mut control, &mut tasks, &state).await;
      let _ = reply.send(ShutdownOutcome::new(false));
    }
    None => finish_shutdown(&mut control, &mut tasks, &state).await,
  }
}

async fn finish_shutdown(
  control: &mut mpsc::Receiver<Control>, tasks: &mut JoinSet<()>,
  state: &watch::Sender<LifecycleSnapshot>,
) {
  state.send_replace(LifecycleSnapshot::shutting_down());
  control.close();
  tasks.shutdown().await;
  state.send_replace(LifecycleSnapshot::stopped(ShutdownReason::Requested));
}

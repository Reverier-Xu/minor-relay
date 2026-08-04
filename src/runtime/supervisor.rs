use std::sync::Arc;

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};

use crate::{
  Error, ExtensionRegistry, NodeConfig, Result, ShutdownOutcome, ShutdownReason,
  api::{Clock, Entropy},
  provider::{KeyProvider, StorageFactory},
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
  let runtime = Handle::try_current().map_err(|_| Error::not_ready("Tokio runtime"))?;
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();

  runtime.spawn(supervise(dependencies, control_rx, state_tx, ready_tx));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(RuntimeClient::new(control_tx, state_rx))
}

async fn supervise(
  dependencies: RuntimeDependencies, mut control: mpsc::Receiver<Control>,
  state: watch::Sender<LifecycleSnapshot>, ready: oneshot::Sender<()>,
) {
  let tasks = JoinSet::<()>::new();
  state.send_replace(LifecycleSnapshot::running());
  if ready.send(()).is_err() {
    finish_shutdown(control, tasks, dependencies, state, None).await;
    return;
  }

  let first_reply = control
    .recv()
    .await
    .map(|Control::Shutdown { reply }| reply);
  finish_shutdown(control, tasks, dependencies, state, first_reply).await;
}

async fn finish_shutdown(
  mut control: mpsc::Receiver<Control>, mut tasks: JoinSet<()>, dependencies: RuntimeDependencies,
  state: watch::Sender<LifecycleSnapshot>, first_reply: Option<oneshot::Sender<ShutdownOutcome>>,
) {
  state.send_replace(LifecycleSnapshot::shutting_down());
  control.close();

  let mut queued_replies = Vec::with_capacity(CONTROL_CAPACITY);
  while let Ok(Control::Shutdown { reply }) = control.try_recv() {
    queued_replies.push(reply);
  }
  tasks.shutdown().await;
  drop(control);
  drop(dependencies);

  state.send_replace(LifecycleSnapshot::stopped(ShutdownReason::Requested));
  if let Some(reply) = first_reply {
    let _ = reply.send(ShutdownOutcome::new(false));
  }
  for reply in queued_replies {
    let _ = reply.send(ShutdownOutcome::new(true));
  }
}

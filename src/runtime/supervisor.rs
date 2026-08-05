use std::sync::Arc;

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};

use crate::{
  Error, NodeConfig, Result, ShutdownOutcome, ShutdownReason,
  api::Entropy,
  provider::{KeyProvider, StorageFactory},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  storage::MetadataStore,
};

const CONTROL_CAPACITY: usize = 32;

struct LifecyclePublisher {
  state: watch::Sender<LifecycleSnapshot>,
  terminal: bool,
}

impl LifecyclePublisher {
  fn new(state: watch::Sender<LifecycleSnapshot>) -> Self {
    Self {
      state,
      terminal: false,
    }
  }

  fn publish(&self, snapshot: LifecycleSnapshot) {
    self.state.send_replace(snapshot);
  }

  fn stop(&mut self, reason: ShutdownReason) {
    self.publish(LifecycleSnapshot::stopped(reason));
    self.terminal = true;
  }
}

impl Drop for LifecyclePublisher {
  fn drop(&mut self) {
    if !self.terminal {
      self.state.send_replace(LifecycleSnapshot::failed());
    }
  }
}

pub(crate) struct RuntimeDependencies {
  pub(crate) storage_factory: Arc<dyn StorageFactory>,
  pub(crate) metadata: Option<MetadataStore>,
  pub(crate) _keys: Arc<dyn KeyProvider>,
  pub(crate) _config: NodeConfig,
  pub(crate) entropy: Arc<dyn Entropy>,
  pub(crate) _runtime_seed: Option<[u8; 32]>,
}

pub(crate) async fn spawn_runtime(mut dependencies: RuntimeDependencies) -> Result<RuntimeClient> {
  let runtime = Handle::try_current().map_err(|_| Error::not_ready("Tokio runtime"))?;
  let mut runtime_seed = [0; 32];
  dependencies.entropy.fill(&mut runtime_seed)?;
  dependencies._runtime_seed = Some(runtime_seed);
  dependencies.metadata = Some(MetadataStore::open(&dependencies.storage_factory).await?);
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
  let mut lifecycle = LifecyclePublisher::new(state);
  lifecycle.publish(LifecycleSnapshot::running());
  if ready.send(()).is_err() {
    finish_shutdown(control, tasks, dependencies, &mut lifecycle, None).await;
    return;
  }

  let first_reply = control
    .recv()
    .await
    .map(|Control::Shutdown { reply }| reply);
  finish_shutdown(control, tasks, dependencies, &mut lifecycle, first_reply).await;
}

async fn finish_shutdown(
  mut control: mpsc::Receiver<Control>, mut tasks: JoinSet<()>, dependencies: RuntimeDependencies,
  lifecycle: &mut LifecyclePublisher, first_reply: Option<oneshot::Sender<ShutdownOutcome>>,
) {
  lifecycle.publish(LifecycleSnapshot::shutting_down());
  control.close();

  let mut queued_replies = Vec::with_capacity(CONTROL_CAPACITY);
  while let Ok(Control::Shutdown { reply }) = control.try_recv() {
    queued_replies.push(reply);
  }
  tasks.shutdown().await;
  drop(control);
  drop(dependencies);

  lifecycle.stop(ShutdownReason::Explicit);
  if let Some(reply) = first_reply {
    let _ = reply.send(ShutdownOutcome::new(ShutdownReason::Explicit));
  }
  for reply in queued_replies {
    let _ = reply.send(ShutdownOutcome::new(ShutdownReason::Explicit));
  }
}

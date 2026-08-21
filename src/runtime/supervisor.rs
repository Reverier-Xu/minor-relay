use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use crate::{
  AdmissionView, ClusterView, Endpoint, Error, IssuedJoinCredential, ListenerView, LocalNodeView,
  NodeConfig, Result, ShutdownOutcome, ShutdownReason,
  api::Entropy,
  identity::{
    credential::JoinCredentialIssuer,
    genesis::create_cluster,
    lifecycle::{LocalIdentityContext, open_local_identity},
  },
  protocol::{feature::FeatureRegistry, offer::node_offer},
  provider::{KeyProvider, StorageFactory},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::SessionDriver,
  transport::{cert::EphemeralCertificate, connection::Connection, tls},
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
  pub(crate) context: Option<Arc<LocalIdentityContext>>,
  pub(crate) keys: Arc<dyn KeyProvider>,
  pub(crate) config: NodeConfig,
  pub(crate) entropy: Arc<dyn Entropy>,
  pub(crate) _runtime_seed: Option<[u8; 32]>,
}

pub(crate) async fn spawn_runtime(mut dependencies: RuntimeDependencies) -> Result<RuntimeClient> {
  let runtime = Handle::try_current().map_err(|_| Error::not_ready("Tokio runtime"))?;
  let mut runtime_seed = [0; 32];
  dependencies.entropy.fill(&mut runtime_seed)?;
  dependencies._runtime_seed = Some(runtime_seed);
  let receipt_retention = dependencies.config.receipt_retention();
  let context = open_local_identity(
    &dependencies.storage_factory,
    &dependencies.keys,
    dependencies.entropy.as_ref(),
    receipt_retention,
  )
  .await?;
  dependencies.context = Some(Arc::new(context));
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
  let mut tasks = JoinSet::<()>::new();
  let mut lifecycle = LifecyclePublisher::new(state);
  lifecycle.publish(LifecycleSnapshot::running());
  if ready.send(()).is_err() {
    finish_shutdown(control, tasks, dependencies, &mut lifecycle, None).await;
    return;
  }

  let mut supervisor = Supervisor::new(dependencies);
  loop {
    let Some(message) = control.recv().await else {
      break;
    };
    match message {
      Control::Shutdown { reply } => {
        finish_shutdown(
          control,
          tasks,
          supervisor.into_dependencies(),
          &mut lifecycle,
          Some(reply),
        )
        .await;
        return;
      }
      Control::CreateCluster { reply } => {
        let result = supervisor.create_cluster().await;
        let _ = reply.send(result);
      }
      Control::RotateJoinCredential { reply } => {
        let result = supervisor.rotate_join_credential();
        let _ = reply.send(result);
      }
      Control::Listen { endpoint, reply } => {
        let result = supervisor.listen(endpoint, &mut tasks).await;
        let _ = reply.send(result);
      }
      Control::StopListener { listener, reply } => {
        let result = supervisor.stop_listener(&listener);
        let _ = reply.send(result);
      }
      Control::JoinCluster {
        receiver,
        credential,
        reply,
      } => {
        let result = supervisor.join_cluster(receiver, credential).await;
        let _ = reply.send(result);
      }
      Control::GetLocalNode { reply } => {
        let result = supervisor.local_node().await;
        let _ = reply.send(result);
      }
    }
  }
  finish_shutdown(
    control,
    tasks,
    supervisor.into_dependencies(),
    &mut lifecycle,
    None,
  )
  .await;
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

struct Supervisor {
  dependencies: RuntimeDependencies,
  driver: SessionDriver,
  listeners: BTreeMap<crate::identity::ListenerId, (Endpoint, AbortHandle)>,
}

impl Supervisor {
  fn new(dependencies: RuntimeDependencies) -> Self {
    let context = dependencies
      .context
      .clone()
      .unwrap_or_else(|| unreachable!("runtime context is provisioned at startup"));
    let registry = FeatureRegistry::builtin()
      .unwrap_or_else(|_| unreachable!("builtin feature registry is valid"));
    let offer = node_offer(&registry, dependencies.config.required_features())
      .unwrap_or_else(|_| unreachable!("local feature offer is valid"));
    let driver = SessionDriver::new(
      context,
      dependencies.keys.clone(),
      dependencies.entropy.clone(),
      Arc::new(std::sync::Mutex::new(JoinCredentialIssuer::new())),
      offer,
    );
    Self {
      dependencies,
      driver,
      listeners: BTreeMap::new(),
    }
  }

  fn into_dependencies(self) -> RuntimeDependencies {
    self.dependencies
  }

  async fn create_cluster(&mut self) -> Result<ClusterView> {
    let context = self.context()?;
    let genesis = create_cluster(
      &context,
      &self.dependencies.keys,
      self.dependencies.entropy.as_ref(),
    )
    .await?;
    Ok(ClusterView::new(
      genesis.cluster().clone(),
      genesis.creator().clone(),
    ))
  }

  fn rotate_join_credential(&mut self) -> Result<IssuedJoinCredential> {
    self
      .driver
      .issuer()
      .lock()
      .map_err(|_| Error::internal("join credential issuer"))?
      .rotate(self.dependencies.entropy.as_ref(), SystemTime::now())
  }

  async fn listen(&mut self, endpoint: Endpoint, tasks: &mut JoinSet<()>) -> Result<ListenerView> {
    let address = format!("{}:{}", endpoint.host(), endpoint.port());
    let listener = tokio::net::TcpListener::bind(&address).await.map_err(|_| {
      Error::provider(
        crate::ProviderErrorKind::Io,
        crate::ProviderErrorContext::TransportBind,
      )
    })?;
    let bound = listener
      .local_addr()
      .map_err(|_| Error::internal("listener address"))?;
    let bound = Endpoint::parse(&format!("wss://{bound}"))?;
    let certificate = EphemeralCertificate::generate(self.dependencies.entropy.as_ref())?;
    let config = tls::server_config(&certificate)?;
    let rules = crate::session::handshake_frame_rules()?;
    let driver = self.driver.clone();
    let abort = tasks.spawn(async move {
      loop {
        let Ok((tcp, _)) = listener.accept().await else {
          return;
        };
        let hint = match driver.join_hint().await {
          Ok(hint) => hint,
          Err(_) => return,
        };
        let config = config.clone();
        let driver = driver.clone();
        tokio::spawn(async move {
          if let Ok(mut connection) = Connection::accept(tcp, config, rules, hint.as_ref()).await {
            let _ = driver.respond(&mut connection).await;
          }
        });
      }
    });
    let id = crate::identity::ListenerId::generate(self.dependencies.entropy.as_ref())?;
    self.listeners.insert(id.clone(), (bound.clone(), abort));
    Ok(ListenerView::new(id, bound))
  }

  fn stop_listener(&mut self, listener: &crate::identity::ListenerId) -> Result<()> {
    let Some((_, abort)) = self.listeners.remove(listener) else {
      return Err(Error::not_found("listener"));
    };
    abort.abort();
    Ok(())
  }

  async fn join_cluster(
    &mut self, receiver: Endpoint, credential: crate::identity::credential::JoinCredential,
  ) -> Result<AdmissionView> {
    let tcp = tokio::net::TcpStream::connect(receiver.authority())
      .await
      .map_err(|_| {
        Error::provider(
          crate::ProviderErrorKind::Io,
          crate::ProviderErrorContext::TransportConnect,
        )
      })?;
    let config = tls::join_client_config()?;
    let server_name = receiver.server_name()?;
    let rules = crate::session::handshake_frame_rules()?;
    let mut connection = Connection::connect(tcp, config, server_name, rules).await?;
    let hint = connection
      .join_hint()
      .cloned()
      .ok_or_else(|| Error::authentication_failed("join hint"))?;
    let secret = crate::protocol::credential::CredentialSecret::from_credential(&credential);
    let (_, view) = self.driver.join(&mut connection, &hint, secret).await?;
    let _ = connection.close().await;
    Ok(view)
  }

  async fn local_node(&mut self) -> Result<LocalNodeView> {
    let context = self.context()?;
    let pointer = crate::identity::genesis::local_cluster(&context)
      .await?
      .ok_or_else(|| Error::not_ready("local cluster"))?;
    Ok(LocalNodeView::new(
      pointer.cluster().clone(),
      context.identity().node().clone(),
      context.identity().public_key().clone(),
    ))
  }

  fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .dependencies
      .context
      .clone()
      .ok_or_else(|| Error::internal("runtime context"))
  }
}

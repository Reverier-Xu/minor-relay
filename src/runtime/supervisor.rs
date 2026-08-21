use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use crate::{
  AdmissionView, ClusterView, Endpoint, Error, ErrorKind, IssuedJoinCredential, ListenerView,
  LocalNodeView, NodeConfig, Result, ShutdownOutcome, ShutdownReason,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{
    credential::JoinCredentialIssuer,
    genesis::create_cluster,
    lifecycle::{LocalIdentityContext, open_local_identity},
  },
  packet::{OutboundRequest, RouteRecord, RouteState},
  protocol::{feature::FeatureRegistry, offer::node_offer},
  provider::{KeyProvider, StorageFactory},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{
      RouteTable, SessionPacketContext, SessionTable, insert_route, run_outbound, run_session,
    },
  },
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
  pub(crate) extensions: Arc<ExtensionRegistry>,
  pub(crate) sessions: SessionTable,
  pub(crate) routes: RouteTable,
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
  let routes = dependencies.routes.clone();
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();

  runtime.spawn(supervise(dependencies, control_rx, state_tx, ready_tx));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(RuntimeClient::new(control_tx, state_rx, routes))
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
        let result = supervisor
          .join_cluster(receiver, credential, &mut tasks)
          .await;
        let _ = reply.send(result);
      }
      Control::GetLocalNode { reply } => {
        let result = supervisor.local_node().await;
        let _ = reply.send(result);
      }
      Control::SendPacket { request, reply } => {
        let result = supervisor.send_packet(request, &mut tasks);
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
  shutdown_tx: watch::Sender<()>,
  connection_tasks: Arc<std::sync::Mutex<Vec<AbortHandle>>>,
  driver: SessionDriver,
  packet: Arc<SessionPacketContext>,
  route_capacity: usize,
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
    let packet = Arc::new(SessionPacketContext::new(
      context.identity().node().clone(),
      dependencies.extensions.clone(),
      dependencies.config.session_queue_messages(),
    ));
    let route_capacity = dependencies.config.trace_metadata_limits().active();
    let driver = SessionDriver::new(
      context,
      dependencies.keys.clone(),
      dependencies.entropy.clone(),
      Arc::new(std::sync::Mutex::new(JoinCredentialIssuer::new())),
      offer,
    );
    let (shutdown_tx, _) = watch::channel(());
    Self {
      dependencies,
      shutdown_tx,
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      driver,
      packet,
      route_capacity,
      listeners: BTreeMap::new(),
    }
  }

  fn into_dependencies(self) -> RuntimeDependencies {
    // Every open session task observes the shutdown signal and closes its
    // connection instead of being orphaned when the supervisor exits; the
    // tracked abort handles terminate the untracked accept-side tasks.
    let _ = self.shutdown_tx.send(());
    if let Ok(handles) = self.connection_tasks.lock() {
      for handle in handles.iter() {
        handle.abort();
      }
    }
    self.dependencies
  }

  async fn create_cluster(&mut self) -> Result<ClusterView> {
    self.require_unblocked()?;
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
    self.require_unblocked()?;
    self
      .driver
      .issuer()
      .lock()
      .map_err(|_| Error::internal("join credential issuer"))?
      .rotate(self.dependencies.entropy.as_ref(), SystemTime::now())
  }

  async fn listen(&mut self, endpoint: Endpoint, tasks: &mut JoinSet<()>) -> Result<ListenerView> {
    self.require_unblocked()?;
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
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    let connection_tasks = self.connection_tasks.clone();
    let abort = tasks.spawn(async move {
      loop {
        let Ok((tcp, _)) = listener.accept().await else {
          return;
        };
        // A transient hint failure must not kill the listener: skip this
        // connection and keep accepting.
        let Ok(hint) = driver.join_hint().await else {
          continue;
        };
        let config = config.clone();
        let driver = driver.clone();
        let sessions = sessions.clone();
        let packet = packet.clone();
        let shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
          if let Ok(mut connection) = Connection::accept(tcp, config, rules, hint.as_ref()).await {
            match driver.respond(&mut connection).await {
              Ok(session) => {
                // Keep the authenticated session open: it serves packet
                // streams until the connection closes (ADR-0007).
                run_session(connection, session, packet, sessions, shutdown).await;
              }
              Err(error) => {
                tracing::warn!(kind = ?error.kind(), context = %error, "session establishment failed");
              }
            }
          }
        });
        if let Ok(mut tasks) = connection_tasks.lock() {
          tasks.push(task.abort_handle());
        }
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
    tasks: &mut JoinSet<()>,
  ) -> Result<AdmissionView> {
    self.require_unblocked()?;
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
    let (session, view) = self.driver.join(&mut connection, &hint, secret).await?;
    // Keep the join session open so both sides can stream packets over it.
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    tasks.spawn(async move {
      run_session(connection, session, packet, sessions, shutdown).await;
    });
    Ok(view)
  }

  /// Routes one outbound packet over the established session to its exact
  /// destination. Failure paths still record the terminal route state so
  /// asynchronous senders can observe them through `GetRoute`.
  fn send_packet(&mut self, request: OutboundRequest, tasks: &mut JoinSet<()>) -> Result<()> {
    let trace_id = request.trace_id.clone();
    let destination = request.destination.clone();
    if let Err(error) = insert_route(
      &self.dependencies.routes,
      self.route_capacity,
      RouteRecord::new(trace_id.clone(), destination.clone()),
    ) {
      request.reject(error.kind());
      return Err(error);
    }
    let fail = |request: OutboundRequest, kind: ErrorKind, error: Error| {
      if let Ok(mut routes) = self.dependencies.routes.lock()
        && let Some(record) = routes.get_mut(&trace_id)
      {
        record.update(RouteState::Failed(kind));
      }
      request.reject(kind);
      error
    };
    let entry = self
      .dependencies
      .sessions
      .lock()
      .map_err(|_| Error::internal("session table"))?
      .get(&destination)
      .cloned();
    let Some(entry) = entry else {
      return Err(fail(
        request,
        ErrorKind::RouteUnavailable,
        Error::route_unavailable("packet session"),
      ));
    };
    if !entry.alive() {
      return Err(fail(
        request,
        ErrorKind::StreamInterrupted,
        Error::stream_interrupted("packet session"),
      ));
    }
    let local = self.packet.local().clone();
    let routes = self.dependencies.routes.clone();
    tasks.spawn(async move {
      run_outbound(entry, local, request, routes).await;
    });
    Ok(())
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

  /// Blocks admission-sensitive operations while the metadata store is
  /// frozen on an indeterminate outcome (ADR-0007, THR-015): credential
  /// reuse, rotation, signing, and new networking stay unavailable until
  /// an authoritative reopen reconciles the exact transaction or proves
  /// absence. Established authenticated sessions are unaffected.
  fn require_unblocked(&self) -> Result<()> {
    let context = self.context()?;
    if context.store().is_blocked()? {
      return Err(Error::not_ready("metadata storage reconciliation"));
    }
    Ok(())
  }
}

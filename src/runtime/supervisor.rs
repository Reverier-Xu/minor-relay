use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use crate::{
  AdmissionView, ClusterView, Endpoint, Error, ErrorKind, IssuedJoinCredential, ListenerView,
  LocalNodeView, NodeConfig, NodeId, Result, ShutdownOutcome, ShutdownReason,
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
  pub(crate) packet_tx: Option<mpsc::Sender<crate::packet::OutboundRequest>>,
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
  let (packet_tx, packet_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();
  let client = RuntimeClient::new(control_tx, state_rx, routes, packet_tx.clone());
  dependencies.packet_tx = Some(packet_tx);

  runtime.spawn(supervise(
    dependencies,
    control_rx,
    packet_rx,
    state_tx,
    ready_tx,
  ));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(client)
}

async fn supervise(
  dependencies: RuntimeDependencies, mut control: mpsc::Receiver<Control>,
  mut packets: mpsc::Receiver<crate::packet::OutboundRequest>,
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
    tokio::select! {
      message = control.recv() => {
        let Some(message) = message else {
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
      Control::ConnectMember {
        receiver,
        peer,
        reply,
      } => {
        let result = supervisor.connect_member(receiver, peer, &mut tasks).await;
        let _ = reply.send(result);
      }
      Control::GetLocalNode { reply } => {
        let result = supervisor.local_node().await;
        let _ = reply.send(result);
      }
      Control::GetMember { node, reply } => {
        let result = supervisor.member(node).await;
        let _ = reply.send(result);
      }
      Control::PageMembers { cursor, limit, reply } => {
        let result = supervisor.page_members(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::PageTopology { cursor, limit, reply } => {
        let result = supervisor.page_topology(cursor, limit).await;
        let _ = reply.send(result);
      }
        }
      }
      request = packets.recv() => {
        let Some(request) = request else {
          continue;
        };
        let _ = supervisor.send_packet(request, &mut tasks);
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
    let policy = crate::session::stream::SessionPolicy::from_config(&dependencies.config);
    let packet = Arc::new(SessionPacketContext::new(
      context.identity().node().clone(),
      dependencies.extensions.clone(),
      policy,
      crate::runtime::RuntimeClient::routing_only(
        dependencies
          .packet_tx
          .clone()
          .unwrap_or_else(|| unreachable!("packet channel is provisioned at startup")),
        dependencies.routes.clone(),
      ),
      std::sync::Arc::new(crate::storage::receipt::HostWallClock),
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
    let bound = crate::transport::Endpoint::from_socket_addr(bound);
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
        // connection and keep accepting. The hint carries the listener's
        // leaf SPKI as the member-mode reconnect pinning anchor.
        let Ok(mut hint) = driver.join_hint().await else {
          continue;
        };
        if let Some(hint) = hint.as_mut()
          && let Ok(spki) = certificate.leaf_spki()
        {
          *hint = hint.clone().with_leaf_spki(spki.as_ref().to_vec());
        }
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
                run_session(
                  connection,
                  session,
                  packet,
                  sessions,
                  shutdown,
                  crate::session::stream::DialDirection::Incoming,
                )
                .await;
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
    // Remember the peer's leaf SPKI from the join as the member-mode
    // reconnect pinning anchor (THR-002 hardening).
    let peer = session.peer().clone();
    if !hint.leaf_spki().is_empty() {
      self
        .driver
        .record_peer_spki(&peer, hint.leaf_spki().to_vec());
    }
    // Keep the join session open so both sides can stream packets over it.
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    tasks.spawn(async move {
      run_session(
        connection,
        session,
        packet,
        sessions,
        shutdown,
        crate::session::stream::DialDirection::Outgoing,
      )
      .await;
    });
    Ok(view)
  }

  /// Reconnects to an already-admitted peer with key trust only (G3-04,
  /// THR-002): the member-mode handshake proves both identities over a
  /// fresh transcript and exporter binding without consulting any join
  /// credential, then keeps the session open for packet streams.
  async fn connect_member(
    &mut self, receiver: Endpoint, peer: NodeId, tasks: &mut JoinSet<()>,
  ) -> Result<NodeId> {
    self.require_unblocked()?;
    let tcp = tokio::net::TcpStream::connect(receiver.authority())
      .await
      .map_err(|_| {
        Error::provider(
          crate::ProviderErrorKind::Io,
          crate::ProviderErrorContext::TransportConnect,
        )
      })?;
    // Member reconnects pin the peer's TLS leaf to the SPKI anchor learned
    // at join (same-listener reconnects); without an anchor this process
    // falls back to the join-mode relaxation and the application proof
    // layer remains the authenticator.
    let config = match self.driver.peer_spki(&peer) {
      Some(spki) => {
        tls::member_client_config(rustls::pki_types::SubjectPublicKeyInfoDer::from(spki))?
      }
      None => tls::join_client_config()?,
    };
    let server_name = receiver.server_name()?;
    let rules = crate::session::handshake_frame_rules()?;
    let mut connection = Connection::connect(tcp, config, server_name, rules).await?;
    let session = self.driver.initiate_member(&mut connection, &peer).await?;
    let authenticated = session.peer().clone();
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    tasks.spawn(async move {
      run_session(
        connection,
        session,
        packet,
        sessions,
        shutdown,
        crate::session::stream::DialDirection::Outgoing,
      )
      .await;
    });
    Ok(authenticated)
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

  /// Lazily publishes this node's own signed descriptor (revision 1) so
  /// the public views always expose the local identity. Endpoints are
  /// published by the listeners once G5-06 wires candidate publication.
  async fn ensure_self_descriptor(&mut self) -> Result<()> {
    let context = self.context()?;
    let node = context.identity().node().clone();
    let public_key = context.identity().public_key().clone();
    let store = context.store();
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?)?;
    let key = crate::StoreKey::new(std::sync::Arc::from(node.as_str().as_bytes().to_vec()));
    let snapshot = store.snapshot().await?;
    if snapshot.get(&namespace, &key).await?.is_some() {
      return Ok(());
    }
    let mut descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      public_key.clone(),
      Vec::new(),
      1,
      false,
      1,
      crate::Signature::from_bytes([0; 64]),
    );
    let handle = context.identity().handle().clone();
    let keys = Arc::clone(&self.dependencies.keys);
    let message = crate::identity::signature::signature_message(
      crate::membership::NODE_DESCRIPTOR_V1_DOMAIN,
      &descriptor.encode_signed_body()?,
    );
    let signature = keys.sign(&handle, &message).await?;
    descriptor.set_signature(signature);
    let transaction = store.prepare_transaction(
      crate::TransactionId::generate(self.dependencies.entropy.as_ref())?,
      snapshot.revision().clone(),
      vec![crate::StoreOperation::Put {
        namespace,
        key,
        expected: crate::StoreExpectation::Absent,
        value: crate::StoreValue::new(std::sync::Arc::from(descriptor.encode()?)),
      }],
    )?;
    let _ = store.commit(transaction).await?;
    Ok(())
  }

  /// One member's public observation from the signed descriptor store and
  /// the session table (SC-G05-P0-23..26).
  async fn member(&mut self, node: NodeId) -> Result<Option<crate::MemberView>> {
    self.ensure_self_descriptor().await?;
    let connected = self
      .dependencies
      .sessions
      .lock()
      .map_err(|_| Error::internal("session table"))?
      .contains_key(&node);
    let snapshot = self.context()?.store().snapshot().await?;
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?)?;
    let key = crate::StoreKey::new(std::sync::Arc::from(node.as_str().as_bytes().to_vec()));
    let Some(value) = snapshot.get(&namespace, &key).await? else {
      return Ok(None);
    };
    let descriptor = crate::membership::NodeDescriptorV1::decode_and_verify_any(value.as_bytes())?;
    Ok(Some(crate::MemberView::new(
      descriptor.node().clone(),
      descriptor.public_key().clone(),
      descriptor.revision(),
      crate::membership::node_descriptor_digest(&descriptor)?,
      if connected {
        crate::ConnectivityStatus::Connected
      } else {
        crate::ConnectivityStatus::Reachable
      },
      descriptor.endpoints().to_vec(),
    )))
  }

  /// Pages the signed descriptors, annotating connectivity from the
  /// session table (SC-G05-P0-23..25).
  async fn page_members(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::MemberPage> {
    self.ensure_self_descriptor().await?;
    let limit = limit.clamp(1, 64);
    // Snapshot the connected set under the lock, then release it before
    // any await so the supervisor future stays `Send`.
    let connected: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(|_| Error::internal("session table"))?
      .keys()
      .cloned()
      .collect();
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?)?;
    let snapshot = self.context()?.store().snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut items = Vec::new();
    let mut last_key: Option<Vec<u8>> = None;
    while let Some(entry) = scan.next().await? {
      let key = entry.key().as_bytes();
      if let Some(cursor) = cursor.as_ref()
        && key <= cursor.as_bytes()
      {
        continue;
      }
      let descriptor =
        crate::membership::NodeDescriptorV1::decode_and_verify_any(entry.value().as_bytes())?;
      let node = descriptor.node().clone();
      items.push(crate::MemberView::new(
        node.clone(),
        descriptor.public_key().clone(),
        descriptor.revision(),
        crate::membership::node_descriptor_digest(&descriptor)?,
        if connected.contains(&node) {
          crate::ConnectivityStatus::Connected
        } else {
          crate::ConnectivityStatus::Reachable
        },
        descriptor.endpoints().to_vec(),
      ));
      last_key = Some(key.to_vec());
      if items.len() >= limit {
        break;
      }
    }
    let reached_end = items.len() < limit;
    let next = if reached_end {
      None
    } else {
      last_key.map(|key| crate::PageCursor::new(std::sync::Arc::from(key)))
    };
    Ok(crate::MemberPage::new(items, next))
  }

  /// Pages the authenticated sessions as directed topology edges
  /// (SC-G05-P0-26).
  async fn page_topology(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TopologyPage> {
    let limit = limit.clamp(1, 64);
    // Build the edge list entirely under the lock (no await inside), so the
    // guard drops before the future completes.
    let mut items = Vec::new();
    let mut last_key: Option<Vec<u8>> = None;
    let context_node = self.context()?.identity().node().clone();
    for (peer, entry) in self
      .dependencies
      .sessions
      .lock()
      .map_err(|_| Error::internal("session table"))?
      .iter()
    {
      let key = peer.as_str().as_bytes();
      if let Some(cursor) = cursor.as_ref()
        && key <= cursor.as_bytes()
      {
        continue;
      }
      items.push(crate::TopologyEdgeView::new(
        context_node.clone(),
        peer.clone(),
        entry.alive(),
        std::time::SystemTime::now(),
      ));
      last_key = Some(key.to_vec());
      if items.len() >= limit {
        break;
      }
    }
    let reached_end = items.len() < limit;
    let next = if reached_end {
      None
    } else {
      last_key.map(|key| crate::PageCursor::new(std::sync::Arc::from(key)))
    };
    Ok(crate::TopologyPage::new(items, next))
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

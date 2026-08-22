use std::sync::Arc;

use crate::{
  Command, ConnectMember, CreateCluster, Error, Event, EventOptions, EventSubscription,
  GetLocalNode, GetMember, GetNodeStatus, GetRoute, JoinCluster, Listen, NodeStatus,
  OutboundPacket, PacketMetadata, PacketPolicy, PacketTarget, PageMembers, PageTopology,
  ProtocolTag, Query, Result, RotateJoinCredential, Shutdown, StopListener, TraceId,
  WaitForShutdown,
  api::{BoxFuture, Entropy},
  extension_registry::ExtensionRegistry,
  runtime::RuntimeClient,
};

#[derive(Clone)]
pub struct NodeHandle {
  runtime: RuntimeClient,
  entropy: Arc<dyn Entropy>,
  extensions: Arc<ExtensionRegistry>,
}

/// Executes one typed command against the runtime. Each command implements
/// this itself, so the handle no longer hardcodes a per-kind TypeId dispatch
/// table: adding a command requires exactly the struct in `operation.rs`
/// plus its `DispatchCommand` impl, and the compiler rejects a command that
/// forgets the impl.
pub(crate) trait DispatchCommand: Command {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>>;
}

/// Executes one typed query against the runtime; see [`DispatchCommand`].
pub(crate) trait DispatchQuery: Query {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>>;
}

impl DispatchCommand for Shutdown {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.shutdown().await })
  }
}

impl DispatchCommand for CreateCluster {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.create_cluster().await })
  }
}

impl DispatchCommand for RotateJoinCredential {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.rotate_join_credential().await })
  }
}

impl DispatchCommand for Listen {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let endpoint = self.into_endpoint();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.listen(endpoint).await })
  }
}

impl DispatchCommand for StopListener {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let listener = self.into_listener();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.stop_listener(listener).await })
  }
}

impl DispatchCommand for JoinCluster {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let (receiver, credential) = self.into_parts();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.join_cluster(receiver, credential).await })
  }
}

impl DispatchCommand for ConnectMember {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let (receiver, peer) = self.into_parts();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.connect_member(receiver, peer).await })
  }
}

impl DispatchQuery for GetNodeStatus {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { Ok(runtime.status()) })
  }
}

impl DispatchQuery for WaitForShutdown {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.wait_for_shutdown().await })
  }
}

impl DispatchQuery for GetLocalNode {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let runtime = runtime.clone();
    Box::pin(async move { runtime.local_node().await })
  }
}

impl DispatchQuery for GetMember {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let node = self.node().clone();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.member(node).await })
  }
}

impl DispatchQuery for PageMembers {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.page_members(cursor, limit).await })
  }
}

impl DispatchQuery for PageTopology {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let page = self.page();
    let cursor = page.cursor().cloned();
    let limit = page.limit();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.page_topology(cursor, limit).await })
  }
}

impl DispatchQuery for GetRoute {
  fn dispatch(self, runtime: &RuntimeClient) -> BoxFuture<'static, Result<Self::Output>> {
    let handle = self.handle().clone();
    let runtime = runtime.clone();
    Box::pin(async move { runtime.route_status(&handle) })
  }
}

impl NodeHandle {
  pub(crate) fn new(
    runtime: RuntimeClient, entropy: Arc<dyn Entropy>, extensions: Arc<ExtensionRegistry>,
  ) -> Self {
    Self {
      runtime,
      entropy,
      extensions,
    }
  }

  /// Creates an outbound packet, allocating its core-generated [`TraceId`]
  /// synchronously from the injected entropy. No body delivery starts
  /// until [`OutboundPacket::send_sync`] or [`OutboundPacket::send_async`]
  /// consumes the body.
  ///
  /// The routing policy must resolve to the built-in direct policy, an
  /// exact-node target rejects a load-balancer selection, and the protocol
  /// tag must be registered in the node's [`ExtensionRegistry`].
  pub fn create_packet(
    &self, target: PacketTarget, protocol: ProtocolTag, policy: PacketPolicy,
    metadata: PacketMetadata,
  ) -> Result<OutboundPacket> {
    let PacketTarget::Exact(_) = &target;
    if policy.load_balancing_policy().is_some() {
      return Err(Error::invalid_input("packet load balancer"));
    }
    if !self.extensions.has_protocol(&protocol) {
      return Err(Error::unsupported("packet protocol"));
    }
    let trace_id = TraceId::generate(self.entropy.as_ref())?;
    Ok(OutboundPacket::new(
      trace_id,
      target,
      protocol,
      metadata,
      self.runtime.clone(),
    ))
  }

  /// Dispatches one typed command to the runtime. The bound is satisfied by
  /// every crate-defined command; callers only name the concrete command
  /// type.
  #[allow(private_bounds)]
  pub async fn command<C: Command + DispatchCommand>(&self, command: C) -> Result<C::Output> {
    command.dispatch(&self.runtime).await
  }

  #[allow(private_bounds)]
  pub async fn query<Q: Query + DispatchQuery>(&self, query: Q) -> Result<Q::Output> {
    query.dispatch(&self.runtime).await
  }

  /// Subscribes to node events.
  ///
  /// TODO(M9): the typed event bus is not wired until the M9 facade
  /// closure; this call is part of the reserved public surface and
  /// currently returns `Unsupported`. `EventOptions` validation stays in
  /// place so the wiring lands without API changes.
  pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>> {
    let _ = options;
    if self.runtime.status() != NodeStatus::Running {
      return Err(Error::shutting_down("node events"));
    }
    Err(Error::unsupported("node events"))
  }
}

use std::{
  any::{Any, TypeId},
  sync::Arc,
};

use crate::{
  Command, CreateCluster, Error, Event, EventOptions, EventSubscription, GetLocalNode,
  GetNodeStatus, GetRoute, JoinCluster, Listen, NodeStatus, OutboundPacket, PacketMetadata,
  PacketPolicy, PacketTarget, ProtocolTag, Query, Result, RotateJoinCredential, Shutdown,
  StopListener, TraceId, WaitForShutdown, api::Entropy, extension_registry::ExtensionRegistry,
  packet::DIRECT_ROUTING_POLICY, runtime::RuntimeClient,
};

#[derive(Clone)]
pub struct NodeHandle {
  runtime: RuntimeClient,
  entropy: Arc<dyn Entropy>,
  extensions: Arc<ExtensionRegistry>,
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
    if policy.routing_policy().as_str() != DIRECT_ROUTING_POLICY {
      return Err(Error::unsupported("packet routing policy"));
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

  pub async fn command<C: Command>(&self, command: C) -> Result<C::Output> {
    let id = TypeId::of::<C>();
    if id == TypeId::of::<Shutdown>() {
      drop(command);
      return cast_output(self.runtime.shutdown().await?);
    }
    if id == TypeId::of::<CreateCluster>() {
      drop(command);
      return cast_output(self.runtime.create_cluster().await?);
    }
    if id == TypeId::of::<RotateJoinCredential>() {
      drop(command);
      return cast_output(self.runtime.rotate_join_credential().await?);
    }
    if id == TypeId::of::<Listen>() {
      let command = downcast_input::<C, Listen>(command)?;
      return cast_output(self.runtime.listen(command.into_endpoint()).await?);
    }
    if id == TypeId::of::<StopListener>() {
      let command = downcast_input::<C, StopListener>(command)?;
      return cast_output(self.runtime.stop_listener(command.into_listener()).await?);
    }
    if id == TypeId::of::<JoinCluster>() {
      let command = downcast_input::<C, JoinCluster>(command)?;
      let (receiver, credential) = command.into_parts();
      return cast_output(self.runtime.join_cluster(receiver, credential).await?);
    }

    drop(command);
    Err(Error::unsupported("node command"))
  }

  pub async fn query<Q: Query>(&self, query: Q) -> Result<Q::Output> {
    if TypeId::of::<Q>() == TypeId::of::<GetNodeStatus>() {
      drop(query);
      return cast_output(self.runtime.status());
    }
    if TypeId::of::<Q>() == TypeId::of::<WaitForShutdown>() {
      drop(query);
      return cast_output(self.runtime.wait_for_shutdown().await?);
    }
    if TypeId::of::<Q>() == TypeId::of::<GetLocalNode>() {
      drop(query);
      return cast_output(self.runtime.local_node().await?);
    }
    if TypeId::of::<Q>() == TypeId::of::<GetRoute>() {
      let query = downcast_input::<Q, GetRoute>(query)?;
      return cast_output(self.runtime.route_status(query.handle())?);
    }

    drop(query);
    Err(Error::unsupported("node query"))
  }

  pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>> {
    let _ = options;
    if self.runtime.status() != NodeStatus::Running {
      return Err(Error::shutting_down("node events"));
    }
    Err(Error::unsupported("node events"))
  }
}

fn downcast_input<Input, Target>(input: Input) -> Result<Target>
where
  Input: Send + 'static,
  Target: Send + 'static, {
  let erased: Box<dyn Any + Send> = Box::new(input);
  erased
    .downcast::<Target>()
    .map(|output| *output)
    .map_err(|_| Error::internal("typed bus input"))
}

fn cast_output<Output, Value>(value: Value) -> Result<Output>
where
  Output: Send + 'static,
  Value: Any + Send, {
  let erased: Box<dyn Any + Send> = Box::new(value);
  erased
    .downcast::<Output>()
    .map(|output| *output)
    .map_err(|_| Error::internal("typed bus output"))
}

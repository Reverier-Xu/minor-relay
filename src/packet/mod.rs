//! Opaque directed packet streams (ADR-0007).
//!
//! The data-plane unit is an opaque packet stream, not an application
//! request or response. [`NodeHandle::create_packet`] allocates the
//! core-generated [`TraceId`] synchronously and performs no body delivery;
//! [`OutboundPacket::send_sync`] waits only for the destination's
//! current-process admission acknowledgement, while
//! [`OutboundPacket::send_async`] returns a [`RouteHandle`] immediately and
//! exposes in-memory route status through the `GetRoute` query.
//!
//! Core frames and forwards body chunks with constant memory and
//! backpressure over one authenticated session, preserves byte order, never
//! persists payload bytes, and never replays or resumes an interrupted
//! stream: route or session interruption ends the stream with
//! `StreamInterrupted`.

pub(crate) mod wire;

use std::{collections::BTreeMap, fmt, sync::Arc, time::SystemTime};

use tokio::sync::{mpsc, oneshot};

use crate::{
  Error, ErrorKind, NodeId, ProtocolTag, QualifiedTag, Result, TraceId, api::BoxFuture,
  extension_registry::ExtensionRegistry, runtime::RuntimeClient,
};

/// The caller-selected routing policy for one packet.
///
/// Typed so the compiler rejects unknown or misspelled policies at build
/// time; only direct exact-node delivery exists at this gate, and selector
/// policies arrive with label routing (G6/G9).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingPolicy {
  /// Delivers directly over the authenticated session to the exact
  /// destination node.
  Direct,
}

/// The maximum number of metadata entries in one packet (ADR-0002 bounded
/// collection).
pub(crate) const METADATA_MAX_ENTRIES: usize = 256;

/// The maximum summed metadata key and value bytes in one packet.
pub(crate) const METADATA_MAX_BYTES: usize = 32 * 1_024;

/// The per-chunk streaming quantum in bytes. Total stream length is not a
/// public limit; core chunks large caller writes stay constant-memory.
pub(crate) const MAX_CHUNK_BYTES: usize = 32 * 1_024;

/// A packet destination: an exact authenticated node, or one node selected
/// by the registered load balancer from the members whose owned labels
/// match the selector (T-G06-01).
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketTarget {
  /// Delivers to exactly this authenticated node.
  Exact(NodeId),
  /// Delivers to the single node a registered load-balancing policy
  /// selects among the label-matching members.
  MatchingNodes(crate::Selector),
}

/// The caller-selected routing policy for one packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketPolicy {
  routing_policy: RoutingPolicy,
  load_balancing: Option<QualifiedTag>,
  max_hops: u32,
}

impl PacketPolicy {
  /// Selects a routing policy and a nonzero hop budget.
  pub fn new(routing_policy: RoutingPolicy, max_hops: u32) -> Result<Self> {
    if max_hops == 0 {
      return Err(Error::invalid_input("packet hop budget"));
    }
    Ok(Self {
      routing_policy,
      load_balancing: None,
      max_hops,
    })
  }

  /// Selects a load-balancing policy for matching-node targets. Exact-node
  /// targets reject a load balancer at `create_packet`.
  pub fn load_balancer(mut self, value: QualifiedTag) -> Self {
    self.load_balancing = Some(value);
    self
  }

  pub fn routing_policy(&self) -> &RoutingPolicy {
    &self.routing_policy
  }

  pub fn load_balancing_policy(&self) -> Option<&QualifiedTag> {
    self.load_balancing.as_ref()
  }

  pub fn max_hops(&self) -> u32 {
    self.max_hops
  }
}

/// A bounded canonical metadata label map carried by one packet.
///
/// Bounds are enforced at [`PacketMetadata::insert`]: at most
/// [`METADATA_MAX_ENTRIES`] entries and [`METADATA_MAX_BYTES`] summed key
/// and value bytes. Keys are unique and ordered by canonical tag text, so
/// the wire encoding is deterministic.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PacketMetadata {
  entries: BTreeMap<QualifiedTag, Arc<[u8]>>,
  total_bytes: usize,
}

impl PacketMetadata {
  pub fn new() -> Self {
    Self::default()
  }

  /// Inserts one label, enforcing uniqueness and the bounded-map limits.
  pub fn insert(mut self, key: QualifiedTag, value: Arc<[u8]>) -> Result<Self> {
    if self.entries.contains_key(&key) {
      return Err(Error::conflict("packet metadata"));
    }
    let added = key.as_str().len() + value.len();
    if self.entries.len() >= METADATA_MAX_ENTRIES || self.total_bytes + added > METADATA_MAX_BYTES {
      return Err(Error::resource_exhausted("packet metadata"));
    }
    self.total_bytes += added;
    self.entries.insert(key, value);
    Ok(self)
  }

  pub fn get(&self, key: &QualifiedTag) -> Option<&[u8]> {
    self.entries.get(key).map(AsRef::as_ref)
  }

  pub fn entries(&self) -> impl ExactSizeIterator<Item = (&QualifiedTag, &[u8])> {
    self
      .entries
      .iter()
      .map(|(key, value)| (key, value.as_ref()))
  }
}

impl fmt::Debug for PacketMetadata {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("PacketMetadata")
      .field("entries", &self.entries.len())
      .field("total_bytes", &self.total_bytes)
      .finish()
  }
}

/// A caller-owned packet body stream. Core pulls chunks with backpressure;
/// returning `Ok(None)` ends the stream.
pub trait PacketBody: fmt::Debug + Send + 'static {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<Arc<[u8]>>>>;
}

/// A one-shot body that yields exactly one bounded chunk (core sync and
/// control streams).
#[derive(Debug)]
pub(crate) struct StaticBody {
  bytes: Option<Arc<[u8]>>,
}

impl StaticBody {
  pub(crate) const fn new(bytes: Arc<[u8]>) -> Self {
    Self { bytes: Some(bytes) }
  }
}

impl PacketBody for StaticBody {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<Arc<[u8]>>>> {
    Box::pin(async move { Ok(self.bytes.take()) })
  }
}

/// An outbound packet with its core-allocated [`TraceId`], created by
/// [`NodeHandle::create_packet`] before any delivery work starts.
pub struct OutboundPacket {
  trace_id: TraceId,
  target: PacketTarget,
  load_balancer: Option<QualifiedTag>,
  max_hops: u32,
  protocol: ProtocolTag,
  metadata: PacketMetadata,
  runtime: RuntimeClient,
}

impl OutboundPacket {
  pub(crate) fn new(
    trace_id: TraceId, target: PacketTarget, load_balancer: Option<QualifiedTag>, max_hops: u32,
    protocol: ProtocolTag, metadata: PacketMetadata, runtime: RuntimeClient,
  ) -> Self {
    Self {
      trace_id,
      target,
      load_balancer,
      max_hops,
      protocol,
      metadata,
      runtime,
    }
  }

  /// The trace ID allocated synchronously at creation, readable before
  /// either send path starts consuming the body.
  pub fn trace_id(&self) -> &TraceId {
    &self.trace_id
  }

  /// Streams the body and waits only for the destination's current-process
  /// admission acknowledgement (ADR-0007): the returned [`DeliveryAck`]
  /// proves authenticated admission to the destination's bounded incoming
  /// stream, never durable retention, processing, or success.
  pub fn send_sync(self, body: Box<dyn PacketBody>) -> BoxFuture<'static, Result<DeliveryAck>> {
    let trace_id = self.trace_id.clone();
    let (request, outcome) = self.into_request(body);
    Box::pin(async move {
      request.runtime.send_packet(request.inner).await?;
      match outcome.await {
        Ok(Ok(admission)) => Ok(DeliveryAck::new(
          trace_id,
          admission.by,
          admission.admitted_at,
        )),
        Ok(Err(kind)) => Err(ack_error(kind)),
        Err(_) => Err(Error::stream_interrupted("packet stream")),
      }
    })
  }

  /// Starts streaming in the background and returns the route handle
  /// immediately. Delivery progress and terminal state are observable
  /// through the `GetRoute` query.
  pub fn send_async(self, body: Box<dyn PacketBody>) -> Result<RouteHandle> {
    let handle = RouteHandle {
      trace_id: self.trace_id.clone(),
    };
    let (request, _) = self.into_request(body);
    request.runtime.try_send_packet(request.inner)?;
    Ok(handle)
  }

  fn into_request(
    self, body: Box<dyn PacketBody>,
  ) -> (SendRequest, oneshot::Receiver<RoutedAckOutcome>) {
    let (notify, outcome) = oneshot::channel();
    let inner = OutboundRequest {
      trace_id: self.trace_id,
      target: self.target,
      load_balancer: self.load_balancer,
      max_hops: self.max_hops,
      protocol: self.protocol,
      metadata: self.metadata,
      body,
      internal: false,
      ack_notify: notify,
    };
    (
      SendRequest {
        inner,
        runtime: self.runtime,
      },
      outcome,
    )
  }
}

impl fmt::Debug for OutboundPacket {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("OutboundPacket")
      .field("trace_id", &self.trace_id)
      .field("target", &self.target)
      .field("protocol", &self.protocol)
      .finish_non_exhaustive()
  }
}

/// Helper pairing an [`OutboundRequest`] with the runtime client that owns
/// its delivery.
struct SendRequest {
  inner: OutboundRequest,
  runtime: RuntimeClient,
}

/// An admitted incoming packet stream handed to the registered
/// [`crate::PacketConsumer`]. Endpoints are the session-authenticated node
/// IDs; the body preserves wire order.
/// The reply context an admitted incoming packet needs to derive a
/// caller-owned return packet: the registry that gates protocol labels and
/// the runtime client that routes outbound packets.
#[derive(Clone)]
pub(crate) struct PacketReplyContext {
  registry: Arc<ExtensionRegistry>,
  runtime: RuntimeClient,
}

impl PacketReplyContext {
  pub(crate) const fn new(registry: Arc<ExtensionRegistry>, runtime: RuntimeClient) -> Self {
    Self { registry, runtime }
  }
}

pub struct IncomingPacket {
  source: NodeId,
  destination: NodeId,
  trace_id: TraceId,
  protocol: ProtocolTag,
  metadata: PacketMetadata,
  body: ChannelBody,
  reply: PacketReplyContext,
}

impl IncomingPacket {
  pub(crate) fn new(
    source: NodeId, destination: NodeId, trace_id: TraceId, protocol: ProtocolTag,
    metadata: PacketMetadata, body: ChannelBody, reply: PacketReplyContext,
  ) -> Self {
    Self {
      source,
      destination,
      trace_id,
      protocol,
      metadata,
      body,
      reply,
    }
  }

  pub fn source(&self) -> &NodeId {
    &self.source
  }

  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  pub fn trace_id(&self) -> &TraceId {
    &self.trace_id
  }

  pub fn protocol(&self) -> &ProtocolTag {
    &self.protocol
  }

  pub fn metadata(&self) -> &PacketMetadata {
    &self.metadata
  }

  pub fn body(&mut self) -> &mut dyn PacketBody {
    &mut self.body
  }

  /// Derives a caller-owned return packet to the authenticated source:
  /// the endpoints are swapped and the incoming `TraceId` is reused. Core
  /// assigns no return meaning, never completes another stream by
  /// correlation, and the derived packet follows the exact-node direct
  /// policy with the caller-supplied protocol and metadata (ADR-0007,
  /// SC-G03-P0-16).
  pub fn derive_return_packet(
    &self, protocol: ProtocolTag, metadata: PacketMetadata,
  ) -> Result<OutboundPacket> {
    if !self.reply.registry.has_protocol(&protocol) {
      return Err(Error::unsupported("packet protocol"));
    }
    Ok(OutboundPacket::new(
      self.trace_id.clone(),
      PacketTarget::Exact(self.source.clone()),
      None,
      1,
      protocol,
      metadata,
      self.reply.runtime.clone(),
    ))
  }
}

impl fmt::Debug for IncomingPacket {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("IncomingPacket")
      .field("source", &self.source)
      .field("destination", &self.destination)
      .field("trace_id", &self.trace_id)
      .field("protocol", &self.protocol)
      .field("metadata", &self.metadata)
      .finish_non_exhaustive()
  }
}

/// The destination's current-process admission acknowledgement (ADR-0007).
/// It carries no durable-retention, processing, or success claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryAck {
  trace_id: TraceId,
  destination: NodeId,
  admitted_at: SystemTime,
}

impl DeliveryAck {
  pub(crate) const fn new(trace_id: TraceId, destination: NodeId, admitted_at: SystemTime) -> Self {
    Self {
      trace_id,
      destination,
      admitted_at,
    }
  }

  pub fn trace_id(&self) -> &TraceId {
    &self.trace_id
  }

  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  pub fn admitted_at(&self) -> SystemTime {
    self.admitted_at
  }
}

/// A handle to one in-flight or completed route, returned by
/// [`OutboundPacket::send_async`] and accepted by the `GetRoute` query.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteHandle {
  trace_id: TraceId,
}

impl RouteHandle {
  pub fn trace_id(&self) -> &TraceId {
    &self.trace_id
  }

  /// Rebuilds the handle of one known route record (event emission).
  pub(crate) const fn from_trace_id(trace_id: TraceId) -> Self {
    Self { trace_id }
  }
}

/// One observed route state. Terminal states are `Delivered` and `Failed`.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteState {
  Selecting,
  Routing,
  Streaming,
  Delivered,
  Failed(ErrorKind),
}

/// One bounded in-memory observation of a route (ADR-0007: trace metadata
/// only, never payload bytes, and no durability claim).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteStatusView {
  handle: RouteHandle,
  selected_node: Option<NodeId>,
  state: RouteState,
  bytes_forwarded: u64,
  updated_at: SystemTime,
}

impl RouteStatusView {
  pub fn handle(&self) -> &RouteHandle {
    &self.handle
  }

  /// The route trace id; the handle already carries the same identity, so
  /// this accessor derives from it instead of duplicating the field.
  pub fn trace_id(&self) -> &TraceId {
    self.handle.trace_id()
  }

  pub fn selected_node(&self) -> Option<&NodeId> {
    self.selected_node.as_ref()
  }

  pub fn state(&self) -> &RouteState {
    &self.state
  }

  pub fn bytes_forwarded(&self) -> u64 {
    self.bytes_forwarded
  }

  pub fn updated_at(&self) -> SystemTime {
    self.updated_at
  }
}

/// The per-session internal admission fact: the admitting session's
/// wall-clock time or the typed rejection kind. The pump binds the selected
/// destination when forwarding to the synchronous waiter.
pub(crate) type AckOutcome = Result<SystemTime, ErrorKind>;

/// The admission outcome delivered to a synchronous sender: the selected
/// destination plus its admission wall-clock time.
pub(crate) struct RoutedAck {
  pub(crate) by: NodeId,
  pub(crate) admitted_at: SystemTime,
}

pub(crate) type RoutedAckOutcome = Result<RoutedAck, ErrorKind>;

/// One outbound send request flowing from the facade to the supervisor.
pub(crate) struct OutboundRequest {
  pub(crate) trace_id: TraceId,
  pub(crate) target: PacketTarget,
  pub(crate) load_balancer: Option<QualifiedTag>,
  pub(crate) max_hops: u32,
  pub(crate) protocol: ProtocolTag,
  pub(crate) metadata: PacketMetadata,
  pub(crate) body: Box<dyn PacketBody>,
  /// Core-internal control traffic (membership sync): routed like any
  /// packet but excluded from durable trace persistence.
  pub(crate) internal: bool,
  pub(crate) ack_notify: oneshot::Sender<RoutedAckOutcome>,
}

impl OutboundRequest {
  /// Rejects the request before routing, notifying a synchronous waiter.
  pub(crate) fn reject(self, kind: ErrorKind) {
    let _ = self.ack_notify.send(Err(kind));
  }
}

/// One item of an admitted incoming stream.
pub(crate) enum StreamItem {
  Chunk(Arc<[u8]>),
  End,
}

/// The [`PacketBody`] backed by one admitted incoming stream's bounded
/// channel. A channel that closes without an `End` item is an interrupted
/// stream (ADR-0007: no replay, no continuation).
#[derive(Debug)]
pub(crate) struct ChannelBody {
  receiver: mpsc::Receiver<StreamItem>,
  done: bool,
}

impl ChannelBody {
  pub(crate) const fn new(receiver: mpsc::Receiver<StreamItem>) -> Self {
    Self {
      receiver,
      done: false,
    }
  }
}

impl PacketBody for ChannelBody {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<Arc<[u8]>>>> {
    Box::pin(async move {
      if self.done {
        return Ok(None);
      }
      match self.receiver.recv().await {
        Some(StreamItem::Chunk(bytes)) => Ok(Some(bytes)),
        Some(StreamItem::End) => {
          self.done = true;
          Ok(None)
        }
        None => Err(Error::stream_interrupted("packet stream")),
      }
    })
  }
}

/// One in-memory route record (bounded trace metadata, never payload).
#[derive(Clone, Debug)]
pub(crate) struct RouteRecord {
  pub(crate) trace_id: TraceId,
  pub(crate) selected_node: Option<NodeId>,
  pub(crate) state: RouteState,
  pub(crate) bytes_forwarded: u64,
  pub(crate) updated_at: SystemTime,
}

impl RouteRecord {
  pub(crate) fn new(trace_id: TraceId, selected_node: NodeId) -> Self {
    Self {
      trace_id,
      selected_node: Some(selected_node),
      state: RouteState::Routing,
      bytes_forwarded: 0,
      updated_at: SystemTime::now(),
    }
  }

  /// A route record for a delivery that failed before any destination was
  /// selected (bounded terminal trace metadata only).
  pub(crate) fn failing(trace_id: TraceId) -> Self {
    Self {
      trace_id,
      selected_node: None,
      state: RouteState::Routing,
      bytes_forwarded: 0,
      updated_at: SystemTime::now(),
    }
  }

  pub(crate) fn update(&mut self, state: RouteState) {
    self.state = state;
    self.updated_at = SystemTime::now();
  }

  pub(crate) fn forward(&mut self, bytes: u64) {
    self.bytes_forwarded = self.bytes_forwarded.saturating_add(bytes);
    self.updated_at = SystemTime::now();
  }

  pub(crate) fn view(&self) -> RouteStatusView {
    RouteStatusView {
      handle: RouteHandle {
        trace_id: self.trace_id.clone(),
      },
      selected_node: self.selected_node.clone(),
      state: self.state.clone(),
      bytes_forwarded: self.bytes_forwarded,
      updated_at: self.updated_at,
    }
  }
}

/// Maps a wire admission rejection kind back to a typed error. The wire
/// ack status decodes to exactly the kinds matched here; any other kind
/// can only reach this function through a local invariant violation, and
/// fails closed with an internal error instead of silently reading as a
/// stream interruption.
pub(crate) fn ack_error(kind: ErrorKind) -> Error {
  match kind {
    ErrorKind::Unsupported => Error::unsupported("packet protocol"),
    ErrorKind::Overloaded => Error::overloaded("packet admission"),
    ErrorKind::RouteUnavailable => Error::route_unavailable("packet route"),
    ErrorKind::StreamInterrupted => Error::stream_interrupted("packet stream"),
    _ => Error::internal("packet ack status"),
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{METADATA_MAX_BYTES, METADATA_MAX_ENTRIES, PacketMetadata};
  use crate::{ErrorKind, QualifiedTag};

  fn key(name: &str) -> QualifiedTag {
    QualifiedTag::parse(&format!("relay.woooo.tech/labels/{name}")).unwrap()
  }

  #[test]
  fn tls_transport_packet_metadata_insert_enforces_byte_bound() {
    let metadata = PacketMetadata::new();
    let value: Arc<[u8]> = Arc::from(vec![0_u8; METADATA_MAX_BYTES]);
    let error = metadata.insert(key("oversize"), value).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);

    let metadata = PacketMetadata::new()
      .insert(key("small"), Arc::from(&b"value"[..]))
      .unwrap();
    assert_eq!(metadata.get(&key("small")), Some(&b"value"[..]));
  }

  #[test]
  fn tls_transport_packet_metadata_insert_enforces_entry_bound_and_uniqueness() {
    let mut metadata = PacketMetadata::new();
    for index in 0..METADATA_MAX_ENTRIES {
      let name = format!("entry-{index:04}");
      metadata = metadata.insert(key(&name), Arc::from(&b""[..])).unwrap();
    }
    let error = metadata
      .clone()
      .insert(key("one-too-many"), Arc::from(&b""[..]))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
    let error = metadata
      .insert(key("entry-0000"), Arc::from(&b""[..]))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  #[test]
  fn tls_transport_packet_metadata_entries_are_canonical_ordered() {
    let metadata = PacketMetadata::new()
      .insert(key("zeta"), Arc::from(&b"1"[..]))
      .unwrap()
      .insert(key("alpha"), Arc::from(&b"2"[..]))
      .unwrap();
    let names: Vec<&str> = metadata.entries().map(|(key, _)| key.name()).collect();
    assert_eq!(names, ["alpha", "zeta"]);
    assert_eq!(metadata.entries().len(), 2);
  }
}

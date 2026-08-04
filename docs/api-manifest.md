---
title: minor-relay Functional 0.1 Public API Manifest
status: accepted
owner: T-G00-06
source: ADR-0006
---

# minor-relay Functional 0.1 Public API Manifest

## Contract

This document freezes the intended functional `0.1.0` Rust source API. Later tasks implement these
signatures incrementally and may not invent another public operation before amending this manifest and
its scenario/evidence ownership. Fields marked private are not constructible by downstream code except
through the listed constructors.

The facade is a typed local command/query/event bus. It is not the network protocol. Command/query/event
traits are sealed; protocol and provider traits are open extension boundaries. All types are
`Send + 'static` where their signature requires ownership across the node runtime.

No public signature contains Tokio channel/task types, rustls, Tungstenite, minicbor, JSON record,
redb, internal transaction record, wire envelope, private key bytes, or Lycoris types.

## Common ABI

```rust
pub type Result<T, E = Error> = std::result::Result<T, E>;
pub type BoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub struct Error { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidInput,
    Conflict,
    NotFound,
    NotReady,
    NotTrusted,
    Revoked,
    Unsupported,
    UnsupportedSchema,
    UnsupportedCapability,
    AuthenticationFailed,
    DeliveryRejected,
    DeliveryTimeout,
    Overloaded,
    ClockUnhealthy,
    ClockExhausted,
    StorageLocked,
    StorageCorrupt,
    QuotaExceeded,
    PermissionDenied,
    Io,
    CommitUnknown,
    Cancelled,
    ShuttingDown,
    Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    Unsupported,
    UnsupportedCapability,
    Overloaded,
    StorageLocked,
    StorageCorrupt,
    QuotaExceeded,
    PermissionDenied,
    Io,
    Cancelled,
    Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorContext {
    StorageOpen,
    StorageSnapshot,
    StorageCommit,
    StorageReconcile,
    StorageFlush,
    KeyCreate,
    KeyReconcile,
    KeyPublicKey,
    KeySign,
    KeyDelete,
    Entropy,
    TransportBind,
    TransportConnect,
    TransportAccept,
    TransportSend,
    TransportReceive,
    TransportClose,
    Discovery,
    ProtocolHandler,
    StateCodec,
    NeighborPolicy,
    RoutingPolicy,
}

impl Error {
    pub fn provider(kind: ProviderErrorKind, context: ProviderErrorContext) -> Self;
    pub fn kind(&self) -> ErrorKind;
    pub fn context(&self) -> &'static str;
}
```

`Error::provider` accepts only the typed provider kinds and contexts above. No dynamic text or source
error can enter it, so paths, addresses, values, and provider handles remain excluded. `Error`
implements `std::error::Error`, `Display`, and redacted `Debug`.

## Value Types

```rust
pub struct NodeId { /* private */ }
pub struct ClusterId { /* private */ }
pub struct TraceId { /* private */ }
pub struct ListenerId { /* private */ }
pub struct SessionId { /* private */ }
pub struct TransactionId { /* private */ }
pub struct Digest { /* private [u8; 32] */ }
pub struct PublicKey { /* private [u8; 32] */ }
pub struct Signature { /* private [u8; 64] */ }

impl NodeId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl ClusterId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl TraceId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl Digest {
    pub const fn from_bytes(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
impl PublicKey {
    pub const fn from_bytes(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
impl Signature {
    pub const fn from_bytes(value: [u8; 64]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 64];
}
```

IDs implement `Clone`, `Eq`, `Ord`, `Hash`, `Debug`, `Display`, and `FromStr`. `Digest`, `PublicKey`, and
`Signature` implement `Clone`, `Eq`, `Ord`, `Hash`, and bounded `Debug`; public keys/signatures may be
encoded only through explicit byte accessors.

```rust
pub struct QualifiedTag { /* private */ }
pub struct FeatureTag { /* private */ }
pub struct ProtocolTag { /* private */ }
pub struct SchemaTag { /* private */ }
pub struct TransportTag { /* private */ }
pub struct DiscoveryTag { /* private */ }
pub struct ResourceTag { /* private */ }
pub struct EventTag { /* private */ }
pub struct LabelKey { /* private */ }
pub struct LabelValue { /* private */ }

impl QualifiedTag {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
    pub fn domain(&self) -> &str;
    pub fn category(&self) -> &str;
    pub fn name(&self) -> &str;
}
```

Each category tag and label type has exactly `parse(&str) -> Result<Self>` and `as_str(&self) -> &str`,
and implements `Clone`, `Eq`, `Ord`, `Hash`, `Debug`, `Display`, and `FromStr`. Category constructors
reject a qualified tag in the wrong category.

```rust
pub struct Endpoint { /* private */ }
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}

pub struct JoinCredential { /* private secret */ }
impl JoinCredential {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn expose_secret(&self) -> &str;
}
```

`JoinCredential` implements neither `Clone`, `Copy`, `Display`, serialization, nor value-revealing
`Debug`. `expose_secret` is the only deliberate escape for application-owned secret transfer.

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime { /* private */ }
impl MonotonicTime {
    pub const fn from_nanos_since_origin(value: u64) -> Self;
    pub const fn as_nanos_since_origin(self) -> u64;
    pub fn checked_add(self, duration: std::time::Duration) -> Option<Self>;
    pub fn checked_duration_since(self, earlier: Self) -> Option<std::time::Duration>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HlcTimestamp { /* private */ }
impl HlcTimestamp {
    pub const fn new(physical_ms: u64, logical: u32) -> Self;
    pub const fn physical_ms(self) -> u64;
    pub const fn logical(self) -> u32;
}
```

## Configuration and Builder

```rust
pub struct NodeConfig { /* private */ }
impl NodeConfig {
    pub fn new() -> Self;
    pub fn with_member_limit(self, value: usize) -> Result<Self>; // 1..=1,024
    pub fn with_anti_entropy_interval(self, value: std::time::Duration) -> Result<Self>;
    pub fn with_ack_timeout(self, value: std::time::Duration) -> Result<Self>;
    pub fn with_trace_retention(self, value: std::time::Duration) -> Result<Self>;
    pub fn with_max_future_skew(self, value: std::time::Duration) -> Result<Self>;
    pub fn with_session_queue_limits(self, messages: usize, bytes: usize) -> Result<Self>;
    pub fn with_protocol_limits(self, value: ProtocolLimits) -> Result<Self>;
    pub fn with_trace_limits(self, value: TraceLimits) -> Result<Self>;
    pub fn with_admission_limits(self, value: AdmissionLimits) -> Result<Self>;
    pub fn require_feature(self, value: FeatureTag) -> Result<Self>;
}
impl Default for NodeConfig {
    fn default() -> Self;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits { /* private */ }
impl AdmissionLimits {
    pub fn new(
        pending_per_source: u16,
        pending_global: u16,
        attempts_per_source_per_minute: u16,
        attempts_global_per_minute: u16,
    ) -> Result<Self>;
    pub const fn pending_per_source(self) -> u16;
    pub const fn pending_global(self) -> u16;
    pub const fn attempts_per_source_per_minute(self) -> u16;
    pub const fn attempts_global_per_minute(self) -> u16;
}
impl Default for AdmissionLimits {
    fn default() -> Self; // ADR-0006: 4, 64, 16, 256
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits { /* private */ }
impl ProtocolLimits {
    pub fn new(data_body_bytes: u32, in_flight_requests: u16) -> Result<Self>;
    pub const fn data_body_bytes(self) -> u32;
    pub const fn in_flight_requests(self) -> u16;
}
impl Default for ProtocolLimits { fn default() -> Self; }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLimits { /* private */ }
impl TraceLimits {
    pub fn new() -> Self;
    pub fn global_active(self, value: u32) -> Result<Self>;
    pub fn per_source_active(self, value: u32) -> Result<Self>;
    pub fn global_total(self, value: u32) -> Result<Self>;
    pub fn per_source_total(self, value: u32) -> Result<Self>;
    pub fn global_bytes(self, value: u64) -> Result<Self>;
    pub fn per_source_bytes(self, value: u64) -> Result<Self>;
    pub fn send_tasks(self, value: u16) -> Result<Self>;
    pub fn handler_tasks(self, value: u16) -> Result<Self>;
    pub const fn global_active_records(self) -> u32;
    pub const fn active_records_per_source(self) -> u32;
    pub const fn global_total_records(self) -> u32;
    pub const fn total_records_per_source(self) -> u32;
    pub const fn global_journal_bytes(self) -> u64;
    pub const fn journal_bytes_per_source(self) -> u64;
    pub const fn concurrent_send_tasks(self) -> u16;
    pub const fn concurrent_handler_tasks(self) -> u16;
}
impl Default for TraceLimits { fn default() -> Self; }

pub struct ExtensionRegistry { /* private */ }
impl ExtensionRegistry {
    pub fn new() -> Self;
    pub fn register_transport(
        &mut self,
        tag: TransportTag,
        value: std::sync::Arc<dyn Transport>,
    ) -> Result<&mut Self>;
    pub fn register_discovery(
        &mut self,
        tag: DiscoveryTag,
        value: std::sync::Arc<dyn Discovery>,
    ) -> Result<&mut Self>;
    pub fn register_feature(
        &mut self,
        definition: FeatureDefinition,
    ) -> Result<&mut Self>;
    pub fn register_protocol(
        &mut self,
        definition: ProtocolDefinition,
        handler: std::sync::Arc<dyn ProtocolHandler>,
    ) -> Result<&mut Self>;
    pub fn register_state_codec(
        &mut self,
        schema: SchemaTag,
        codec: std::sync::Arc<dyn StateCodec>,
    ) -> Result<&mut Self>;
    pub fn register_neighbor_policy(
        &mut self,
        tag: QualifiedTag,
        policy: std::sync::Arc<dyn NeighborPolicy>,
    ) -> Result<&mut Self>;
    pub fn register_routing_policy(
        &mut self,
        tag: QualifiedTag,
        policy: std::sync::Arc<dyn RoutingPolicy>,
    ) -> Result<&mut Self>;
}
impl Default for ExtensionRegistry {
    fn default() -> Self;
}

pub struct NodeBuilder { /* private */ }
impl NodeBuilder {
    pub fn new(
        storage: std::sync::Arc<dyn StorageFactory>,
        keys: std::sync::Arc<dyn KeyProvider>,
    ) -> Self;
    pub fn config(self, value: NodeConfig) -> Self;
    pub fn extensions(self, value: ExtensionRegistry) -> Self;
    pub fn clock(self, value: std::sync::Arc<dyn Clock>) -> Self;
    pub fn entropy(self, value: std::sync::Arc<dyn Entropy>) -> Self;
    pub async fn start(self) -> Result<NodeHandle>;
}
```

Built-in TLS WebSocket, sparse neighbor, routing, and opaque state behavior are registered by default.
`FeatureDefinition::protocol` binds the canonically sorted owned handler tags and its immutable
`test_contract_owner` into the core-computed definition digest. The owner is a domain-qualified
`resources` tag controlled by the same DNS owner as the feature; it names the compatibility contract,
not a repository path. Every `ProtocolDefinition` must name a registered owner feature that lists that exact
protocol; missing, duplicate, or cross-owned handlers fail startup. Registered features are supported by
default; `NodeConfig::require_feature` places a dependency-closed feature into every local signed
`required` offer. A duplicate stable tag or incomplete/conflicting definition fails `start` before
network I/O.

## Typed Bus

```rust
mod private { pub trait Sealed {} }

#[allow(private_bounds)]
pub trait Command: private::Sealed + Send + 'static {
    type Output: Send + 'static;
}
#[allow(private_bounds)]
pub trait Query: private::Sealed + Send + 'static {
    type Output: Send + 'static;
}
#[allow(private_bounds)]
pub trait Event: private::Sealed + Clone + Send + Sync + 'static {}

#[derive(Clone)]
pub struct NodeHandle { /* private */ }
impl NodeHandle {
    pub async fn command<C: Command>(&self, command: C) -> Result<C::Output>;
    pub async fn query<Q: Query>(&self, query: Q) -> Result<Q::Output>;
    pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>>;
}
```

`NodeHandle` is a full-authority local handle. Sealing prevents downstream local operations; application
network behavior extends only through registries.

## Commands

```rust
pub struct Shutdown { /* private */ }
impl Shutdown { pub fn new() -> Self; }
impl Command for Shutdown { type Output = ShutdownOutcome; }

pub struct CreateCluster { /* private */ }
impl CreateCluster { pub fn new() -> Self; }
impl Command for CreateCluster { type Output = ClusterView; }

pub struct RotateJoinCredential { /* private */ }
impl RotateJoinCredential { pub fn new() -> Self; }
impl Command for RotateJoinCredential { type Output = IssuedJoinCredential; }

pub struct Listen { /* private */ }
impl Listen { pub fn new(endpoint: Endpoint) -> Self; }
impl Command for Listen { type Output = ListenerView; }

pub struct StopListener { /* private */ }
impl StopListener { pub fn new(listener: ListenerId) -> Self; }
impl Command for StopListener { type Output = (); }

pub struct JoinCluster { /* private */ }
impl JoinCluster { pub fn new(receiver: Endpoint, credential: JoinCredential) -> Self; }
impl Command for JoinCluster { type Output = AdmissionView; }

pub struct DisconnectPeer { /* private */ }
impl DisconnectPeer { pub fn new(peer: NodeId) -> Self; }
impl Command for DisconnectPeer { type Output = (); }

pub struct DirectRequest { /* private */ }
impl DirectRequest {
    pub fn new(peer: NodeId, protocol: ProtocolTag, payload: std::sync::Arc<[u8]>) -> Self;
    pub fn require_feature(self, feature: FeatureTag) -> Self;
}
impl Command for DirectRequest { type Output = DirectReply; }

pub struct UpdateDescriptor { /* private */ }
impl UpdateDescriptor {
    pub fn new(expected_revision: u64, patch: DescriptorPatch) -> Self;
}
impl Command for UpdateDescriptor { type Output = MemberView; }

pub struct RoutedRequest { /* private */ }
impl RoutedRequest {
    pub fn new(destination: NodeId, protocol: ProtocolTag, payload: std::sync::Arc<[u8]>) -> Self;
    pub fn require_transit_feature(self, feature: FeatureTag) -> Self;
    pub fn require_destination_feature(self, feature: FeatureTag) -> Self;
}
impl Command for RoutedRequest { type Output = DeliveryReceipt; }

pub struct PutState { /* private */ }
impl PutState {
    pub fn new(namespace: SchemaTag, key: StateKey, value: StateValue) -> Self;
    pub fn precondition(self, value: StatePrecondition) -> Self;
}
impl Command for PutState { type Output = StateRecordView; }

pub struct DeleteState { /* private */ }
impl DeleteState {
    pub fn new(namespace: SchemaTag, key: StateKey) -> Self;
    pub fn precondition(self, value: StatePrecondition) -> Self;
}
impl Command for DeleteState { type Output = StateRecordView; }

pub struct MutateLabels { /* private */ }
impl MutateLabels {
    pub fn new(expected_revision: u64, changes: Vec<LabelChange>) -> Result<Self>;
}
impl Command for MutateLabels { type Output = LabelSetView; }

pub struct RevokeNode { /* private */ }
impl RevokeNode {
    pub fn new(subject: NodeId, expected_key: PublicKey) -> Self;
}
impl Command for RevokeNode { type Output = RevokeOutcome; }

pub struct CleanupState { /* private */ }
impl CleanupState {
    pub fn new(
        namespace: SchemaTag,
        key: StateKey,
        expected_tombstone: StateVersion,
        acknowledgement: AcceptStaleReplicaResurrection,
    ) -> Result<Self>;
}
impl Command for CleanupState { type Output = CleanupOutcome; }

pub struct LeaveCluster { /* private */ }
impl LeaveCluster {
    pub fn new(acknowledgement: ReplaceIdentityAndDeleteOldLocalState) -> Self;
}
impl Command for LeaveCluster { type Output = LeaveOutcome; }
```

`CleanupState` is the sole public cleanup operation. G7 implements its private transaction semantics;
G9 exports this command.

## Queries

```rust
pub struct GetLocalNode { /* private */ }
impl GetLocalNode { pub fn new() -> Self; }
impl Query for GetLocalNode { type Output = LocalNodeView; }

pub struct GetNodeStatus { /* private */ }
impl GetNodeStatus { pub fn new() -> Self; }
impl Query for GetNodeStatus { type Output = NodeStatus; }

pub struct WaitForShutdown { /* private */ }
impl WaitForShutdown { pub fn new() -> Self; }
impl Query for WaitForShutdown { type Output = ShutdownReason; }

pub struct ListListeners { /* private */ }
impl ListListeners { pub fn new() -> Self; }
impl Query for ListListeners { type Output = Vec<ListenerView>; }

pub struct ListSessions { /* private */ }
impl ListSessions { pub fn new() -> Self; }
impl Query for ListSessions { type Output = Vec<SessionView>; }

pub struct ListTrust { /* private */ }
impl ListTrust { pub fn new() -> Self; }
impl Query for ListTrust { type Output = Vec<TrustedIdentityView>; }

pub struct GetMember { /* private */ }
impl GetMember { pub fn new(node: NodeId) -> Self; }
impl Query for GetMember { type Output = Option<MemberView>; }

pub struct ListMembers { /* private */ }
impl ListMembers { pub fn new() -> Self; }
impl Query for ListMembers { type Output = Vec<MemberView>; }

pub struct GetTopology { /* private */ }
impl GetTopology { pub fn new() -> Self; }
impl Query for GetTopology { type Output = TopologyView; }

pub struct GetDelivery { /* private */ }
impl GetDelivery { pub fn new(trace: TraceId) -> Self; }
impl Query for GetDelivery { type Output = Option<DeliveryView>; }

pub struct GetState { /* private */ }
impl GetState { pub fn new(namespace: SchemaTag, key: StateKey) -> Self; }
impl Query for GetState { type Output = Option<StateRecordView>; }

pub struct ScanState { /* private */ }
impl ScanState {
    pub fn new(namespace: SchemaTag) -> Self;
    pub fn prefix(self, value: std::sync::Arc<[u8]>) -> Self;
    pub fn limit(self, value: usize) -> Result<Self>;
    pub fn cursor(self, value: StateCursor) -> Self;
}
impl Query for ScanState { type Output = StatePage; }

pub struct GetClockHealth { /* private */ }
impl GetClockHealth { pub fn new() -> Self; }
impl Query for GetClockHealth { type Output = ClockHealthView; }

pub struct GetNodeResource { /* private */ }
impl GetNodeResource { pub fn new(node: NodeId, tag: ResourceTag) -> Self; }
impl Query for GetNodeResource { type Output = Option<ResourceView>; }

pub struct ListNodeResources { /* private */ }
impl ListNodeResources { pub fn new(node: NodeId) -> Self; }
impl Query for ListNodeResources { type Output = ResourceSnapshot; }

pub struct SelectNodes { /* private */ }
impl SelectNodes { pub fn new(selector: Selector) -> Self; }
impl Query for SelectNodes { type Output = Vec<NodeId>; }

pub struct ListSessionFeatures { /* private */ }
impl ListSessionFeatures { pub fn new(peer: NodeId) -> Self; }
impl Query for ListSessionFeatures { type Output = Vec<SessionFeatureView>; }

pub struct GetObservability { /* private */ }
impl GetObservability { pub fn new() -> Self; }
impl Query for GetObservability { type Output = ObservabilitySnapshot; }
```

## Views and Request Values

All listed non-secret view structs use private fields and exactly the listed accessors. They implement
`Clone` and bounded/redacted `Debug`; equality is implemented when all represented fields have stable
equality. `IssuedJoinCredential`, `JoinCredential`, and `KeyHandle` are excluded from this blanket
`Clone` statement.

```rust
#[non_exhaustive]
pub enum NodeStatus { Starting, Running, ShuttingDown, Stopped, Failed }
#[non_exhaustive]
pub enum ShutdownReason { Requested, ActiveLeave, Fatal(ErrorKind) }

pub struct ShutdownOutcome { /* private */ }
impl ShutdownOutcome { pub fn already_stopped(&self) -> bool; }

pub struct LocalNodeView { /* private */ }
impl LocalNodeView {
    pub fn node_id(&self) -> &NodeId;
    pub fn public_key(&self) -> &PublicKey;
    pub fn cluster_id(&self) -> Option<&ClusterId>;
}

pub struct ClusterView { /* private */ }
impl ClusterView {
    pub fn cluster_id(&self) -> &ClusterId;
    pub fn creator(&self) -> &NodeId;
}

pub struct IssuedJoinCredential { /* private secret */ }
impl IssuedJoinCredential {
    pub fn credential(&self) -> &JoinCredential;
    pub fn expires_at(&self) -> MonotonicTime;
    pub fn into_credential(self) -> JoinCredential;
}

pub struct ListenerView { /* private */ }
impl ListenerView {
    pub fn id(&self) -> &ListenerId;
    pub fn endpoint(&self) -> &Endpoint;
}

pub struct AdmissionView { /* private */ }
impl AdmissionView {
    pub fn cluster_id(&self) -> &ClusterId;
    pub fn admitted_node(&self) -> &NodeId;
    pub fn issuer(&self) -> &NodeId;
}

pub struct DirectReply { /* private */ }
impl DirectReply { pub fn payload(&self) -> &[u8]; }

#[non_exhaustive]
pub enum DeliveryStatus { Accepted, RejectedUnsupported, TimedOut, AcceptedLate }
pub struct DeliveryReceipt { /* private */ }
impl DeliveryReceipt {
    pub fn trace_id(&self) -> &TraceId;
    pub fn destination(&self) -> &NodeId;
    pub fn status(&self) -> DeliveryStatus;
}
pub struct DeliveryView { /* private */ }
impl DeliveryView {
    pub fn receipt(&self) -> Option<&DeliveryReceipt>;
    pub fn next_ordinal(&self) -> Option<u8>;
}

pub struct DescriptorPatch { /* private */ }
impl DescriptorPatch {
    pub fn new() -> Self;
    pub fn add_endpoint(self, endpoint: Endpoint) -> Result<Self>;
    pub fn remove_endpoint(self, endpoint: Endpoint) -> Result<Self>;
    pub fn set_resource(self, tag: ResourceTag, value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn remove_resource(self, tag: ResourceTag) -> Result<Self>;
}

#[non_exhaustive]
pub enum TrustStatus { Trusted, Revoked }
pub struct TrustedIdentityView { /* private */ }
impl TrustedIdentityView {
    pub fn node_id(&self) -> &NodeId;
    pub fn public_key(&self) -> &PublicKey;
    pub fn status(&self) -> TrustStatus;
}

#[non_exhaustive]
pub enum ConnectivityStatus { Unknown, Offline, Reachable, Connected }
pub struct EndpointView { /* private */ }
impl EndpointView {
    pub fn endpoint(&self) -> &Endpoint;
    pub fn expires_at(&self) -> Option<MonotonicTime>;
}
pub struct MemberView { /* private */ }
impl MemberView {
    pub fn identity(&self) -> &TrustedIdentityView;
    pub fn descriptor_revision(&self) -> u64;
    pub fn descriptor_digest(&self) -> &Digest;
    pub fn endpoints(&self) -> &[EndpointView];
    pub fn connectivity(&self) -> ConnectivityStatus;
}
pub struct SessionView { /* private */ }
impl SessionView {
    pub fn id(&self) -> &SessionId;
    pub fn generation(&self) -> u64;
    pub fn peer(&self) -> &NodeId;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn selected_features(&self) -> &[SessionFeatureView];
}
pub struct SessionFeatureView { /* private */ }
impl SessionFeatureView {
    pub fn feature(&self) -> &FeatureTag;
    pub fn definition_digest(&self) -> &Digest;
}
pub struct TopologyEdgeView { /* private */ }
impl TopologyEdgeView {
    pub fn left(&self) -> &NodeId;
    pub fn right(&self) -> &NodeId;
    pub fn session_generation(&self) -> u64;
}
pub struct TopologyView { /* private */ }
impl TopologyView {
    pub fn local_node(&self) -> &NodeId;
    pub fn edges(&self) -> &[TopologyEdgeView];
    pub fn digest(&self) -> &Digest;
}
```

```rust
pub struct StateKey { /* private Arc<[u8]> */ }
impl StateKey {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
pub struct StateValue { /* private */ }
impl StateValue {
    pub fn new(schema: SchemaTag, value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn schema(&self) -> &SchemaTag;
    pub fn as_bytes(&self) -> &[u8];
}
pub struct StateVersion { /* private */ }
impl StateVersion {
    pub fn timestamp(&self) -> HlcTimestamp;
    pub fn writer(&self) -> &NodeId;
    pub fn is_tombstone(&self) -> bool;
    pub fn digest(&self) -> &Digest;
}
pub struct StateRecordView { /* private */ }
impl StateRecordView {
    pub fn namespace(&self) -> &SchemaTag;
    pub fn key(&self) -> &StateKey;
    pub fn version(&self) -> &StateVersion;
    pub fn value(&self) -> Option<&StateValue>;
}
#[non_exhaustive]
pub enum StatePrecondition { Any, Absent, Exact(StateVersion) }
pub struct StateCursor { /* private */ }
pub struct StatePage { /* private */ }
impl StatePage {
    pub fn records(&self) -> &[StateRecordView];
    pub fn next(&self) -> Option<&StateCursor>;
}

#[non_exhaustive]
pub enum ClockHealth { HealthyIsolated, Healthy, Degraded, Unhealthy }
pub struct ClockHealthView { /* private */ }
impl ClockHealthView {
    pub fn health(&self) -> ClockHealth;
    pub fn active_peers(&self) -> usize;
    pub fn fresh_inliers(&self) -> usize;
    pub fn uncertainty(&self) -> std::time::Duration;
    pub fn quarantined_records(&self) -> usize;
}
```

```rust
pub struct Selector { /* private */ }
impl Selector {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
#[non_exhaustive]
pub enum LabelChange {
    Set { key: LabelKey, value: LabelValue },
    Remove { key: LabelKey },
}
pub struct LabelSetView { /* private */ }
impl LabelSetView {
    pub fn node(&self) -> &NodeId;
    pub fn revision(&self) -> u64;
    pub fn digest(&self) -> &Digest;
    pub fn labels(&self) -> &std::collections::BTreeMap<LabelKey, LabelValue>;
}
pub struct ResourceView { /* private */ }
impl ResourceView {
    pub fn node(&self) -> &NodeId;
    pub fn tag(&self) -> &ResourceTag;
    pub fn generation(&self) -> u64;
    pub fn value(&self) -> &[u8];
}
pub struct ResourceSnapshot { /* private */ }
impl ResourceSnapshot {
    pub fn values(&self) -> &[ResourceView];
    pub fn digest(&self) -> &Digest;
}

pub enum AcceptStaleReplicaResurrection {
    AcceptStaleReplicaResurrection,
}
pub enum ReplaceIdentityAndDeleteOldLocalState {
    ReplaceIdentityAndDeleteOldLocalState,
}
pub struct RevokeOutcome { /* private */ }
impl RevokeOutcome {
    pub fn node(&self) -> &NodeId;
    pub fn already_revoked(&self) -> bool;
}
pub struct CleanupOutcome { /* private */ }
impl CleanupOutcome {
    pub fn namespace(&self) -> &SchemaTag;
    pub fn key(&self) -> &StateKey;
    pub fn removed_version(&self) -> &StateVersion;
}
pub struct LeaveOutcome { /* private */ }
impl LeaveOutcome {
    pub fn old_node_id(&self) -> &NodeId;
    pub fn new_node_id(&self) -> &NodeId;
}
```

The two acknowledgement enums do not implement `Default`.

## Events and Observability

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOptions { /* private; default 256, legal capacity 1..=1,024 */ }
impl EventOptions {
    pub fn new() -> Self;
    pub fn capacity(self, value: usize) -> Result<Self>;
}
impl Default for EventOptions { fn default() -> Self; }

pub struct EventSubscription<E: Event> { /* private */ }
impl<E: Event> EventSubscription<E> {
    pub async fn recv(&mut self) -> Result<EventReceive<E>>;
    pub fn try_recv(&mut self) -> Result<EventReceive<E>>;
}
#[non_exhaustive]
pub enum EventReceive<E> {
    Item(E),
    Empty,
    Lagged { missed: u64 },
    Closed,
}

pub struct SessionChanged { /* private */ }
pub struct MemberChanged { /* private */ }
pub struct StateChanged { /* private */ }
pub struct LabelsChanged { /* private */ }
pub struct NodeRevoked { /* private */ }
pub struct StateCleaned { /* private */ }
pub struct IdentityReplaced { /* private */ }
pub struct EquivocationObserved { /* private */ }

impl SessionChanged {
    pub fn sequence(&self) -> u64;
    pub fn session(&self) -> &SessionView;
}
impl MemberChanged {
    pub fn sequence(&self) -> u64;
    pub fn member(&self) -> &MemberView;
}
impl StateChanged {
    pub fn sequence(&self) -> u64;
    pub fn record(&self) -> &StateRecordView;
}
impl LabelsChanged {
    pub fn sequence(&self) -> u64;
    pub fn labels(&self) -> &LabelSetView;
}
impl NodeRevoked {
    pub fn sequence(&self) -> u64;
    pub fn outcome(&self) -> &RevokeOutcome;
}
impl StateCleaned {
    pub fn sequence(&self) -> u64;
    pub fn outcome(&self) -> &CleanupOutcome;
}
impl IdentityReplaced {
    pub fn sequence(&self) -> u64;
    pub fn outcome(&self) -> &LeaveOutcome;
}
impl EquivocationObserved {
    pub fn sequence(&self) -> u64;
    pub fn writer(&self) -> &NodeId;
    pub fn timestamp(&self) -> HlcTimestamp;
    pub fn digest(&self) -> &Digest;
}
```

Each event type implements sealed `Event`. Events are transient; lag requires an authoritative query
refresh.

```rust
pub struct ObservabilitySnapshot { /* private */ }
impl ObservabilitySnapshot {
    pub fn counter(&self, tag: &ResourceTag) -> Option<u64>;
    pub fn session_generation_digest(&self) -> &Digest;
    pub fn captured_at(&self) -> MonotonicTime;
}
```

Only bounded domain-qualified counters ratified by ADR-0005/G10 are returned. No addresses, paths,
payloads, peer text, internal task handles, or storage records are exposed.

## Open Extension Contracts

All extension traits are `Debug + Send + Sync + 'static`. They are trusted in-process code and must be
usable behind `Arc<dyn Trait>` unless generic parameters are shown.

```rust
pub trait Clock: std::fmt::Debug + Send + Sync + 'static {
    fn utc_now(&self) -> std::time::SystemTime;
    fn monotonic_now(&self) -> MonotonicTime;
    fn sleep_until<'a>(&'a self, deadline: MonotonicTime) -> BoxFuture<'a, ()>;
}
pub trait Entropy: std::fmt::Debug + Send + Sync + 'static {
    fn fill(&self, output: &mut [u8]) -> Result<()>;
}
```

```rust
pub struct KeyOperationId { /* private */ }
pub struct KeyHandle { /* private secret provider handle */ }
pub struct CreatedKey { /* private */ }
impl KeyOperationId {
    pub fn as_bytes(&self) -> &[u8];
}
impl KeyHandle {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn expose_provider_handle(&self) -> &[u8];
}
impl CreatedKey {
    pub fn new(handle: KeyHandle, public_key: PublicKey) -> Self;
    pub fn handle(&self) -> &KeyHandle;
    pub fn public_key(&self) -> &PublicKey;
}
#[non_exhaustive]
pub enum KeyCreateState { Present(CreatedKey), Absent, Unknown }
#[non_exhaustive]
pub enum KeyDeleteState { Present, Absent, Unknown }

pub trait KeyProvider: std::fmt::Debug + Send + Sync + 'static {
    fn create_ed25519<'a>(&'a self, operation: &'a KeyOperationId)
        -> BoxFuture<'a, Result<KeyCreateState>>;
    fn reconcile_create<'a>(&'a self, operation: &'a KeyOperationId)
        -> BoxFuture<'a, Result<KeyCreateState>>;
    fn public_key<'a>(&'a self, handle: &'a KeyHandle)
        -> BoxFuture<'a, Result<PublicKey>>;
    fn sign<'a>(&'a self, handle: &'a KeyHandle, message: &'a [u8])
        -> BoxFuture<'a, Result<Signature>>;
    fn delete<'a>(&'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle)
        -> BoxFuture<'a, Result<KeyDeleteState>>;
    fn reconcile_delete<'a>(&'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle)
        -> BoxFuture<'a, Result<KeyDeleteState>>;
}
```

`KeyHandle` and `IssuedJoinCredential` implement neither `Clone`, serialization, `Display`, nor
value-revealing `Debug`. `expose_provider_handle` is the explicit sensitive SPI escape used by the
provider that created the handle; it is public because external provider implementations must persist
and reopen their opaque locator. Provider contract suites create operation IDs; downstream code cannot
forge core-owned IDs.

```rust
pub struct StoreRequirements { /* private */ }
pub struct StoreCapabilities { /* private */ }
pub struct StoreRevision { /* private */ }
pub struct StoreNamespace { /* private domain tag */ }
pub struct StoreKey { /* private bytes */ }
pub struct StoreValue { /* private bytes */ }
pub struct StoreSnapshot { /* private immutable */ }
pub struct StoreTransaction { /* private operations */ }
pub struct CommitReceipt { /* private */ }

impl StoreRequirements {
    pub fn required_durability(&self) -> DurabilityLevel;
    pub fn requires_conditional_batch(&self) -> bool;
    pub fn requires_ordered_scan(&self) -> bool;
    pub fn requires_reconciliation(&self) -> bool;
    pub fn requires_exclusive_lifetime_lock(&self) -> bool;
    pub fn requires_transactional_migration(&self) -> bool;
}
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityLevel { ProcessCrashAtomic, OsCrashDurable }
impl StoreCapabilities {
    pub fn new(durability: DurabilityLevel) -> Self;
    pub fn conditional_batch(self, supported: bool) -> Self;
    pub fn ordered_scan(self, supported: bool) -> Self;
    pub fn reconciliation(self, supported: bool) -> Self;
    pub fn exclusive_lifetime_lock(self, supported: bool) -> Self;
    pub fn transactional_migration(self, supported: bool) -> Self;
    pub fn durability(&self) -> DurabilityLevel;
    pub fn has_conditional_batch(&self) -> bool;
    pub fn has_ordered_scan(&self) -> bool;
    pub fn has_reconciliation(&self) -> bool;
    pub fn has_exclusive_lifetime_lock(&self) -> bool;
    pub fn has_transactional_migration(&self) -> bool;
}
impl StoreRevision {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
impl StoreNamespace {
    pub fn new(value: QualifiedTag) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl StoreKey {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
impl StoreValue {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
    pub fn digest(&self) -> &Digest;
}
pub struct StoreEntry { /* private */ }
impl StoreEntry {
    pub fn new(namespace: StoreNamespace, key: StoreKey, value: StoreValue) -> Self;
    pub fn namespace(&self) -> &StoreNamespace;
    pub fn key(&self) -> &StoreKey;
    pub fn value(&self) -> &StoreValue;
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreExpectation { Absent, Exact(Digest) }
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreOperation {
    Check { namespace: StoreNamespace, key: StoreKey, expected: StoreExpectation },
    Put { namespace: StoreNamespace, key: StoreKey, expected: StoreExpectation, value: StoreValue },
    Delete { namespace: StoreNamespace, key: StoreKey, expected: Digest },
}
impl StoreTransaction {
    pub fn id(&self) -> &TransactionId;
    pub fn operation_digest(&self) -> &Digest;
    pub fn base_revision(&self) -> &StoreRevision;
    pub fn operations(&self) -> &[StoreOperation];
}
impl CommitReceipt {
    pub fn new(
        transaction: TransactionId,
        operation_digest: Digest,
        committed_revision: StoreRevision,
    ) -> Self;
    pub fn transaction(&self) -> &TransactionId;
    pub fn operation_digest(&self) -> &Digest;
    pub fn committed_revision(&self) -> &StoreRevision;
}

#[non_exhaustive]
pub enum CommitOutcome {
    Committed(CommitReceipt),
    Aborted,
    Conflict,
    Unknown { transaction: TransactionId, operation_digest: Digest },
}
#[non_exhaustive]
pub enum ReconcileOutcome { Committed(CommitReceipt), Aborted, DigestConflict, Unknown }

impl StoreSnapshot {
    pub fn new(revision: StoreRevision, entries: Vec<StoreEntry>) -> Result<Self>;
    pub fn revision(&self) -> &StoreRevision;
    pub fn get(&self, namespace: &StoreNamespace, key: &StoreKey) -> Option<&StoreValue>;
    pub fn scan(
        &self,
        namespace: &StoreNamespace,
        prefix: &[u8],
        after: Option<&StoreKey>,
        limit: usize,
    ) -> Result<Vec<(StoreKey, StoreValue)>>;
}

pub trait StorageFactory: std::fmt::Debug + Send + Sync + 'static {
    fn open<'a>(&'a self, requirements: StoreRequirements)
        -> BoxFuture<'a, Result<Box<dyn Storage>>>;
}
pub trait Storage: std::fmt::Debug + Send + Sync + 'static {
    fn capabilities(&self) -> StoreCapabilities;
    fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<StoreSnapshot>>;
    fn commit<'a>(&'a self, transaction: StoreTransaction)
        -> BoxFuture<'a, Result<CommitOutcome>>;
    fn reconcile<'a>(&'a self, transaction: &'a TransactionId, digest: &'a Digest)
        -> BoxFuture<'a, Result<ReconcileOutcome>>;
    fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}
```

`TransactionId`, `StoreRevision`, `StoreNamespace`, `StoreKey`, and `StoreValue` implement `Clone`,
`Eq`, `Ord`, `Hash`, and bounded `Debug`. `StoreEntry`, `StoreSnapshot`, `StoreTransaction`, and
`CommitReceipt` implement `Clone` and bounded `Debug`. Provider constructors validate all byte/count
ceilings before accepting reopened data. Core constructs transactions and requirements; their private
fields plus read-only accessors expose only backend-neutral opaque bytes, revisions, preconditions, and
capability requirements. A backend receiving an unknown non-exhaustive operation returns
`UnsupportedCapability`; no logical identity/wire type enters the storage SPI.

```rust
pub struct ChannelBinding { /* private [u8; 32] */ }
impl ChannelBinding {
    pub const fn from_tls_exporter(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
pub trait Transport: std::fmt::Debug + Send + Sync + 'static {
    fn bind<'a>(&'a self, endpoint: &'a Endpoint)
        -> BoxFuture<'a, Result<Box<dyn TransportListener>>>;
    fn connect<'a>(&'a self, endpoint: &'a Endpoint)
        -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;
}
pub trait TransportListener: std::fmt::Debug + Send + Sync + 'static {
    fn local_endpoint(&self) -> Endpoint;
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;
    fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}
pub trait TransportConnection: std::fmt::Debug + Send + Sync + 'static {
    fn peer_endpoint(&self) -> Endpoint;
    fn channel_binding(&self) -> ChannelBinding;
    fn send<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<()>>;
    fn receive<'a>(&'a self) -> BoxFuture<'a, Result<Option<Vec<u8>>>>;
    fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

pub struct DiscoveryContext { /* private facade views */ }
impl DiscoveryContext {
    pub fn local_node(&self) -> &NodeId;
    pub fn known_members(&self) -> &[MemberView];
}
pub struct DiscoveredEndpoint { /* private */ }
impl DiscoveredEndpoint {
    pub fn new(node_hint: Option<NodeId>, endpoint: Endpoint, expires_at: Option<MonotonicTime>) -> Self;
    pub fn node_hint(&self) -> Option<&NodeId>;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn expires_at(&self) -> Option<MonotonicTime>;
}
pub trait Discovery: std::fmt::Debug + Send + Sync + 'static {
    fn discover<'a>(&'a self, context: DiscoveryContext)
        -> BoxFuture<'a, Result<Vec<DiscoveredEndpoint>>>;
}
```

A transport is security-critical trusted code. The core still performs the ADR-0001 application
handshake and requires the exact TLS exporter binding contract before session activation.

```rust
pub struct ProtocolDefinition { /* private */ }
impl ProtocolDefinition {
    pub fn new(tag: ProtocolTag, owning_feature: FeatureTag) -> Self;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitWidth { U16, U32, U64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitUnit { Count, Bytes, Milliseconds }
pub struct LimitDefinition { /* private */ }
impl LimitDefinition {
    pub fn new(
        tag: QualifiedTag,
        width: LimitWidth,
        unit: LimitUnit,
        default: u64,
        floor: u64,
        ceiling: u64,
        mandatory: bool,
    ) -> Result<Self>;
}
pub struct FeatureDefinition { /* private; core computes canonical digest */ }
impl FeatureDefinition {
    pub fn new(tag: FeatureTag, fingerprint: Digest, test_contract_owner: QualifiedTag) -> Result<Self>;
    pub fn dependency(self, tag: FeatureTag) -> Result<Self>;
    pub fn conflict(self, tag: FeatureTag) -> Result<Self>;
    pub fn limit(self, value: LimitDefinition) -> Result<Self>;
    pub fn protocol(self, value: ProtocolTag) -> Result<Self>;
    pub fn test_contract_owner(&self) -> &QualifiedTag;
    pub fn definition_digest(&self) -> &Digest;
}
pub struct RequestContext { /* private facade IDs only */ }
impl RequestContext {
    pub fn local_node(&self) -> &NodeId;
    pub fn source(&self) -> &NodeId;
    pub fn trace_id(&self) -> Option<&TraceId>;
    pub fn session_peer(&self) -> Option<&NodeId>;
}
#[non_exhaustive]
pub enum HandlerReply { NoReply, Reply(std::sync::Arc<[u8]>) }
pub trait ProtocolHandler: std::fmt::Debug + Send + Sync + 'static {
    fn handle<'a>(&'a self, context: RequestContext, payload: &'a [u8])
        -> BoxFuture<'a, Result<HandlerReply>>;
}
pub trait StateCodec: std::fmt::Debug + Send + Sync + 'static {
    fn validate(&self, bytes: &[u8]) -> Result<()>;
}

pub struct NeighborPolicyInput { /* private bounded facade views */ }
impl NeighborPolicyInput {
    pub fn local_node(&self) -> &NodeId;
    pub fn members(&self) -> &[MemberView];
    pub fn current_peers(&self) -> &[NodeId];
    pub fn maximum_peers(&self) -> usize;
}
pub struct NeighborPlan { /* private */ }
impl NeighborPlan {
    pub fn new(desired_peers: Vec<NodeId>) -> Result<Self>;
    pub fn desired_peers(&self) -> &[NodeId];
}
pub trait NeighborPolicy: std::fmt::Debug + Send + Sync + 'static {
    fn choose(&self, input: &NeighborPolicyInput) -> Result<NeighborPlan>;
}
pub struct RouteContext { /* private bounded facade views */ }
impl RouteContext {
    pub fn local_node(&self) -> &NodeId;
    pub fn source(&self) -> &NodeId;
    pub fn destination(&self) -> &NodeId;
    pub fn active_neighbors(&self) -> &[NodeId];
    pub fn topology(&self) -> &TopologyView;
}
pub trait RoutingPolicy: std::fmt::Debug + Send + Sync + 'static {
    fn next_hop(&self, input: &RouteContext) -> Result<Option<NodeId>>;
}
```

Policy inputs expose immutable bounded membership/topology views only. Plans are validated for member
ceiling, self/duplicate, active edge, hop, and feature constraints before use.

## Adapter Constructors

```rust
pub mod adapters {
    #[cfg(feature = "json")]
    pub fn json_store(path: std::path::PathBuf)
        -> std::sync::Arc<dyn crate::extension::StorageFactory>;

    #[cfg(feature = "redb")]
    pub fn redb_store(path: std::path::PathBuf)
        -> std::sync::Arc<dyn crate::extension::StorageFactory>;
}
```

JSON remains test-only and reports its platform capability. Constructors return trait objects; concrete
adapter types are not public.

## Root Reexports

`src/lib.rs` keeps implementation modules private and deliberately reexports:

```rust
pub use crate::api::{
    BoxFuture, Command, Error, ErrorKind, Event, EventOptions, EventReceive,
    EventSubscription, NodeHandle, ProviderErrorContext, ProviderErrorKind, Query, Result,
};
pub use crate::builder::{
    AdmissionLimits, ExtensionRegistry, NodeBuilder, NodeConfig, ProtocolLimits, TraceLimits,
};
pub use crate::identity::{
    AdmissionView, ClusterId, ClusterView, IssuedJoinCredential, JoinCredential,
    LocalNodeView, NodeId, PublicKey, RevokeOutcome, Signature, TrustStatus,
    TrustedIdentityView,
};
pub use crate::operation::{
    CleanupState, CreateCluster, DeleteState, DirectRequest, DisconnectPeer, GetClockHealth,
    GetDelivery, GetLocalNode, GetMember, GetNodeResource, GetNodeStatus, GetObservability,
    GetState, GetTopology, JoinCluster, LeaveCluster, Listen, ListListeners, ListMembers,
    ListNodeResources, ListSessionFeatures, ListSessions, ListTrust, MutateLabels, PutState,
    RevokeNode, RotateJoinCredential, RoutedRequest, ScanState, SelectNodes, Shutdown,
    StopListener, UpdateDescriptor, WaitForShutdown,
};
pub use crate::protocol::{
    Digest, DiscoveryTag, EventTag, FeatureDefinition, FeatureTag, LimitDefinition, LimitUnit,
    LimitWidth, ProtocolDefinition, ProtocolTag, QualifiedTag, ResourceTag, SchemaTag, TraceId,
    TransportTag,
};
pub use crate::view::{
    AcceptStaleReplicaResurrection, CleanupOutcome, ClockHealth,
    ClockHealthView, ConnectivityStatus, DeliveryReceipt, DeliveryStatus, DeliveryView,
    DescriptorPatch, DirectReply, Endpoint, EndpointView, EquivocationObserved, HlcTimestamp,
    IdentityReplaced, LabelChange, LabelsChanged,
    LabelKey, LabelSetView, LabelValue, LeaveOutcome, ListenerId, ListenerView,
    MemberChanged, MemberView, MonotonicTime, NodeRevoked, NodeStatus, ObservabilitySnapshot,
    ReplaceIdentityAndDeleteOldLocalState, ResourceSnapshot, ResourceView, Selector,
    SessionChanged, SessionFeatureView, SessionId, SessionView, ShutdownOutcome,
    ShutdownReason, StateChanged, StateCleaned, StateCursor, StateKey, StatePage,
    StatePrecondition, StateRecordView, StateValue, StateVersion, TopologyEdgeView,
    TopologyView,
};

pub mod extension {
    pub use crate::extension_impl::{
        ChannelBinding, Clock, CommitOutcome, CommitReceipt, CreatedKey, Discovery,
        DiscoveryContext, DiscoveredEndpoint, DurabilityLevel, Entropy, HandlerReply, KeyCreateState,
        KeyDeleteState, KeyHandle, KeyOperationId, KeyProvider, NeighborPlan,
        NeighborPolicy, NeighborPolicyInput, ProtocolHandler, ReconcileOutcome,
        RequestContext, RouteContext, RoutingPolicy, StateCodec, Storage, StorageFactory,
        StoreCapabilities, StoreEntry, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
        StoreRequirements, StoreRevision, StoreSnapshot, StoreTransaction, StoreValue,
        TransactionId, Transport, TransportConnection, TransportListener,
    };
}
```

`tests/public_api.rs` compares the actual root inventory with this manifest and forbids wildcard or
duplicate reexports.

## Operation Ownership

| Surface | Primary task |
| --- | --- |
| Values, errors, tags, config | T-G01-01 |
| Builder, typed bus lifecycle, clock/entropy | T-G01-02 |
| Storage/key-provider SPI declarations required by `NodeBuilder` | T-G01-02 |
| Storage/key-provider validation, behavior, implementations, and contract suites | T-G02-01/T-G02-02 |
| Listen, join, direct protocol | T-G03-02 |
| Feature/handler registry | T-G03-01 |
| Session/trust views | T-G04-05 |
| Descriptor/member/topology operations | T-G05-01/T-G05-03 |
| Routed request/delivery views | T-G06-05 |
| State/clock query and private cleanup machinery | T-G07-03/T-G07-05 |
| Storage factory/adapters | T-G08-01/T-G08-02 |
| Labels, selectors, revoke, CleanupState, leave, events | T-G09-02..T-G09-07 |
| Public observability snapshot | T-G10-05 |
| Final exact API approval | T-G10-08 |

## Compatibility Rules

- Before the functional `0.1.0` candidate, amendments are allowed only before the owning task enters RED.
- After functional `0.1.0`, removing/renaming a public item, changing a parameter/output/trait bound,
  unsealing a local command, or exposing implementation types is breaking.
- Adding a sealed built-in command/query/event or non-required view accessor is normally additive and
  requires a minor release plus scenario/evidence impact.
- Adding a required object-safe trait method is breaking; extension traits must use additive companion
  traits or a planned major boundary.
- Delivery `Accepted` always means durable destination acceptance, never handler/application success.
- Resource/platform labels remain informational; only authenticated feature selection authorizes behavior.

pub(crate) mod private {
  pub trait Sealed {}
}

use crate::{Endpoint, JoinCredential, NodeId, identity::ListenerId, packet::RouteHandle};

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

pub struct Shutdown {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl Shutdown {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for Shutdown {}

impl Command for Shutdown {
  type Output = crate::ShutdownOutcome;
}

pub struct CreateCluster {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl CreateCluster {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for CreateCluster {}

impl Command for CreateCluster {
  type Output = crate::ClusterView;
}

pub struct RotateJoinCredential {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl RotateJoinCredential {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for RotateJoinCredential {}

impl Command for RotateJoinCredential {
  type Output = crate::IssuedJoinCredential;
}

pub struct Listen {
  endpoint: Endpoint,
}

impl Listen {
  pub fn new(endpoint: Endpoint) -> Self {
    Self { endpoint }
  }

  pub(crate) fn into_endpoint(self) -> Endpoint {
    self.endpoint
  }
}

impl private::Sealed for Listen {}

impl Command for Listen {
  type Output = crate::ListenerView;
}

pub struct StopListener {
  listener: ListenerId,
}

impl StopListener {
  pub fn new(listener: ListenerId) -> Self {
    Self { listener }
  }

  pub(crate) fn into_listener(self) -> ListenerId {
    self.listener
  }
}

impl private::Sealed for StopListener {}

impl Command for StopListener {
  type Output = ();
}

pub struct JoinCluster {
  receiver: Endpoint,
  credential: JoinCredential,
}

impl JoinCluster {
  pub fn new(receiver: Endpoint, credential: JoinCredential) -> Self {
    Self {
      receiver,
      credential,
    }
  }

  pub(crate) fn into_parts(self) -> (Endpoint, JoinCredential) {
    (self.receiver, self.credential)
  }
}

impl private::Sealed for JoinCluster {}

impl Command for JoinCluster {
  type Output = crate::AdmissionView;
}

/// Connects to an already-admitted peer using key trust only (G3-04): no
/// join credential is consulted or required, the expected peer's trusted
/// identity binding gates the handshake, and the negotiated feature policy
/// is the same exact offer/selection machinery as a join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectMember {
  receiver: Endpoint,
  peer: NodeId,
}

impl ConnectMember {
  /// `receiver` is the peer's listen endpoint; `peer` is the expected
  /// node identity whose trusted binding must already exist.
  pub fn new(receiver: Endpoint, peer: NodeId) -> Self {
    Self { receiver, peer }
  }

  pub(crate) fn into_parts(self) -> (Endpoint, NodeId) {
    (self.receiver, self.peer)
  }
}

impl private::Sealed for ConnectMember {}

impl Command for ConnectMember {
  type Output = crate::NodeId;
}

pub struct GetNodeStatus {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl GetNodeStatus {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for GetNodeStatus {}

impl Query for GetNodeStatus {
  type Output = crate::NodeStatus;
}

pub struct GetLocalNode {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl GetLocalNode {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for GetLocalNode {}

impl Query for GetLocalNode {
  type Output = crate::LocalNodeView;
}

pub struct WaitForShutdown {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl WaitForShutdown {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for WaitForShutdown {}

impl Query for WaitForShutdown {
  type Output = crate::ShutdownReason;
}

/// Queries one member's public observation (G5-06).
pub struct GetMember {
  node: NodeId,
}

impl GetMember {
  pub fn new(node: NodeId) -> Self {
    Self { node }
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }
}

impl private::Sealed for GetMember {}

impl Query for GetMember {
  type Output = Option<crate::MemberView>;
}

/// Pages the public membership observations (G5-06).
pub struct PageMembers {
  page: crate::PageSpec,
}

impl PageMembers {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageMembers {}

impl Query for PageMembers {
  type Output = crate::MemberPage;
}

/// Pages the live resource winners matching one selector (T-G09-02).
pub struct SelectResources {
  selector: crate::Selector,
  page: crate::PageSpec,
}

impl SelectResources {
  pub fn new(selector: crate::Selector, page: crate::PageSpec) -> Self {
    Self { selector, page }
  }

  pub(crate) const fn selector(&self) -> &crate::Selector {
    &self.selector
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for SelectResources {}

impl Query for SelectResources {
  type Output = crate::ResourcePage;
}

/// One caller-authored resource write intent (T-G09-03): the stable name
/// plus its reserved and custom labels. Core stamps the wall-clock tuple
/// and signs the candidate record when the command executes; the caller
/// never supplies a timestamp, writer, or signature.
pub struct ResourceWrite {
  name: crate::ResourceName,
  labels: crate::ResourceLabels,
}

impl ResourceWrite {
  pub fn new(name: crate::ResourceName, labels: crate::ResourceLabels) -> Self {
    Self { name, labels }
  }

  pub(crate) const fn name(&self) -> &crate::ResourceName {
    &self.name
  }

  pub(crate) const fn labels(&self) -> &crate::ResourceLabels {
    &self.labels
  }
}

/// Commits one resource write intent as a signed candidate record
/// (T-G09-03). Acceptance never promises the candidate becomes or stays
/// the tuple winner; the outcome view reports the accepted record and
/// whether it is the current winner.
pub struct PutResource {
  write: ResourceWrite,
}

impl PutResource {
  /// Validates the write's encoded shape before it reaches the runtime:
  /// a candidate that can never fit the canonical record envelope is
  /// rejected here, before any signing or storage work.
  pub fn new(record: ResourceWrite) -> crate::Result<Self> {
    crate::resource::check_write_shape(record.name(), record.labels())?;
    Ok(Self { write: record })
  }

  pub(crate) fn into_write(self) -> ResourceWrite {
    self.write
  }
}

impl private::Sealed for PutResource {}

impl Command for PutResource {
  type Output = crate::ResourceMutationView;
}

/// Revokes one exact subject binding's connection and admission authority
/// (T-G09-04, ADR-0006): a durable local authorization boundary that
/// closes the identity's sessions and rejects its new sessions, raw
/// grants, and admissions — without deleting or reinterpreting any stored
/// metadata. `expected_key` pins the exact trusted binding so a stale or
/// substituted revocation fails closed.
pub struct RevokeNode {
  subject: NodeId,
  expected_key: crate::PublicKey,
}

impl RevokeNode {
  pub fn new(subject: NodeId, expected_key: crate::PublicKey) -> Self {
    Self {
      subject,
      expected_key,
    }
  }

  pub(crate) fn into_parts(self) -> (NodeId, crate::PublicKey) {
    (self.subject, self.expected_key)
  }
}

impl private::Sealed for RevokeNode {}

impl Command for RevokeNode {
  type Output = crate::RevokeOutcome;
}

/// Creates signed removal evidence for one resource (T-G09-05): the
/// removal commits only when the locally stored winner still equals
/// `expected` exactly and the removal strictly wins the tuple, so a stale
/// request never removes newer metadata and never poses as a newer
/// wall-clock winner. Removal is limited to core metadata; core never
/// follows the resource URI or touches the caller's object.
pub struct RemoveResource {
  name: crate::ResourceName,
  expected: crate::ResourceVersion,
}

impl RemoveResource {
  pub fn new(name: crate::ResourceName, expected: crate::ResourceVersion) -> Self {
    Self { name, expected }
  }

  pub(crate) fn into_parts(self) -> (crate::ResourceName, crate::ResourceVersion) {
    (self.name, self.expected)
  }
}

impl private::Sealed for RemoveResource {}

impl Command for RemoveResource {
  type Output = crate::ResourceMutationView;
}

/// A locally revoked identity lost connection and admission authority
/// (T-G09-04). Emitted once per revocation transition, after the durable
/// commit; an idempotent repeated revoke emits nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRevoked {
  subject: NodeId,
}

impl NodeRevoked {
  pub fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) const fn new(subject: NodeId) -> Self {
    Self { subject }
  }
}

impl private::Sealed for NodeRevoked {}

impl Event for NodeRevoked {}

/// One committed local resource candidate became visible in the catalog
/// (T-G09-03). Emitted exactly once after the candidate's durable commit;
/// the command's [`crate::ResourceMutationView`] reports whether that
/// candidate is the current winner. Aborted and indeterminate candidates
/// emit nothing, and restart or maintenance never replays the event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceChanged {
  resource: crate::ResourceName,
}

impl ResourceChanged {
  pub fn resource(&self) -> &crate::ResourceName {
    &self.resource
  }

  pub(crate) const fn new(resource: crate::ResourceName) -> Self {
    Self { resource }
  }
}

impl private::Sealed for ResourceChanged {}

impl Event for ResourceChanged {}

/// Pages the public topology edges (G5-06).
pub struct PageTopology {
  page: crate::PageSpec,
}

impl PageTopology {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageTopology {}

impl Query for PageTopology {
  type Output = crate::TopologyPage;
}

/// Pages the public trust observations (G5-06).
pub struct PageTrust {
  page: crate::PageSpec,
}

impl PageTrust {
  pub fn new(page: crate::PageSpec) -> Self {
    Self { page }
  }

  pub(crate) const fn page(&self) -> &crate::PageSpec {
    &self.page
  }
}

impl private::Sealed for PageTrust {}

impl Query for PageTrust {
  type Output = crate::TrustPage;
}

/// Forces one bounded immediate recovery cycle and returns its view
/// (G5-06).
pub struct StartRecovery {
  _private: (),
}

#[allow(clippy::new_without_default)]
impl StartRecovery {
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl private::Sealed for StartRecovery {}

impl Command for StartRecovery {
  type Output = crate::RecoveryView;
}

/// Closes the authenticated session to one peer (G5-06, partition
/// simulation and failure matrix).
pub struct DisconnectPeer {
  peer: NodeId,
}

impl DisconnectPeer {
  pub fn new(peer: NodeId) -> Self {
    Self { peer }
  }

  pub(crate) const fn peer(&self) -> &NodeId {
    &self.peer
  }
}

impl private::Sealed for DisconnectPeer {}

impl Command for DisconnectPeer {
  type Output = ();
}

/// Updates the local node's own descriptor (owner-only node metadata,
/// ADR-0007): endpoint candidates and capability labels are applied at a
/// strictly higher revision than `expected_revision`, and the updated
/// member view is returned. Same-revision or stale expectations conflict.
pub struct UpdateNodeMetadata {
  expected_revision: u64,
  patch: crate::NodeMetadataPatch,
}

impl UpdateNodeMetadata {
  pub fn new(expected_revision: u64, patch: crate::NodeMetadataPatch) -> Self {
    Self {
      expected_revision,
      patch,
    }
  }

  pub(crate) fn into_parts(self) -> (u64, crate::NodeMetadataPatch) {
    (self.expected_revision, self.patch)
  }
}

impl private::Sealed for UpdateNodeMetadata {}

impl Command for UpdateNodeMetadata {
  type Output = crate::MemberView;
}

/// Queries the in-memory route status of one packet route handle
/// (ADR-0007: bounded trace metadata only, no durability claim).
pub struct GetRoute {
  handle: RouteHandle,
}

impl GetRoute {
  pub fn new(handle: RouteHandle) -> Self {
    Self { handle }
  }

  pub(crate) const fn handle(&self) -> &RouteHandle {
    &self.handle
  }
}

impl private::Sealed for GetRoute {}

impl Query for GetRoute {
  type Output = crate::RouteStatusView;
}

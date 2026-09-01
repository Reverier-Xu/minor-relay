use crate::{ClusterId, Endpoint, Error, ErrorKind, NodeId, PublicKey, identity::ListenerId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NodeStatus {
  Starting,
  Running,
  ShuttingDown,
  Stopped,
  Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ShutdownReason {
  Explicit,
  ActiveLeave,
  Fatal(ErrorKind),
}

/// The created or existing local cluster returned by `CreateCluster`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterView {
  cluster_id: ClusterId,
  creator: NodeId,
}

impl ClusterView {
  pub fn cluster_id(&self) -> &ClusterId {
    &self.cluster_id
  }

  pub fn creator(&self) -> &NodeId {
    &self.creator
  }

  pub(crate) const fn new(cluster_id: ClusterId, creator: NodeId) -> Self {
    Self {
      cluster_id,
      creator,
    }
  }
}

/// The completed admission returned by `JoinCluster`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionView {
  cluster_id: ClusterId,
  admitted_node: NodeId,
  issuer: NodeId,
}

impl AdmissionView {
  pub fn cluster_id(&self) -> &ClusterId {
    &self.cluster_id
  }

  pub fn admitted_node(&self) -> &NodeId {
    &self.admitted_node
  }

  pub fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) const fn new(cluster_id: ClusterId, admitted_node: NodeId, issuer: NodeId) -> Self {
    Self {
      cluster_id,
      admitted_node,
      issuer,
    }
  }
}

/// One bound listener returned by `Listen`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerView {
  id: ListenerId,
  endpoint: Endpoint,
}

impl ListenerView {
  pub fn id(&self) -> &ListenerId {
    &self.id
  }

  pub fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub(crate) const fn new(id: ListenerId, endpoint: Endpoint) -> Self {
    Self { id, endpoint }
  }
}

/// The local node's identity and cluster membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeView {
  cluster_id: ClusterId,
  node_id: NodeId,
  public_key: PublicKey,
}

impl LocalNodeView {
  pub fn cluster_id(&self) -> &ClusterId {
    &self.cluster_id
  }

  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) const fn new(cluster_id: ClusterId, node_id: NodeId, public_key: PublicKey) -> Self {
    Self {
      cluster_id,
      node_id,
      public_key,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownOutcome {
  reason: ShutdownReason,
}

impl ShutdownOutcome {
  pub fn reason(&self) -> &ShutdownReason {
    &self.reason
  }

  pub(crate) const fn new(reason: ShutdownReason) -> Self {
    Self { reason }
  }
}

// ---- G5 public membership and topology views (SC-G05-P0-23..26) ----

/// The connectivity of one member as observed locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectivityStatus {
  /// No observation yet.
  Unknown,
  /// Known but no session and not a neighbor candidate.
  Offline,
  /// Has candidate endpoints but no authenticated session.
  Reachable,
  /// Has an authenticated session.
  Connected,
}

/// One public member observation: the exact owner-marked descriptor plus the
/// local connectivity view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberView {
  node_id: NodeId,
  public_key: PublicKey,
  owner_revision: u64,
  digest: crate::Digest,
  connectivity: ConnectivityStatus,
  endpoints: Vec<Endpoint>,
  labels: crate::LabelSet,
}

impl MemberView {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub fn owner_revision(&self) -> u64 {
    self.owner_revision
  }

  pub fn digest(&self) -> &crate::Digest {
    &self.digest
  }

  pub fn connectivity(&self) -> ConnectivityStatus {
    self.connectivity
  }

  pub fn endpoints(&self) -> &[Endpoint] {
    &self.endpoints
  }

  /// The member's node-owned capability labels (SC-G06-P0-02).
  pub fn labels(&self) -> &crate::LabelSet {
    &self.labels
  }

  pub(crate) fn new(
    node_id: NodeId, public_key: PublicKey, owner_revision: u64, digest: crate::Digest,
    connectivity: ConnectivityStatus, endpoints: Vec<Endpoint>, labels: crate::LabelSet,
  ) -> Self {
    Self {
      node_id,
      public_key,
      owner_revision,
      digest,
      connectivity,
      endpoints,
      labels,
    }
  }
}

/// The caller-built patch behind the `UpdateNodeMetadata` command: the
/// owning node's bounded edits to its own descriptor, applied at a strictly
/// higher revision (ADR-0007 owner-only records).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeMetadataPatch {
  add_endpoints: Vec<Endpoint>,
  remove_endpoints: Vec<Endpoint>,
  set_labels: Vec<(crate::LabelKey, crate::LabelValue)>,
  remove_labels: Vec<crate::LabelKey>,
}

/// The validated edits carried by one [`NodeMetadataPatch`].
pub(crate) struct PatchParts {
  pub(crate) add_endpoints: Vec<Endpoint>,
  pub(crate) remove_endpoints: Vec<Endpoint>,
  pub(crate) set_labels: Vec<(crate::LabelKey, crate::LabelValue)>,
  pub(crate) remove_labels: Vec<crate::LabelKey>,
}

impl NodeMetadataPatch {
  pub fn new() -> Self {
    Self::default()
  }

  /// Adds one endpoint candidate. Duplicates within one patch are
  /// rejected.
  pub fn add_endpoint(mut self, endpoint: Endpoint) -> crate::Result<Self> {
    if self.add_endpoints.contains(&endpoint) {
      return Err(Error::conflict("node metadata endpoint"));
    }
    self.add_endpoints.push(endpoint);
    Ok(self)
  }

  /// Removes one endpoint candidate; removing an unknown endpoint fails.
  /// Removals apply to the record as it exists after the additions.
  pub fn remove_endpoint(mut self, endpoint: Endpoint) -> crate::Result<Self> {
    self.remove_endpoints.push(endpoint);
    Ok(self)
  }

  /// Sets one capability label. Setting the same key twice in one patch
  /// is rejected.
  pub fn set_capability(
    mut self, key: crate::LabelKey, value: crate::LabelValue,
  ) -> crate::Result<Self> {
    if self.set_labels.iter().any(|(existing, _)| existing == &key) {
      return Err(Error::conflict("node metadata label"));
    }
    self.set_labels.push((key, value));
    Ok(self)
  }

  /// Removes one capability label; removing an unknown key fails at
  /// apply time against the current record.
  pub fn remove_capability(mut self, key: crate::LabelKey) -> crate::Result<Self> {
    self.remove_labels.push(key);
    Ok(self)
  }

  pub(crate) fn into_parts(self) -> PatchParts {
    PatchParts {
      add_endpoints: self.add_endpoints,
      remove_endpoints: self.remove_endpoints,
      set_labels: self.set_labels,
      remove_labels: self.remove_labels,
    }
  }
}

/// One bounded page of member observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberPage {
  items: Vec<MemberView>,
  next: Option<crate::PageCursor>,
}

impl MemberPage {
  pub fn items(&self) -> &[MemberView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<MemberView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// One public resource observation: the winning record's stable name,
/// its reserved-plus-custom labels, and its exact tuple version.
///
/// A resource whose current winner is a signed removal is not observed:
/// removal evidence stays internal, and a removed name reads as absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceView {
  name: crate::ResourceName,
  labels: crate::ResourceLabels,
  version: crate::ResourceVersion,
}

impl ResourceView {
  pub fn name(&self) -> &crate::ResourceName {
    &self.name
  }

  pub fn labels(&self) -> &crate::ResourceLabels {
    &self.labels
  }

  pub fn version(&self) -> &crate::ResourceVersion {
    &self.version
  }

  pub(crate) fn new(
    name: crate::ResourceName, labels: crate::ResourceLabels, version: crate::ResourceVersion,
  ) -> Self {
    Self {
      name,
      labels,
      version,
    }
  }
}

/// One bounded page of resource observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePage {
  items: Vec<ResourceView>,
  next: Option<crate::PageCursor>,
}

impl ResourcePage {
  pub fn items(&self) -> &[ResourceView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<ResourceView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// The outcome of one local resource mutation (T-G09-03/05): the accepted
/// signed candidate plus whether that candidate is the register's current
/// tuple winner. Acceptance is not a promise of winning or staying
/// current; a losing candidate stays harmless.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceMutationView {
  accepted: ResourceView,
  current_winner: bool,
}

impl ResourceMutationView {
  /// The accepted candidate as committed (or offered) locally.
  pub fn accepted(&self) -> &ResourceView {
    &self.accepted
  }

  /// Whether the accepted candidate is the register's current winner.
  pub fn is_current_winner(&self) -> bool {
    self.current_winner
  }

  pub(crate) fn new(accepted: ResourceView, current_winner: bool) -> Self {
    Self {
      accepted,
      current_winner,
    }
  }
}

/// The explicit acknowledgement required by [`crate::LeaveCluster`]
/// (T-G09-06): constructing it is the caller's deliberate confirmation
/// that the leave replaces the node's identity and deletes the old
/// identity's local core metadata. It has no `Default`, so the
/// acknowledgement cannot be produced accidentally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceIdentityAndDeleteOldCoreMetadata {
  acknowledged: bool,
}

impl ReplaceIdentityAndDeleteOldCoreMetadata {
  /// Constructs the acknowledgement; there is deliberately no `Default`
  /// so the acknowledgement cannot be produced accidentally.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self { acknowledged: true }
  }

  pub(crate) const fn is_acknowledged(&self) -> bool {
    self.acknowledged
  }
}

/// The outcome of one active leave (T-G09-06): the exact former and
/// replacement identities, bound together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaveOutcome {
  former_identity: NodeId,
  replacement_identity: NodeId,
}

impl LeaveOutcome {
  pub fn former_identity(&self) -> &NodeId {
    &self.former_identity
  }

  pub fn replacement_identity(&self) -> &NodeId {
    &self.replacement_identity
  }

  pub(crate) const fn new(former_identity: NodeId, replacement_identity: NodeId) -> Self {
    Self {
      former_identity,
      replacement_identity,
    }
  }
}

/// The outcome of one authorization revoke (T-G09-04): the exact subject
/// and whether this call performed the revocation transition (an
/// idempotent repeated revoke reports `true` for `was_already_revoked`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeOutcome {
  subject: NodeId,
  was_already_revoked: bool,
}

impl RevokeOutcome {
  pub fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub fn was_already_revoked(&self) -> bool {
    self.was_already_revoked
  }

  pub(crate) const fn new(subject: NodeId, was_already_revoked: bool) -> Self {
    Self {
      subject,
      was_already_revoked,
    }
  }
}

/// One public topology edge: a directed session between two members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyEdgeView {
  source: NodeId,
  destination: NodeId,
  connected: bool,
  observed_at: std::time::SystemTime,
}

impl TopologyEdgeView {
  pub fn source(&self) -> &NodeId {
    &self.source
  }

  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  pub fn connected(&self) -> bool {
    self.connected
  }

  pub fn observed_at(&self) -> std::time::SystemTime {
    self.observed_at
  }

  pub(crate) fn new(
    source: NodeId, destination: NodeId, connected: bool, observed_at: std::time::SystemTime,
  ) -> Self {
    Self {
      source,
      destination,
      connected,
      observed_at,
    }
  }
}

/// One bounded page of topology edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyPage {
  items: Vec<TopologyEdgeView>,
  next: Option<crate::PageCursor>,
}

impl TopologyPage {
  pub fn items(&self) -> &[TopologyEdgeView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<TopologyEdgeView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// One paged query spec: a bounded first page or a continuation after a
/// cursor (api-manifest shape).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageSpec {
  cursor: Option<crate::PageCursor>,
  limit: usize,
}

impl PageSpec {
  pub fn first(limit: usize) -> crate::Result<Self> {
    Self::build(None, limit)
  }

  pub fn after(cursor: crate::PageCursor, limit: usize) -> crate::Result<Self> {
    Self::build(Some(cursor), limit)
  }

  /// The single limit check behind both constructors: a first page and a
  /// continuation differ only in their cursor.
  fn build(cursor: Option<crate::PageCursor>, limit: usize) -> crate::Result<Self> {
    if limit == 0 {
      return Err(crate::Error::invalid_input("page limit"));
    }
    Ok(Self { cursor, limit })
  }

  pub(crate) const fn cursor(&self) -> Option<&crate::PageCursor> {
    self.cursor.as_ref()
  }

  pub(crate) const fn limit(&self) -> usize {
    self.limit
  }
}

// ---- G5 trust and recovery views (SC-G05-P0-24..30) ----

/// The trust status of one observed identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrustStatus {
  /// The binding is trusted (verified from an admission grant or an
  /// issuer snapshot).
  Trusted,
  /// The binding was revoked (G9 wires revocation).
  Revoked,
}

/// One public trust observation: an exact NodeId-to-key binding with its
/// status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedIdentityView {
  node_id: NodeId,
  public_key: PublicKey,
  status: TrustStatus,
}

impl TrustedIdentityView {
  pub fn node_id(&self) -> &NodeId {
    &self.node_id
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub const fn status(&self) -> TrustStatus {
    self.status
  }

  pub(crate) const fn new(node_id: NodeId, public_key: PublicKey, status: TrustStatus) -> Self {
    Self {
      node_id,
      public_key,
      status,
    }
  }
}

/// One bounded page of trust observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPage {
  items: Vec<TrustedIdentityView>,
  next: Option<crate::PageCursor>,
}

impl TrustPage {
  pub fn items(&self) -> &[TrustedIdentityView] {
    &self.items
  }

  pub fn next(&self) -> Option<&crate::PageCursor> {
    self.next.as_ref()
  }

  pub(crate) fn new(items: Vec<TrustedIdentityView>, next: Option<crate::PageCursor>) -> Self {
    Self { items, next }
  }
}

/// The public view of one immediate recovery observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryView {
  is_connected: bool,
  unreachable_components: usize,
  next_attempt_at: Option<std::time::SystemTime>,
}

impl RecoveryView {
  pub const fn is_connected(&self) -> bool {
    self.is_connected
  }

  pub const fn unreachable_components(&self) -> usize {
    self.unreachable_components
  }

  pub const fn next_attempt_at(&self) -> Option<std::time::SystemTime> {
    self.next_attempt_at
  }

  pub(crate) const fn new(
    is_connected: bool, unreachable_components: usize,
    next_attempt_at: Option<std::time::SystemTime>,
  ) -> Self {
    Self {
      is_connected,
      unreachable_components,
      next_attempt_at,
    }
  }
}

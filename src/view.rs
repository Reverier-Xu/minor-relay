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
pub(crate) type PatchParts = (
  Vec<Endpoint>,
  Vec<Endpoint>,
  Vec<(crate::LabelKey, crate::LabelValue)>,
  Vec<crate::LabelKey>,
);

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
    (
      self.add_endpoints,
      self.remove_endpoints,
      self.set_labels,
      self.remove_labels,
    )
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
    if limit == 0 {
      return Err(crate::Error::invalid_input("page limit"));
    }
    Ok(Self {
      cursor: None,
      limit,
    })
  }

  pub fn after(cursor: crate::PageCursor, limit: usize) -> crate::Result<Self> {
    if limit == 0 {
      return Err(crate::Error::invalid_input("page limit"));
    }
    Ok(Self {
      cursor: Some(cursor),
      limit,
    })
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

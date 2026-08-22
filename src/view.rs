use crate::{ClusterId, Endpoint, ErrorKind, NodeId, PublicKey, identity::ListenerId};

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

/// One public member observation: the exact signed descriptor plus the
/// local connectivity view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberView {
  node_id: NodeId,
  public_key: PublicKey,
  owner_revision: u64,
  digest: crate::Digest,
  connectivity: ConnectivityStatus,
  endpoints: Vec<Endpoint>,
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

  pub(crate) fn new(
    node_id: NodeId, public_key: PublicKey, owner_revision: u64, digest: crate::Digest,
    connectivity: ConnectivityStatus, endpoints: Vec<Endpoint>,
  ) -> Self {
    Self {
      node_id,
      public_key,
      owner_revision,
      digest,
      connectivity,
      endpoints,
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

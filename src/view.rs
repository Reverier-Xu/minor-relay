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

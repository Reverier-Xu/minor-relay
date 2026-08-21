pub(crate) mod private {
  pub trait Sealed {}
}

use crate::{Endpoint, JoinCredential, identity::ListenerId, packet::RouteHandle};

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

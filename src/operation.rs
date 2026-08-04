pub(crate) mod private {
  pub trait Sealed {}
}

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

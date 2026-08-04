use crate::ErrorKind;

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
  Requested,
  ActiveLeave,
  Fatal(ErrorKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownOutcome {
  already_stopped: bool,
}

impl ShutdownOutcome {
  pub fn already_stopped(&self) -> bool {
    self.already_stopped
  }
}

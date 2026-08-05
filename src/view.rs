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
  Explicit,
  ActiveLeave,
  Fatal(ErrorKind),
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

use tokio::sync::{mpsc, watch};

use crate::NodeStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleSnapshot {
  status: NodeStatus,
}

impl LifecycleSnapshot {
  pub(crate) const fn starting() -> Self {
    Self {
      status: NodeStatus::Starting,
    }
  }

  pub(crate) const fn running() -> Self {
    Self {
      status: NodeStatus::Running,
    }
  }

  pub(crate) const fn stopped() -> Self {
    Self {
      status: NodeStatus::Stopped,
    }
  }

  pub(crate) const fn status(self) -> NodeStatus {
    self.status
  }
}

#[derive(Clone)]
pub(crate) struct RuntimeClient {
  _control: mpsc::Sender<()>,
  state: watch::Receiver<LifecycleSnapshot>,
}

impl RuntimeClient {
  pub(crate) fn new(control: mpsc::Sender<()>, state: watch::Receiver<LifecycleSnapshot>) -> Self {
    Self {
      _control: control,
      state,
    }
  }

  pub(crate) fn status(&self) -> NodeStatus {
    self.state.borrow().status()
  }
}

use tokio::sync::{mpsc, oneshot, watch};

use crate::{Error, NodeStatus, Result, ShutdownOutcome, ShutdownReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleSnapshot {
  status: NodeStatus,
  reason: Option<ShutdownReason>,
}

impl LifecycleSnapshot {
  pub(crate) const fn starting() -> Self {
    Self {
      status: NodeStatus::Starting,
      reason: None,
    }
  }

  pub(crate) const fn running() -> Self {
    Self {
      status: NodeStatus::Running,
      reason: None,
    }
  }

  pub(crate) const fn shutting_down() -> Self {
    Self {
      status: NodeStatus::ShuttingDown,
      reason: None,
    }
  }

  pub(crate) const fn stopped(reason: ShutdownReason) -> Self {
    Self {
      status: NodeStatus::Stopped,
      reason: Some(reason),
    }
  }

  pub(crate) const fn status(self) -> NodeStatus {
    self.status
  }

  pub(crate) const fn reason(self) -> Option<ShutdownReason> {
    self.reason
  }
}

pub(crate) enum Control {
  Shutdown {
    reply: oneshot::Sender<ShutdownOutcome>,
  },
}

#[derive(Clone)]
pub(crate) struct RuntimeClient {
  control: mpsc::Sender<Control>,
  state: watch::Receiver<LifecycleSnapshot>,
}

impl RuntimeClient {
  pub(crate) fn new(
    control: mpsc::Sender<Control>, state: watch::Receiver<LifecycleSnapshot>,
  ) -> Self {
    Self { control, state }
  }

  pub(crate) fn status(&self) -> NodeStatus {
    self.state.borrow().status()
  }

  pub(crate) async fn shutdown(&self) -> Result<ShutdownOutcome> {
    if self.state.borrow().reason().is_some() {
      return Ok(ShutdownOutcome::new(true));
    }

    let (reply, response) = oneshot::channel();
    if self
      .control
      .send(Control::Shutdown { reply })
      .await
      .is_err()
    {
      self.wait_for_shutdown().await?;
      return Ok(ShutdownOutcome::new(true));
    }

    match response.await {
      Ok(outcome) => Ok(outcome),
      Err(_) => {
        self.wait_for_shutdown().await?;
        Ok(ShutdownOutcome::new(true))
      }
    }
  }

  pub(crate) async fn wait_for_shutdown(&self) -> Result<ShutdownReason> {
    let mut state = self.state.clone();
    loop {
      if let Some(reason) = state.borrow().reason() {
        return Ok(reason);
      }
      state
        .changed()
        .await
        .map_err(|_| Error::internal("node shutdown state"))?;
    }
  }
}

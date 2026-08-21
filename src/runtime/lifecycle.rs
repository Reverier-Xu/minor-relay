use tokio::sync::{mpsc, oneshot, watch};

use crate::{
  AdmissionView, ClusterView, Endpoint, Error, IssuedJoinCredential, ListenerView, LocalNodeView,
  NodeStatus, Result, ShutdownOutcome, ShutdownReason,
  identity::{ListenerId, credential::JoinCredential},
};

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

  pub(crate) const fn failed() -> Self {
    Self {
      status: NodeStatus::Failed,
      reason: Some(ShutdownReason::Fatal(crate::ErrorKind::Internal)),
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
  CreateCluster {
    reply: oneshot::Sender<Result<ClusterView>>,
  },
  RotateJoinCredential {
    reply: oneshot::Sender<Result<IssuedJoinCredential>>,
  },
  Listen {
    endpoint: Endpoint,
    reply: oneshot::Sender<Result<ListenerView>>,
  },
  StopListener {
    listener: ListenerId,
    reply: oneshot::Sender<Result<()>>,
  },
  JoinCluster {
    receiver: Endpoint,
    credential: JoinCredential,
    reply: oneshot::Sender<Result<AdmissionView>>,
  },
  GetLocalNode {
    reply: oneshot::Sender<Result<LocalNodeView>>,
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
    if let Some(reason) = self.state.borrow().reason() {
      return Ok(ShutdownOutcome::new(reason));
    }

    let (reply, response) = oneshot::channel();
    if self
      .control
      .send(Control::Shutdown { reply })
      .await
      .is_err()
    {
      return self.wait_for_shutdown().await.map(ShutdownOutcome::new);
    }

    match response.await {
      Ok(outcome) => Ok(outcome),
      Err(_) => self.wait_for_shutdown().await.map(ShutdownOutcome::new),
    }
  }

  async fn send_command<Output, Build>(&self, build: Build) -> Result<Output>
  where
    Build: FnOnce(oneshot::Sender<Result<Output>>) -> Control,
    Output: Send + 'static, {
    let (reply, response) = oneshot::channel();
    self
      .control
      .send(build(reply))
      .await
      .map_err(|_| Error::shutting_down("node control"))?;
    response
      .await
      .map_err(|_| Error::internal("node control reply"))?
  }

  pub(crate) async fn create_cluster(&self) -> Result<ClusterView> {
    self
      .send_command(|reply| Control::CreateCluster { reply })
      .await
  }

  pub(crate) async fn rotate_join_credential(&self) -> Result<IssuedJoinCredential> {
    self
      .send_command(|reply| Control::RotateJoinCredential { reply })
      .await
  }

  pub(crate) async fn listen(&self, endpoint: Endpoint) -> Result<ListenerView> {
    self
      .send_command(|reply| Control::Listen { endpoint, reply })
      .await
  }

  pub(crate) async fn stop_listener(&self, listener: ListenerId) -> Result<()> {
    self
      .send_command(|reply| Control::StopListener { listener, reply })
      .await
  }

  pub(crate) async fn join_cluster(
    &self, receiver: Endpoint, credential: JoinCredential,
  ) -> Result<AdmissionView> {
    self
      .send_command(|reply| Control::JoinCluster {
        receiver,
        credential,
        reply,
      })
      .await
  }

  pub(crate) async fn local_node(&self) -> Result<LocalNodeView> {
    self
      .send_command(|reply| Control::GetLocalNode { reply })
      .await
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

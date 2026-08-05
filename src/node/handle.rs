use std::any::{Any, TypeId};

use crate::{
  Command, Error, Event, EventOptions, EventSubscription, GetNodeStatus, NodeStatus, Query, Result,
  Shutdown, WaitForShutdown, runtime::RuntimeClient,
};

#[derive(Clone)]
pub struct NodeHandle {
  runtime: RuntimeClient,
}

impl NodeHandle {
  pub(crate) fn new(runtime: RuntimeClient) -> Self {
    Self { runtime }
  }

  pub async fn command<C: Command>(&self, command: C) -> Result<C::Output> {
    if TypeId::of::<C>() == TypeId::of::<Shutdown>() {
      drop(command);
      return cast_output(self.runtime.shutdown().await?);
    }

    drop(command);
    Err(Error::unsupported("node command"))
  }

  pub async fn query<Q: Query>(&self, query: Q) -> Result<Q::Output> {
    if TypeId::of::<Q>() == TypeId::of::<GetNodeStatus>() {
      drop(query);
      return cast_output(self.runtime.status());
    }
    if TypeId::of::<Q>() == TypeId::of::<WaitForShutdown>() {
      drop(query);
      return cast_output(self.runtime.wait_for_shutdown().await?);
    }

    drop(query);
    Err(Error::unsupported("node query"))
  }

  pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>> {
    let _ = options;
    if self.runtime.status() != NodeStatus::Running {
      return Err(Error::shutting_down("node events"));
    }
    Err(Error::unsupported("node events"))
  }
}

fn cast_output<Output, Value>(value: Value) -> Result<Output>
where
  Output: Send + 'static,
  Value: Any + Send, {
  let erased: Box<dyn Any + Send> = Box::new(value);
  erased
    .downcast::<Output>()
    .map(|output| *output)
    .map_err(|_| Error::internal("typed bus output"))
}

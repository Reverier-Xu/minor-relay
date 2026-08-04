use tokio::sync::broadcast;

use crate::{Error, Event, Result};

const DEFAULT_EVENT_CAPACITY: usize = 256;
const MAX_EVENT_CAPACITY: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOptions {
  capacity: usize,
}

impl EventOptions {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn capacity(mut self, value: usize) -> Result<Self> {
    if !(1..=MAX_EVENT_CAPACITY).contains(&value) {
      return Err(Error::invalid_input("event subscription capacity"));
    }
    self.capacity = value;
    Ok(self)
  }
}

impl Default for EventOptions {
  fn default() -> Self {
    Self {
      capacity: DEFAULT_EVENT_CAPACITY,
    }
  }
}

pub struct EventSubscription<E: Event> {
  receiver: broadcast::Receiver<E>,
}

impl<E: Event> EventSubscription<E> {
  pub async fn recv(&mut self) -> Result<EventReceive<E>> {
    let receive = match self.receiver.recv().await {
      Ok(event) => EventReceive::Item(event),
      Err(broadcast::error::RecvError::Lagged(missed)) => EventReceive::Lagged { missed },
      Err(broadcast::error::RecvError::Closed) => EventReceive::Closed,
    };
    Ok(receive)
  }

  pub fn try_recv(&mut self) -> Result<EventReceive<E>> {
    let receive = match self.receiver.try_recv() {
      Ok(event) => EventReceive::Item(event),
      Err(broadcast::error::TryRecvError::Empty) => EventReceive::Empty,
      Err(broadcast::error::TryRecvError::Lagged(missed)) => EventReceive::Lagged { missed },
      Err(broadcast::error::TryRecvError::Closed) => EventReceive::Closed,
    };
    Ok(receive)
  }
}

#[non_exhaustive]
pub enum EventReceive<E> {
  Item(E),
  Empty,
  Lagged { missed: u64 },
  Closed,
}

#[cfg(test)]
fn event_channel<E: Event>(options: EventOptions) -> (broadcast::Sender<E>, EventSubscription<E>) {
  let (sender, receiver) = broadcast::channel(options.capacity);
  (sender, EventSubscription { receiver })
}

#[cfg(test)]
mod tests {
  use super::event_channel;
  use crate::{Event, EventOptions, EventReceive, operation::private};

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct TestEvent(u8);

  impl private::Sealed for TestEvent {}
  impl Event for TestEvent {}

  #[tokio::test]
  async fn g1_lifecycle_event_subscription_reports_empty_lagged_and_closed() {
    let options = EventOptions::new().capacity(2).unwrap();
    let (sender, mut subscription) = event_channel::<TestEvent>(options);

    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Empty
    ));
    sender.send(TestEvent(1)).unwrap();
    sender.send(TestEvent(2)).unwrap();
    sender.send(TestEvent(3)).unwrap();

    assert!(matches!(
      subscription.try_recv().unwrap(),
      EventReceive::Lagged { missed: 1 }
    ));
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(2))
    ));
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Item(TestEvent(3))
    ));

    drop(sender);
    assert!(matches!(
      subscription.recv().await.unwrap(),
      EventReceive::Closed
    ));
  }
}

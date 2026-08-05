use tokio::sync::broadcast;

use crate::{Error, Event, Result};

const DEFAULT_EVENT_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOptions {
  capacity: usize,
}

impl EventOptions {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn capacity(mut self, value: usize) -> Result<Self> {
    validate_capacity(value)?;
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

fn validate_capacity(value: usize) -> Result<()> {
  if value == 0 {
    return Err(Error::invalid_input("event subscription capacity"));
  }
  let represented = value
    .checked_next_power_of_two()
    .ok_or_else(|| Error::invalid_input("event subscription capacity"))?;
  let mut allocation_probe = Vec::<u8>::new();
  allocation_probe
    .try_reserve_exact(represented)
    .map_err(|_| Error::resource_exhausted("event subscription capacity"))?;
  Ok(())
}

#[cfg(test)]
fn event_channel<E: Event>(options: EventOptions) -> (broadcast::Sender<E>, EventSubscription<E>) {
  let (sender, receiver) = broadcast::channel(options.capacity);
  (sender, EventSubscription { receiver })
}

#[cfg(test)]
mod tests {
  use super::event_channel;
  use crate::{ErrorKind, Event, EventOptions, EventReceive, operation::private};

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct TestEvent(u8);

  impl private::Sealed for TestEvent {}
  impl Event for TestEvent {}

  #[test]
  fn g1_lifecycle_event_capacity_accepts_values_above_old_maximum() {
    EventOptions::new().capacity(1_025).unwrap();
    EventOptions::new().capacity(4_097).unwrap();
    assert_eq!(
      EventOptions::new().capacity(0).unwrap_err().kind(),
      ErrorKind::InvalidInput,
    );
    assert_eq!(
      EventOptions::new().capacity(usize::MAX).unwrap_err().kind(),
      ErrorKind::InvalidInput,
    );
    assert_eq!(
      EventOptions::new()
        .capacity(isize::MAX as usize)
        .unwrap_err()
        .kind(),
      ErrorKind::ResourceExhausted,
    );
  }

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

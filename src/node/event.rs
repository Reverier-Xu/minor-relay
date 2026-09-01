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

/// The runtime event hub (T-G09-03): one typed subscriber set per event
/// type. Events are transient — an emission with no live subscriber is
/// dropped, a lagging subscriber observes `Lagged` and must re-read
/// through the paged queries, and nothing is retained for replay after
/// restart.
///
/// The hub holds each subscription's sender strongly so the channel stays
/// open for the subscriber's receiver; a sender whose receiver count
/// drops to zero is pruned on the next emission or subscription.
pub(crate) struct EventHub {
  subscribers: std::sync::Mutex<
    std::collections::HashMap<std::any::TypeId, Vec<Box<dyn std::any::Any + Send + Sync>>>,
  >,
}

impl EventHub {
  pub(crate) fn new() -> Self {
    Self {
      subscribers: std::sync::Mutex::new(std::collections::HashMap::new()),
    }
  }

  /// Locks the subscriber map, recovering from a poisoned lock: the map
  /// holds only plain subscriber vectors, so a panicking emitter cannot
  /// leave it inconsistent.
  fn lock(
    &self,
  ) -> std::sync::MutexGuard<
    '_,
    std::collections::HashMap<std::any::TypeId, Vec<Box<dyn std::any::Any + Send + Sync>>>,
  > {
    self
      .subscribers
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }

  /// Subscribes with an independent bounded channel per subscription, so
  /// one slow subscriber's lag never backpressures emitters or other
  /// subscribers.
  pub(crate) fn subscribe<E: Event>(&self, options: EventOptions) -> EventSubscription<E> {
    let (sender, receiver) = broadcast::channel(options.capacity);
    let mut subscribers = self.lock();
    let entries = subscribers.entry(std::any::TypeId::of::<E>()).or_default();
    Self::prune::<E>(entries);
    entries.push(Box::new(std::sync::Arc::new(sender)));
    EventSubscription { receiver }
  }

  /// Emits one event to every live subscriber of its type; a subscriber
  /// whose channel is full lags instead of blocking the emitter.
  pub(crate) fn emit<E: Event>(&self, event: E) {
    let mut subscribers = self.lock();
    let Some(entries) = subscribers.get_mut(&std::any::TypeId::of::<E>()) else {
      return;
    };
    for entry in entries.iter() {
      if let Some(sender) = entry.downcast_ref::<std::sync::Arc<broadcast::Sender<E>>>() {
        // A send error means this channel has no active receivers; the
        // transient event is gone and the next retain prunes the sender.
        let _ = sender.send(event.clone());
      }
    }
    Self::prune::<E>(entries);
  }

  /// Drops senders whose subscribers have all gone away.
  fn prune<E: Event>(entries: &mut Vec<Box<dyn std::any::Any + Send + Sync>>) {
    entries.retain(|entry| {
      entry
        .downcast_ref::<std::sync::Arc<broadcast::Sender<E>>>()
        .is_some_and(|sender| sender.receiver_count() > 0)
    });
  }
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

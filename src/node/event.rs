#[cfg(test)]
mod tests {
  use crate::{Event, EventOptions, EventReceive, operation::private};

  use super::event_channel;

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct TestEvent(u8);

  impl private::Sealed for TestEvent {}
  impl Event for TestEvent {}

  #[tokio::test]
  async fn g1_lifecycle_event_subscription_reports_empty_lagged_and_closed() {
    let options = EventOptions::new().capacity(2).unwrap();
    let (sender, mut subscription) = event_channel::<TestEvent>(options);

    assert!(matches!(subscription.try_recv().unwrap(), EventReceive::Empty));
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

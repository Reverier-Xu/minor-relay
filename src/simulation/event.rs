#[cfg(test)]
mod tests {
  use crate::simulation::{
    event::{DropReason, EventKey, EventLog, EventPhase, EventRecord, MessageId},
    topology::{AddressId, LinkKey, NodeKey},
  };

  #[test]
  fn simulation_event_order_is_total_at_equal_deadline() {
    let mut keys = vec![
      EventKey::new(10, EventPhase::Delivery, 0, 4, MessageId::new(2), 1, 7),
      EventKey::new(10, EventPhase::Topology, 0, 3, MessageId::new(0), 0, 6),
      EventKey::new(10, EventPhase::Send, 0, 2, MessageId::new(1), 0, 5),
      EventKey::new(10, EventPhase::Node, 0, 1, MessageId::new(0), 0, 4),
      EventKey::new(10, EventPhase::Delivery, 1, 4, MessageId::new(2), 0, 8),
    ];
    keys.sort();

    assert_eq!(
      keys.iter().map(|key| key.phase()).collect::<Vec<_>>(),
      [
        EventPhase::Topology,
        EventPhase::Node,
        EventPhase::Send,
        EventPhase::Delivery,
        EventPhase::Delivery,
      ],
    );
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
  }

  #[test]
  fn simulation_event_digest_is_canonical_and_behavior_only() {
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let records = [
      EventRecord::SendAccepted {
        at_nanos: 5,
        message: MessageId::new(9),
        link,
        copies: 2,
        bytes: 16,
      },
      EventRecord::Dropped {
        at_nanos: 7,
        message: MessageId::new(9),
        copy: 1,
        reason: DropReason::StaleAddress,
      },
      EventRecord::AddressChanged {
        at_nanos: 8,
        node: NodeKey::new(2),
        address: AddressId::new(22),
        generation: 1,
      },
    ];
    let mut first = EventLog::new(3).unwrap();
    let mut second = EventLog::new(3).unwrap();
    for record in records.clone() {
      first.push(record).unwrap();
    }
    for record in records {
      second.push(record).unwrap();
    }

    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.records(), second.records());

    let mut changed = EventLog::new(3).unwrap();
    changed
      .push(EventRecord::SendAccepted {
        at_nanos: 5,
        message: MessageId::new(9),
        link,
        copies: 1,
        bytes: 16,
      })
      .unwrap();
    assert_ne!(first.digest(), changed.digest());
  }

  #[test]
  fn simulation_event_log_rejects_capacity_before_mutation() {
    assert!(EventLog::new(0).is_err());
    let mut log = EventLog::new(1).unwrap();
    log
      .push(EventRecord::Delivered {
        at_nanos: 1,
        message: MessageId::new(1),
        copy: 0,
      })
      .unwrap();
    let before = log.clone();

    assert!(
      log.push(EventRecord::Delivered {
        at_nanos: 2,
        message: MessageId::new(2),
        copy: 0,
      })
      .is_err()
    );
    assert_eq!(log, before);
  }
}

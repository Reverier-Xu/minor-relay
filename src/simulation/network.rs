#[cfg(test)]
mod tests {
  use std::time::Duration;

  use crate::simulation::{
    event::{DropReason, EventRecord},
    network::Simulator,
    topology::{AddressId, LinkKey, LinkPolicy, NodeKey, PartitionId, SimulationLimits, Topology},
  };

  fn limits(events: usize, bytes: usize) -> SimulationLimits {
    SimulationLimits::new(4, events, bytes, 512, 256).unwrap()
  }

  fn policy(delay: u64, loss: u32, duplicate: u32, reorder: u32, window: u64) -> LinkPolicy {
    LinkPolicy::new(
      Duration::from_nanos(delay),
      Duration::ZERO,
      loss,
      duplicate,
      reorder,
      Duration::from_nanos(window),
    )
    .unwrap()
  }

  fn topology(limits: SimulationLimits) -> Topology {
    let mut topology = Topology::new(limits);
    for value in 1..=4 {
      topology
        .add_node(NodeKey::new(value), AddressId::new(u32::from(value) * 10))
        .unwrap();
    }
    topology
  }

  #[test]
  fn simulation_network_fault_semantics() {
    let mut topology = topology(limits(32, 4_096));
    let loss = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let duplicate = LinkKey::new(NodeKey::new(2), NodeKey::new(3));
    let reorder = LinkKey::new(NodeKey::new(3), NodeKey::new(4));
    topology.add_link(loss, policy(1, 1_000_000, 0, 0, 0)).unwrap();
    topology
      .add_link(duplicate, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    topology
      .add_link(reorder, policy(1, 0, 0, 1_000_000, 10))
      .unwrap();
    let mut simulator = Simulator::new(7, topology).unwrap();

    let lost = simulator.send(loss, 8).unwrap();
    let duplicated = simulator.send(duplicate, 8).unwrap();
    let first = simulator.send(reorder, 8).unwrap();
    let second = simulator.send(reorder, 8).unwrap();
    simulator.run().unwrap();

    assert!(!delivered_messages(simulator.records()).contains(&lost));
    assert_eq!(
      delivered_copies(simulator.records(), duplicated),
      vec![0, 1],
    );
    let reordered = delivered_messages(simulator.records())
      .into_iter()
      .filter(|message| *message == first || *message == second)
      .collect::<Vec<_>>();
    assert_eq!(reordered, vec![second, first]);
  }

  #[test]
  fn simulation_network_queue_reservation_is_atomic() {
    let mut topology = topology(limits(1, 8));
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    topology
      .add_link(link, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    let mut simulator = Simulator::new(9, topology).unwrap();

    assert!(simulator.send(link, 8).is_err());
    assert_eq!(simulator.pending_events(), 0);
    assert_eq!(simulator.pending_bytes(), 0);
    assert!(matches!(
      simulator.records().last(),
      Some(EventRecord::QueueRejected { copies: 2, bytes: 16, .. })
    ));
  }

  #[test]
  fn simulation_network_one_way_partition_and_heal() {
    let mut topology = topology(limits(32, 4_096));
    let outbound = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let inbound = LinkKey::new(NodeKey::new(2), NodeKey::new(1));
    topology.add_link(outbound, policy(5, 0, 0, 0, 0)).unwrap();
    topology.add_link(inbound, policy(5, 0, 0, 0, 0)).unwrap();
    let mut simulator = Simulator::new(11, topology).unwrap();

    simulator.partition(outbound, PartitionId::new(1)).unwrap();
    let blocked = simulator.send(outbound, 1).unwrap();
    let reverse = simulator.send(inbound, 1).unwrap();
    simulator.heal(outbound, PartitionId::new(1)).unwrap();
    let stale = simulator.send(outbound, 1).unwrap();
    simulator.partition(outbound, PartitionId::new(2)).unwrap();
    simulator.heal(outbound, PartitionId::new(2)).unwrap();
    let current = simulator.send(outbound, 1).unwrap();
    simulator.run().unwrap();

    assert!(has_drop(simulator.records(), blocked, DropReason::Blocked));
    assert!(delivered_messages(simulator.records()).contains(&reverse));
    assert!(has_drop(simulator.records(), stale, DropReason::StaleLink));
    assert!(delivered_messages(simulator.records()).contains(&current));
  }

  #[test]
  fn simulation_network_lifecycle_faults_use_incarnations() {
    let mut topology = topology(limits(32, 4_096));
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    topology.add_link(link, policy(5, 0, 0, 0, 0)).unwrap();
    let mut simulator = Simulator::new(13, topology).unwrap();

    let old_boot = simulator.send(link, 1).unwrap();
    simulator.restart(NodeKey::new(2)).unwrap();
    simulator.run().unwrap();
    let old_address = simulator.send(link, 1).unwrap();
    simulator
      .change_address(NodeKey::new(2), AddressId::new(99))
      .unwrap();
    simulator.run().unwrap();
    let current = simulator.send(link, 1).unwrap();
    let deadline_before = simulator.next_deadline();
    simulator.set_clock_skew(NodeKey::new(2), -7).unwrap();
    assert_eq!(deadline_before, simulator.next_deadline());
    simulator.run().unwrap();

    assert!(has_drop(simulator.records(), old_boot, DropReason::StaleBoot));
    assert!(has_drop(
      simulator.records(),
      old_address,
      DropReason::StaleAddress,
    ));
    assert!(delivered_messages(simulator.records()).contains(&current));
    assert_eq!(simulator.observed_utc(NodeKey::new(2), 100).unwrap(), 93);
  }

  fn delivered_messages(records: &[EventRecord]) -> Vec<crate::simulation::event::MessageId> {
    records
      .iter()
      .filter_map(|record| match record {
        EventRecord::Delivered { message, .. } => Some(*message),
        _ => None,
      })
      .collect()
  }

  fn delivered_copies(
    records: &[EventRecord],
    expected: crate::simulation::event::MessageId,
  ) -> Vec<u8> {
    records
      .iter()
      .filter_map(|record| match record {
        EventRecord::Delivered { message, copy, .. } if *message == expected => Some(*copy),
        _ => None,
      })
      .collect()
  }

  fn has_drop(
    records: &[EventRecord],
    expected: crate::simulation::event::MessageId,
    expected_reason: DropReason,
  ) -> bool {
    records.iter().any(|record| {
      matches!(record, EventRecord::Dropped { message, reason, .. } if *message == expected && *reason == expected_reason)
    })
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::{
    AddressId, LinkKey, LinkPolicy, NodeKey, PartitionId, SimulationLimits, Topology,
  };

  fn limits(max_nodes: usize) -> SimulationLimits {
    SimulationLimits::new(max_nodes, 32, 4_096, 128, 1_024).unwrap()
  }

  fn policy(delay: u64) -> LinkPolicy {
    LinkPolicy::new(Duration::from_nanos(delay), Duration::ZERO, 0, 0, 0, Duration::ZERO)
      .unwrap()
  }

  #[test]
  fn simulation_topology_rejects_invalid_bounds_atomically() {
    assert!(SimulationLimits::new(0, 1, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(1_025, 1, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 0, 1, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 0, 1, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 0, 1).is_err());
    assert!(SimulationLimits::new(2, 1, 1, 1, 0).is_err());

    let mut topology = Topology::new(limits(2));
    topology.add_node(NodeKey::new(1), AddressId::new(10)).unwrap();
    topology.add_node(NodeKey::new(2), AddressId::new(20)).unwrap();
    let before = topology.clone();

    assert!(topology.add_node(NodeKey::new(3), AddressId::new(30)).is_err());
    assert!(topology.add_node(NodeKey::new(2), AddressId::new(21)).is_err());
    assert_eq!(topology, before);
  }

  #[test]
  fn simulation_topology_preserves_directed_links() {
    let mut topology = Topology::new(limits(2));
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    topology.add_node(left, AddressId::new(10)).unwrap();
    topology.add_node(right, AddressId::new(20)).unwrap();

    let outbound = LinkKey::new(left, right);
    let inbound = LinkKey::new(right, left);
    topology.add_link(outbound, policy(5)).unwrap();
    topology.add_link(inbound, policy(9)).unwrap();

    assert_eq!(topology.link(outbound).unwrap().policy().fixed_delay(), Duration::from_nanos(5));
    assert_eq!(topology.link(inbound).unwrap().policy().fixed_delay(), Duration::from_nanos(9));
    assert!(!topology.link(outbound).unwrap().is_blocked());
    assert!(!topology.link(inbound).unwrap().is_blocked());
  }

  #[test]
  fn simulation_topology_keeps_overlapping_partitions_independent() {
    let mut topology = Topology::new(limits(2));
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let outbound = LinkKey::new(left, right);
    let inbound = LinkKey::new(right, left);
    topology.add_node(left, AddressId::new(10)).unwrap();
    topology.add_node(right, AddressId::new(20)).unwrap();
    topology.add_link(outbound, policy(1)).unwrap();
    topology.add_link(inbound, policy(1)).unwrap();

    topology.partition(outbound, PartitionId::new(1)).unwrap();
    topology.partition(outbound, PartitionId::new(2)).unwrap();
    let blocked_generation = topology.link(outbound).unwrap().generation();
    topology.heal(outbound, PartitionId::new(1)).unwrap();

    assert!(topology.link(outbound).unwrap().is_blocked());
    assert!(!topology.link(inbound).unwrap().is_blocked());
    assert!(topology.link(outbound).unwrap().generation() > blocked_generation);

    topology.heal(outbound, PartitionId::new(2)).unwrap();
    assert!(!topology.link(outbound).unwrap().is_blocked());
  }
}

#[cfg(test)]
mod tests {
  use crate::simulation::{
    event::{DropReason, EventRecord, MessageId},
    redaction::{
      ArtifactCandidate, EventKind, NormalizedEvent, RedactionError, ScenarioAliasKind,
    },
    topology::{AddressId, LinkKey, NodeKey, PartitionId},
  };

  use super::ScenarioFixture;

  fn all_records() -> Vec<EventRecord> {
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let link = LinkKey::new(left, right);
    let message = MessageId::new(7);
    let mut records = vec![
      EventRecord::SendAccepted {
        at_nanos: 1,
        message,
        link,
        copies: 2,
        bytes: 64,
      },
      EventRecord::Lost {
        at_nanos: 2,
        message,
      },
      EventRecord::DuplicateCreated {
        at_nanos: 3,
        message,
      },
      EventRecord::Reordered {
        at_nanos: 4,
        message,
        copy: 1,
      },
      EventRecord::Delivered {
        at_nanos: 5,
        message,
        copy: 0,
      },
      EventRecord::Partitioned {
        at_nanos: 6,
        link,
        partition: PartitionId::new(1),
        generation: 1,
      },
      EventRecord::Healed {
        at_nanos: 7,
        link,
        partition: PartitionId::new(1),
        generation: 2,
      },
      EventRecord::Restarted {
        at_nanos: 8,
        node: right,
        boot_epoch: 1,
      },
      EventRecord::AddressChanged {
        at_nanos: 9,
        node: right,
        address: AddressId::new(99),
        generation: 1,
      },
      EventRecord::ClockSkewChanged {
        at_nanos: 10,
        node: right,
        skew_nanos: -17,
      },
      EventRecord::QueueRejected {
        at_nanos: 11,
        message,
        copies: 2,
        bytes: 128,
      },
    ];
    for (offset, reason) in [
      DropReason::Blocked,
      DropReason::StaleLink,
      DropReason::StaleBoot,
      DropReason::StaleAddress,
      DropReason::Offline,
    ]
    .into_iter()
    .enumerate()
    {
      records.push(EventRecord::Dropped {
        at_nanos: 12 + offset as u64,
        message,
        copy: 0,
        reason,
      });
    }
    records
  }

  #[test]
  fn simulation_failure_artifact_security_normalizes_closed_simulation_events() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let records = all_records();
    let normalized = fixture
      .normalize_candidates(records.iter().map(ArtifactCandidate::Simulation))
      .unwrap();

    assert_eq!(normalized.len(), records.len());
    assert_eq!(
      normalized.iter().map(NormalizedEvent::kind).collect::<Vec<_>>(),
      [
        EventKind::SendAccepted,
        EventKind::Lost,
        EventKind::DuplicateCreated,
        EventKind::Reordered,
        EventKind::Delivered,
        EventKind::Partitioned,
        EventKind::Healed,
        EventKind::Restarted,
        EventKind::AddressChanged,
        EventKind::ClockSkewChanged,
        EventKind::QueueRejected,
        EventKind::Dropped,
        EventKind::Dropped,
        EventKind::Dropped,
        EventKind::Dropped,
        EventKind::Dropped,
      ],
    );
    assert!(normalized.iter().all(|event| event.at_nanos() > 0));
    assert_eq!(normalized[0].path_alias(), Some("path-1"));
    assert_eq!(normalized[5].fault_alias(), Some("fault-1"));
    assert_eq!(normalized[7].node_alias(), Some("node-2"));
    assert_eq!(normalized[8].endpoint_alias(), Some("endpoint-5"));
    assert_eq!(normalized[0].payload_len(), Some(64));
    assert_eq!(normalized[10].payload_len(), Some(128));
  }

  #[test]
  fn simulation_failure_artifact_security_normalizes_ephemeral_ids_to_aliases() {
    let mut first = ScenarioFixture::empty();
    first.register_node(NodeKey::new(1), 1).unwrap();
    first.register_endpoint(AddressId::new(111), 1).unwrap();
    let mut second = ScenarioFixture::empty();
    second.register_node(NodeKey::new(9), 1).unwrap();
    second.register_endpoint(AddressId::new(999), 1).unwrap();

    let first_event = EventRecord::AddressChanged {
      at_nanos: 5,
      node: NodeKey::new(1),
      address: AddressId::new(111),
      generation: 3,
    };
    let second_event = EventRecord::AddressChanged {
      at_nanos: 5,
      node: NodeKey::new(9),
      address: AddressId::new(999),
      generation: 3,
    };

    assert_eq!(
      first.normalize_record(&first_event),
      second.normalize_record(&second_event),
    );
  }

  #[test]
  fn simulation_failure_artifact_security_rejects_unknown_and_duplicate_aliases() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let unknown = EventRecord::Restarted {
      at_nanos: 1,
      node: NodeKey::new(99),
      boot_epoch: 1,
    };
    assert_eq!(
      fixture.normalize_record(&unknown),
      Err(RedactionError::UnknownAlias(ScenarioAliasKind::Node)),
    );

    let mut fixture = ScenarioFixture::empty();
    fixture.register_node(NodeKey::new(1), 1).unwrap();
    assert_eq!(
      fixture.register_node(NodeKey::new(2), 1),
      Err(RedactionError::DuplicateAlias(ScenarioAliasKind::Node)),
    );
    assert_eq!(
      fixture.register_node(NodeKey::new(1), 2),
      Err(RedactionError::DuplicateSource(ScenarioAliasKind::Node)),
    );
    assert_eq!(
      fixture.register_endpoint(AddressId::new(1), 0),
      Err(RedactionError::InvalidAlias),
    );
  }
}

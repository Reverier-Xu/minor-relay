use std::collections::{BTreeMap, BTreeSet};

use crate::simulation::{
  event::{DropReason, EventRecord},
  redaction::{
    ArtifactCandidate, EndpointAlias, FaultAlias, NodeAlias, NormalizedDropReason, NormalizedEvent,
    PathAlias, RedactionError, ScenarioAliasKind,
  },
  topology::{AddressId, LinkKey, NodeKey, PartitionId},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScenarioFixture {
  nodes: BTreeMap<NodeKey, u16>,
  node_aliases: BTreeSet<u16>,
  endpoints: BTreeMap<AddressId, u16>,
  endpoint_aliases: BTreeSet<u16>,
  paths: BTreeMap<LinkKey, u16>,
  path_aliases: BTreeSet<u16>,
  faults: BTreeMap<PartitionId, u16>,
  fault_aliases: BTreeSet<u16>,
}

impl ScenarioFixture {
  pub(crate) fn empty() -> Self {
    Self {
      nodes: BTreeMap::new(),
      node_aliases: BTreeSet::new(),
      endpoints: BTreeMap::new(),
      endpoint_aliases: BTreeSet::new(),
      paths: BTreeMap::new(),
      path_aliases: BTreeSet::new(),
      faults: BTreeMap::new(),
      fault_aliases: BTreeSet::new(),
    }
  }

  pub(crate) fn network_fault_matrix() -> Result<Self, RedactionError> {
    let mut fixture = Self::empty();
    for ordinal in 1..=4_u16 {
      fixture.register_node(NodeKey::new(ordinal), ordinal)?;
      fixture.register_endpoint(AddressId::new(u32::from(ordinal) * 10), ordinal)?;
    }
    fixture.register_endpoint(AddressId::new(99), 5)?;
    for (ordinal, (from, to)) in [
      (1, 2),
      (2, 3),
      (3, 4),
      (4, 1),
      (1, 4),
      (2, 4),
      (1, 3),
      (4, 2),
    ]
    .into_iter()
    .enumerate()
    {
      fixture.register_path(
        LinkKey::new(NodeKey::new(from), NodeKey::new(to)),
        u16::try_from(ordinal + 1).map_err(|_| RedactionError::InvalidAlias)?,
      )?;
    }
    for ordinal in 1..=3_u32 {
      fixture.register_fault(
        PartitionId::new(ordinal),
        u16::try_from(ordinal).map_err(|_| RedactionError::InvalidAlias)?,
      )?;
    }
    Ok(fixture)
  }

  pub(crate) fn register_node(
    &mut self, source: NodeKey, ordinal: u16,
  ) -> Result<(), RedactionError> {
    register_alias(
      &mut self.nodes,
      &mut self.node_aliases,
      source,
      ordinal,
      ScenarioAliasKind::Node,
    )
  }

  pub(crate) fn register_endpoint(
    &mut self, source: AddressId, ordinal: u16,
  ) -> Result<(), RedactionError> {
    register_alias(
      &mut self.endpoints,
      &mut self.endpoint_aliases,
      source,
      ordinal,
      ScenarioAliasKind::Endpoint,
    )
  }

  pub(crate) fn register_path(
    &mut self, source: LinkKey, ordinal: u16,
  ) -> Result<(), RedactionError> {
    register_alias(
      &mut self.paths,
      &mut self.path_aliases,
      source,
      ordinal,
      ScenarioAliasKind::Path,
    )
  }

  pub(crate) fn register_fault(
    &mut self, source: PartitionId, ordinal: u16,
  ) -> Result<(), RedactionError> {
    register_alias(
      &mut self.faults,
      &mut self.fault_aliases,
      source,
      ordinal,
      ScenarioAliasKind::Fault,
    )
  }

  pub(crate) fn normalize_candidates<'a>(
    &self, candidates: impl IntoIterator<Item = ArtifactCandidate<'a>>,
  ) -> Result<Vec<NormalizedEvent>, RedactionError> {
    let mut normalized = Vec::new();
    for candidate in candidates {
      normalized.push(self.normalize_candidate(candidate)?);
    }
    Ok(normalized)
  }

  pub(crate) fn normalize_candidate(
    &self, candidate: ArtifactCandidate<'_>,
  ) -> Result<NormalizedEvent, RedactionError> {
    match candidate {
      ArtifactCandidate::Simulation(record) => self.normalize_record(record),
      ArtifactCandidate::Forbidden(value) => Err(RedactionError::ForbiddenField(value.class())),
    }
  }

  pub(crate) fn normalize_record(
    &self, record: &EventRecord,
  ) -> Result<NormalizedEvent, RedactionError> {
    match *record {
      EventRecord::SendAccepted {
        at_nanos,
        message,
        link,
        copies,
        bytes,
      } => Ok(NormalizedEvent::SendAccepted {
        at_nanos,
        message: message.value(),
        path: self.path(link)?,
        copies,
        payload_len: bytes,
      }),
      EventRecord::Lost { at_nanos, message } => Ok(NormalizedEvent::Lost {
        at_nanos,
        message: message.value(),
      }),
      EventRecord::DuplicateCreated { at_nanos, message } => {
        Ok(NormalizedEvent::DuplicateCreated {
          at_nanos,
          message: message.value(),
        })
      }
      EventRecord::Reordered {
        at_nanos,
        message,
        copy,
      } => Ok(NormalizedEvent::Reordered {
        at_nanos,
        message: message.value(),
        copy,
      }),
      EventRecord::Delivered {
        at_nanos,
        message,
        copy,
      } => Ok(NormalizedEvent::Delivered {
        at_nanos,
        message: message.value(),
        copy,
      }),
      EventRecord::Dropped {
        at_nanos,
        message,
        copy,
        reason,
      } => Ok(NormalizedEvent::Dropped {
        at_nanos,
        message: message.value(),
        copy,
        reason: normalize_drop_reason(reason),
      }),
      EventRecord::Partitioned {
        at_nanos,
        link,
        partition,
        generation,
      } => Ok(NormalizedEvent::Partitioned {
        at_nanos,
        path: self.path(link)?,
        fault: self.fault(partition)?,
        generation,
      }),
      EventRecord::Healed {
        at_nanos,
        link,
        partition,
        generation,
      } => Ok(NormalizedEvent::Healed {
        at_nanos,
        path: self.path(link)?,
        fault: self.fault(partition)?,
        generation,
      }),
      EventRecord::Restarted {
        at_nanos,
        node,
        boot_epoch,
      } => Ok(NormalizedEvent::Restarted {
        at_nanos,
        node: self.node(node)?,
        boot_epoch,
      }),
      EventRecord::AddressChanged {
        at_nanos,
        node,
        address,
        generation,
      } => Ok(NormalizedEvent::AddressChanged {
        at_nanos,
        node: self.node(node)?,
        endpoint: self.endpoint(address)?,
        generation,
      }),
      EventRecord::ClockSkewChanged {
        at_nanos,
        node,
        skew_nanos,
      } => Ok(NormalizedEvent::ClockSkewChanged {
        at_nanos,
        node: self.node(node)?,
        skew_nanos,
      }),
      EventRecord::QueueRejected {
        at_nanos,
        message,
        copies,
        bytes,
      } => Ok(NormalizedEvent::QueueRejected {
        at_nanos,
        message: message.value(),
        copies,
        payload_len: bytes,
      }),
    }
  }

  fn node(&self, source: NodeKey) -> Result<NodeAlias, RedactionError> {
    let ordinal = resolve_alias(&self.nodes, source, ScenarioAliasKind::Node)?;
    NodeAlias::new(ordinal)
  }

  fn endpoint(&self, source: AddressId) -> Result<EndpointAlias, RedactionError> {
    let ordinal = resolve_alias(&self.endpoints, source, ScenarioAliasKind::Endpoint)?;
    EndpointAlias::new(ordinal)
  }

  fn path(&self, source: LinkKey) -> Result<PathAlias, RedactionError> {
    let ordinal = resolve_alias(&self.paths, source, ScenarioAliasKind::Path)?;
    PathAlias::new(ordinal)
  }

  fn fault(&self, source: PartitionId) -> Result<FaultAlias, RedactionError> {
    let ordinal = resolve_alias(&self.faults, source, ScenarioAliasKind::Fault)?;
    FaultAlias::new(ordinal)
  }
}

fn register_alias<T: Copy + Ord>(
  sources: &mut BTreeMap<T, u16>, aliases: &mut BTreeSet<u16>, source: T, ordinal: u16,
  kind: ScenarioAliasKind,
) -> Result<(), RedactionError> {
  if ordinal == 0 {
    return Err(RedactionError::InvalidAlias);
  }
  if sources.contains_key(&source) {
    return Err(RedactionError::DuplicateSource(kind));
  }
  if aliases.contains(&ordinal) {
    return Err(RedactionError::DuplicateAlias(kind));
  }
  sources.insert(source, ordinal);
  aliases.insert(ordinal);
  Ok(())
}

fn resolve_alias<T: Copy + Ord>(
  sources: &BTreeMap<T, u16>, source: T, kind: ScenarioAliasKind,
) -> Result<u16, RedactionError> {
  sources
    .get(&source)
    .copied()
    .ok_or(RedactionError::UnknownAlias(kind))
}

const fn normalize_drop_reason(reason: DropReason) -> NormalizedDropReason {
  match reason {
    DropReason::Blocked => NormalizedDropReason::Blocked,
    DropReason::StaleLink => NormalizedDropReason::StaleLink,
    DropReason::StaleBoot => NormalizedDropReason::StaleBoot,
    DropReason::StaleAddress => NormalizedDropReason::StaleAddress,
    DropReason::Offline => NormalizedDropReason::Offline,
  }
}

#[cfg(test)]
mod tests {
  use super::ScenarioFixture;
  use crate::simulation::{
    event::{DropReason, EventRecord, MessageId},
    redaction::{ArtifactCandidate, EventKind, NormalizedEvent, RedactionError, ScenarioAliasKind},
    topology::{AddressId, LinkKey, NodeKey, PartitionId},
  };

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
      normalized
        .iter()
        .map(NormalizedEvent::kind)
        .collect::<Vec<_>>(),
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
    assert_eq!(normalized[0].path_alias().as_deref(), Some("path-1"));
    assert_eq!(normalized[5].fault_alias().as_deref(), Some("fault-1"));
    assert_eq!(normalized[7].node_alias().as_deref(), Some("node-2"));
    assert_eq!(
      normalized[8].endpoint_alias().as_deref(),
      Some("endpoint-5")
    );
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

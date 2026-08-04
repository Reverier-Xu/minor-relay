use minor_relay_test_support::{
  Alias, AliasKind, AliasTable, NormalizedDropReason, NormalizedEvent, NormalizedEventSource,
  SourceError,
};

use crate::simulation::{
  event::{DropReason, EventRecord},
  redaction::ArtifactCandidate,
  topology::{AddressId, LinkKey, NodeKey, PartitionId},
};

pub(crate) struct ScenarioFixture {
  nodes: AliasTable<NodeKey>,
  endpoints: AliasTable<AddressId>,
  paths: AliasTable<LinkKey>,
  faults: AliasTable<PartitionId>,
}

impl ScenarioFixture {
  fn empty() -> Self {
    Self {
      nodes: AliasTable::new(AliasKind::Node),
      endpoints: AliasTable::new(AliasKind::Endpoint),
      paths: AliasTable::new(AliasKind::Path),
      faults: AliasTable::new(AliasKind::Fault),
    }
  }

  pub(crate) fn network_fault_matrix() -> Result<Self, SourceError> {
    let mut fixture = Self::empty();
    for value in 1..=4_u16 {
      fixture.register_node(NodeKey::new(value))?;
      fixture.register_endpoint(AddressId::new(u32::from(value) * 10))?;
    }
    fixture.register_endpoint(AddressId::new(99))?;
    for (from, to) in [
      (1, 2),
      (2, 3),
      (3, 4),
      (4, 1),
      (1, 4),
      (2, 4),
      (1, 3),
      (4, 2),
    ] {
      fixture.register_path(LinkKey::new(NodeKey::new(from), NodeKey::new(to)))?;
    }
    for value in 1..=3_u32 {
      fixture.register_fault(PartitionId::new(value))?;
    }
    Ok(fixture)
  }

  fn register_node(&mut self, source: NodeKey) -> Result<Alias, SourceError> {
    self.nodes.register(source)
  }

  fn register_endpoint(&mut self, source: AddressId) -> Result<Alias, SourceError> {
    self.endpoints.register(source)
  }

  fn register_path(&mut self, source: LinkKey) -> Result<Alias, SourceError> {
    self.paths.register(source)
  }

  fn register_fault(&mut self, source: PartitionId) -> Result<Alias, SourceError> {
    self.faults.register(source)
  }

  pub(crate) fn normalize_record(
    &self, record: &EventRecord,
  ) -> Result<NormalizedEvent, SourceError> {
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
        path: self.paths.resolve(link)?,
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
        path: self.paths.resolve(link)?,
        fault: self.faults.resolve(partition)?,
        generation,
      }),
      EventRecord::Healed {
        at_nanos,
        link,
        partition,
        generation,
      } => Ok(NormalizedEvent::Healed {
        at_nanos,
        path: self.paths.resolve(link)?,
        fault: self.faults.resolve(partition)?,
        generation,
      }),
      EventRecord::Restarted {
        at_nanos,
        node,
        boot_epoch,
      } => Ok(NormalizedEvent::Restarted {
        at_nanos,
        node: self.nodes.resolve(node)?,
        boot_epoch,
      }),
      EventRecord::AddressChanged {
        at_nanos,
        node,
        address,
        generation,
      } => Ok(NormalizedEvent::AddressChanged {
        at_nanos,
        node: self.nodes.resolve(node)?,
        endpoint: self.endpoints.resolve(address)?,
        generation,
      }),
      EventRecord::ClockSkewChanged {
        at_nanos,
        node,
        skew_nanos,
      } => Ok(NormalizedEvent::ClockSkewChanged {
        at_nanos,
        node: self.nodes.resolve(node)?,
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
}

enum CandidateSet<'a> {
  Records(&'a [EventRecord]),
  Candidates(&'a [ArtifactCandidate<'a>]),
}

pub(crate) struct SimulationEvidenceSource<'a> {
  fixture: &'a ScenarioFixture,
  values: CandidateSet<'a>,
}

impl<'a> SimulationEvidenceSource<'a> {
  pub(crate) const fn records(fixture: &'a ScenarioFixture, records: &'a [EventRecord]) -> Self {
    Self {
      fixture,
      values: CandidateSet::Records(records),
    }
  }

  pub(crate) const fn candidates(
    fixture: &'a ScenarioFixture, candidates: &'a [ArtifactCandidate<'a>],
  ) -> Self {
    Self {
      fixture,
      values: CandidateSet::Candidates(candidates),
    }
  }

  fn len(&self) -> usize {
    match self.values {
      CandidateSet::Records(records) => records.len(),
      CandidateSet::Candidates(candidates) => candidates.len(),
    }
  }

  fn normalize(&self, index: usize) -> Result<NormalizedEvent, SourceError> {
    match self.values {
      CandidateSet::Records(records) => records
        .get(index)
        .ok_or(SourceError::InvalidEventIndex)
        .and_then(|record| self.fixture.normalize_record(record)),
      CandidateSet::Candidates(candidates) => match candidates
        .get(index)
        .copied()
        .ok_or(SourceError::InvalidEventIndex)?
      {
        ArtifactCandidate::Forbidden(value) => Err(SourceError::ForbiddenField(value.class())),
      },
    }
  }
}

struct SimulationEvents<'source, 'data> {
  source: &'source SimulationEvidenceSource<'data>,
  indices: std::ops::Range<usize>,
}

impl Iterator for SimulationEvents<'_, '_> {
  type Item = Result<NormalizedEvent, SourceError>;

  fn next(&mut self) -> Option<Self::Item> {
    self
      .indices
      .next()
      .map(|index| self.source.normalize(index))
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    self.indices.size_hint()
  }
}

impl ExactSizeIterator for SimulationEvents<'_, '_> {}

impl NormalizedEventSource for SimulationEvidenceSource<'_> {
  fn prevalidated_events(
    &self,
  ) -> Result<
    Box<dyn ExactSizeIterator<Item = Result<NormalizedEvent, SourceError>> + '_>,
    SourceError,
  > {
    for index in 0..self.len() {
      self.normalize(index)?;
    }
    Ok(Box::new(SimulationEvents {
      source: self,
      indices: 0..self.len(),
    }))
  }
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
  use minor_relay_test_support::{
    AliasKind, NormalizedDropReason, NormalizedEvent, NormalizedEventSource, SourceError,
  };

  use super::{ScenarioFixture, SimulationEvidenceSource};
  use crate::simulation::{
    event::{DropReason, EventRecord, MessageId},
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
  fn simulation_failure_artifact_security_normalizes_all_simulation_event_variants() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let records = all_records();
    let source = SimulationEvidenceSource::records(&fixture, &records);
    let events = source
      .prevalidated_events()
      .unwrap()
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    assert_eq!(events.len(), records.len());
    let [
      NormalizedEvent::SendAccepted {
        path, payload_len, ..
      },
      NormalizedEvent::Lost { .. },
      NormalizedEvent::DuplicateCreated { .. },
      NormalizedEvent::Reordered { .. },
      NormalizedEvent::Delivered { .. },
      NormalizedEvent::Partitioned { fault, .. },
      NormalizedEvent::Healed { .. },
      NormalizedEvent::Restarted { node, .. },
      NormalizedEvent::AddressChanged { endpoint, .. },
      NormalizedEvent::ClockSkewChanged { .. },
      NormalizedEvent::QueueRejected { .. },
      NormalizedEvent::Dropped {
        reason: NormalizedDropReason::Blocked,
        ..
      },
      NormalizedEvent::Dropped {
        reason: NormalizedDropReason::StaleLink,
        ..
      },
      NormalizedEvent::Dropped {
        reason: NormalizedDropReason::StaleBoot,
        ..
      },
      NormalizedEvent::Dropped {
        reason: NormalizedDropReason::StaleAddress,
        ..
      },
      NormalizedEvent::Dropped {
        reason: NormalizedDropReason::Offline,
        ..
      },
    ] = events.as_slice()
    else {
      panic!("normalized simulation event sequence differs from the closed record set");
    };
    assert_eq!(path.render(), "path-1");
    assert_eq!(fault.render(), "fault-1");
    assert_eq!(node.render(), "node-2");
    assert_eq!(endpoint.render(), "endpoint-5");
    assert_eq!(*payload_len, 64);
  }

  #[test]
  fn simulation_failure_artifact_security_aliases_ignore_raw_source_values() {
    let mut first = ScenarioFixture::empty();
    first.register_node(NodeKey::new(1)).unwrap();
    first.register_endpoint(AddressId::new(111)).unwrap();
    let mut second = ScenarioFixture::empty();
    second.register_node(NodeKey::new(9)).unwrap();
    second.register_endpoint(AddressId::new(999)).unwrap();
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
  fn simulation_failure_artifact_security_alias_tables_reject_unknown_and_duplicate_sources() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let unknown = EventRecord::Restarted {
      at_nanos: 1,
      node: NodeKey::new(99),
      boot_epoch: 1,
    };
    assert_eq!(
      fixture.normalize_record(&unknown),
      Err(SourceError::UnknownAlias(AliasKind::Node)),
    );
    let mut fixture = ScenarioFixture::empty();
    fixture.register_node(NodeKey::new(1)).unwrap();
    assert_eq!(
      fixture.register_node(NodeKey::new(1)),
      Err(SourceError::DuplicateSource(AliasKind::Node)),
    );
  }
}

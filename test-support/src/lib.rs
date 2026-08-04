#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::{
    AliasKind, AliasTable, ArtifactError, CargoTestId, CommitDigest, EvidenceId,
    EvidenceManifest, FailureClass, LockfileDigest, NormalizedEvent, NormalizedEventSource,
    ProducerKind, ReplaySpec, SourceError, build_failure_artifact,
  };

  struct FixedSource {
    events: Vec<NormalizedEvent>,
    preflight: Result<(), SourceError>,
    event_reads: Cell<usize>,
  }

  impl NormalizedEventSource for FixedSource {
    fn prevalidate(&self) -> Result<usize, SourceError> {
      self.preflight?;
      Ok(self.events.len())
    }

    fn event(&self, index: usize) -> Result<NormalizedEvent, SourceError> {
      self.event_reads.set(self.event_reads.get() + 1);
      self
        .events
        .get(index)
        .copied()
        .ok_or(SourceError::InvalidEventIndex)
    }
  }

  fn manifest(producer: ProducerKind) -> EvidenceManifest {
    EvidenceManifest::new(
      producer,
      EvidenceId::new("SC-G01-P0-04").unwrap(),
      EvidenceId::new("shared-artifact-contract").unwrap(),
      Some(7),
      FailureClass::Invariant,
      EvidenceId::new("producer-neutral-schema").unwrap(),
      CommitDigest::parse_hex("1111111111111111111111111111111111111111").unwrap(),
      LockfileDigest::from_bytes([0x22; 32]),
      ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity),
    )
    .unwrap()
  }

  #[test]
  fn all_producer_classes_use_one_bounded_schema() {
    let event = NormalizedEvent::state_transition(
      5,
      EvidenceId::new("fixture-machine").unwrap(),
      EvidenceId::new("ready").unwrap(),
    );
    for producer in ProducerKind::ALL {
      let source = FixedSource {
        events: vec![event],
        preflight: Ok(()),
        event_reads: Cell::new(0),
      };
      let artifact = build_failure_artifact(&manifest(producer), &source).unwrap();
      assert!(artifact.as_bytes().starts_with(
        b"{\"schema\":\"relay.woooo.tech/schemas/failure-replay\""
      ));
      assert_eq!(artifact.producer(), producer);
      assert!(artifact.as_bytes().len() <= 1_048_576);
    }
  }

  #[test]
  fn forbidden_source_fails_before_any_event_or_digest_read() {
    let source = FixedSource {
      events: vec![NormalizedEvent::state_transition(
        1,
        EvidenceId::new("fixture-machine").unwrap(),
        EvidenceId::new("failed").unwrap(),
      )],
      preflight: Err(SourceError::ForbiddenField(
        super::ForbiddenFieldClass::Credential,
      )),
      event_reads: Cell::new(0),
    };

    assert_eq!(
      build_failure_artifact(&manifest(ProducerKind::Property), &source),
      Err(ArtifactError::ForbiddenField(
        super::ForbiddenFieldClass::Credential
      )),
    );
    assert_eq!(source.event_reads.get(), 0);
  }

  #[test]
  fn aliases_are_sequential_and_independent_of_source_values() {
    let mut first = AliasTable::new(AliasKind::Endpoint);
    let mut second = AliasTable::new(AliasKind::Endpoint);

    assert_eq!(first.register(111_u64).unwrap().render(), "endpoint-1");
    assert_eq!(first.register(999_u64).unwrap().render(), "endpoint-2");
    assert_eq!(second.register(999_u64).unwrap().render(), "endpoint-1");
    assert_eq!(second.register(111_u64).unwrap().render(), "endpoint-2");
    assert_eq!(
      first.register(111_u64),
      Err(SourceError::DuplicateSource(AliasKind::Endpoint)),
    );
  }

  #[test]
  fn metadata_and_replay_inputs_are_role_separated_and_validated() {
    assert!(CommitDigest::parse_hex("00").is_err());
    assert!(CommitDigest::parse_hex(&"g".repeat(40)).is_err());
    assert!(EvidenceId::new("../../host-path").is_err());
    assert!(EvidenceId::new("hostile\ntext").is_err());
    assert!(ReplaySpec::parse("simulation", &["--scenario", "x", "--seed", "1"]).is_err());
    assert!(ReplaySpec::parse("/tmp/cargo", &["--locked", "--lib", "x"]).is_err());
  }
}

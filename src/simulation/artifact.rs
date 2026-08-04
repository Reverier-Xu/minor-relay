#[cfg(test)]
mod tests {
  use crate::simulation::{
    event::{EventRecord, MessageId},
    fixture::ScenarioFixture,
    redaction::{ArtifactCandidate, ForbiddenFieldClass, SensitiveCandidate},
    scenario::ReplaySpec,
  };

  use super::{
    ArtifactError, ArtifactLimits, EvidenceDigest, EvidenceManifest, FailureClass, InvariantId,
    MAX_ARTIFACT_BYTES, MAX_RETAINED_EVENTS, build_failure_artifact,
    build_failure_artifact_with_limits,
  };

  fn manifest(seed: u64) -> EvidenceManifest {
    EvidenceManifest::network_fault_matrix(
      seed,
      FailureClass::Invariant,
      InvariantId::CompleteFaultMatrix,
      EvidenceDigest::new([0x11; 32]),
      EvidenceDigest::new([0x22; 32]),
      ReplaySpec::simulation_network_fault_matrix(seed),
    )
    .unwrap()
  }

  fn lost_records(count: usize) -> Vec<EventRecord> {
    (0..count)
      .map(|value| EventRecord::Lost {
        at_nanos: value as u64,
        message: MessageId::new(value as u64),
      })
      .collect()
  }

  #[test]
  fn simulation_failure_artifact_security_rejects_forbidden_before_digesting() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let sentinel = b"artifact-secret-sentinel";
    let candidate = ArtifactCandidate::Forbidden(SensitiveCandidate::new(
      ForbiddenFieldClass::Credential,
      sentinel,
    ));

    let result = build_failure_artifact(&manifest(1), &fixture, &[candidate]);
    assert_eq!(
      result,
      Err(ArtifactError::ForbiddenField(
        ForbiddenFieldClass::Credential
      )),
    );
    assert!(!format!("{result:?}").contains("artifact-secret"));
  }

  #[test]
  fn simulation_failure_artifact_security_count_truncation_keeps_exact_windows() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let records = lost_records(MAX_RETAINED_EVENTS + 1);
    let candidates = records
      .iter()
      .map(ArtifactCandidate::Simulation)
      .collect::<Vec<_>>();
    let artifact = build_failure_artifact(&manifest(7), &fixture, &candidates).unwrap();
    let truncation = artifact.truncation();

    assert_eq!(truncation.total_events(), 10_001);
    assert_eq!(truncation.retained_events(), 10_000);
    assert_eq!(truncation.omitted_events(), 1);
    assert_eq!(truncation.first_events(), 5_000);
    assert_eq!(truncation.last_events(), 5_000);
    assert!(truncation.count_truncated());
    assert!(!truncation.byte_truncated());
    assert_eq!(artifact.first_window()[0].at_nanos(), 0);
    assert_eq!(artifact.first_window()[4_999].at_nanos(), 4_999);
    assert_eq!(artifact.last_window()[0].at_nanos(), 5_001);
    assert_eq!(artifact.last_window()[4_999].at_nanos(), 10_000);
    assert!(artifact.as_bytes().len() <= MAX_ARTIFACT_BYTES);
  }

  #[test]
  fn simulation_failure_artifact_security_digest_covers_omitted_middle() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let first_records = lost_records(MAX_RETAINED_EVENTS + 1);
    let mut second_records = first_records.clone();
    second_records[MAX_RETAINED_EVENTS / 2] = EventRecord::Lost {
      at_nanos: 999_999,
      message: MessageId::new(999_999),
    };
    let first_candidates = first_records
      .iter()
      .map(ArtifactCandidate::Simulation)
      .collect::<Vec<_>>();
    let second_candidates = second_records
      .iter()
      .map(ArtifactCandidate::Simulation)
      .collect::<Vec<_>>();

    let first = build_failure_artifact(&manifest(8), &fixture, &first_candidates).unwrap();
    let second = build_failure_artifact(&manifest(8), &fixture, &second_candidates).unwrap();

    assert_eq!(first.first_window(), second.first_window());
    assert_eq!(first.last_window(), second.last_window());
    assert_ne!(first.event_digest(), second.event_digest());
    assert_ne!(first.as_bytes(), second.as_bytes());
  }

  #[test]
  fn simulation_failure_artifact_security_byte_truncation_is_bounded_and_deterministic() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let records = lost_records(200);
    let candidates = records
      .iter()
      .map(ArtifactCandidate::Simulation)
      .collect::<Vec<_>>();
    let limits = ArtifactLimits::for_test(2_048, MAX_RETAINED_EVENTS).unwrap();

    let first =
      build_failure_artifact_with_limits(&manifest(9), &fixture, &candidates, limits).unwrap();
    let second =
      build_failure_artifact_with_limits(&manifest(9), &fixture, &candidates, limits).unwrap();

    assert_eq!(first, second);
    assert!(first.as_bytes().len() <= 2_048);
    assert!(first.truncation().byte_truncated());
    assert!(!first.truncation().count_truncated());
    assert!(first.truncation().retained_events() < 200);
    assert_eq!(
      first.truncation().first_events(),
      (first.truncation().retained_events() + 1) / 2,
    );
    assert_eq!(
      first.truncation().last_events(),
      first.truncation().retained_events() / 2,
    );

    let tighter = ArtifactLimits::for_test(first.as_bytes().len() - 1, MAX_RETAINED_EVENTS).unwrap();
    let tighter_artifact =
      build_failure_artifact_with_limits(&manifest(9), &fixture, &candidates, tighter).unwrap();
    assert!(
      tighter_artifact.truncation().retained_events() < first.truncation().retained_events()
    );
  }

  #[test]
  fn simulation_failure_artifact_security_enforces_exact_fixed_byte_boundary() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let artifact = build_failure_artifact_with_limits(
      &manifest(10),
      &fixture,
      &[],
      ArtifactLimits::for_test(MAX_ARTIFACT_BYTES, MAX_RETAINED_EVENTS).unwrap(),
    )
    .unwrap();
    let exact = artifact.as_bytes().len();

    let exact_artifact = build_failure_artifact_with_limits(
      &manifest(10),
      &fixture,
      &[],
      ArtifactLimits::for_test(exact, MAX_RETAINED_EVENTS).unwrap(),
    )
    .unwrap();
    assert_eq!(exact_artifact.as_bytes().len(), exact);
    assert_eq!(
      build_failure_artifact_with_limits(
        &manifest(10),
        &fixture,
        &[],
        ArtifactLimits::for_test(exact - 1, MAX_RETAINED_EVENTS).unwrap(),
      ),
      Err(ArtifactError::FixedFieldsExceedByteCeiling),
    );
  }

  #[test]
  fn simulation_failure_artifact_security_json_is_canonical_and_byte_stable() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let records = lost_records(3);
    let candidates = records
      .iter()
      .map(ArtifactCandidate::Simulation)
      .collect::<Vec<_>>();

    let first = build_failure_artifact(&manifest(11), &fixture, &candidates).unwrap();
    let second = build_failure_artifact(&manifest(11), &fixture, &candidates).unwrap();

    assert_eq!(first, second);
    assert!(first.as_bytes().starts_with(
      b"{\"schema\":\"relay.woooo.tech/schemas/failure-replay\",\"scenario_id\":\"SC-G01-P0-04\""
    ));
    assert_eq!(first.as_bytes().last(), Some(&b'}'));
    assert!(!first.as_bytes().contains(&b'\n'));
    assert_eq!(first.event_digest().as_hex().len(), 64);
  }

  #[test]
  fn simulation_failure_artifact_security_manifest_rejects_replay_seed_mismatch() {
    assert_eq!(
      EvidenceManifest::network_fault_matrix(
        12,
        FailureClass::Invariant,
        InvariantId::CompleteFaultMatrix,
        EvidenceDigest::new([0x11; 32]),
        EvidenceDigest::new([0x22; 32]),
        ReplaySpec::simulation_network_fault_matrix(13),
      ),
      Err(ArtifactError::ReplaySeedMismatch),
    );
  }
}

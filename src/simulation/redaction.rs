use std::fmt;

use minor_relay_test_support::ForbiddenFieldClass;

#[derive(Clone, Copy)]
pub(crate) struct SensitiveCandidate<'a> {
  class: ForbiddenFieldClass,
  _value: &'a [u8],
}

impl<'a> SensitiveCandidate<'a> {
  pub(crate) const fn new(class: ForbiddenFieldClass, value: &'a [u8]) -> Self {
    Self {
      class,
      _value: value,
    }
  }

  pub(crate) const fn class(self) -> ForbiddenFieldClass {
    self.class
  }
}

impl fmt::Debug for SensitiveCandidate<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("SensitiveCandidate([REDACTED])")
  }
}

#[derive(Clone, Copy)]
pub(crate) enum ArtifactCandidate<'a> {
  Forbidden(SensitiveCandidate<'a>),
}

#[cfg(test)]
mod tests {
  use minor_relay_test_support::{
    ArtifactError, CommitDigest, EvidenceId, EvidenceManifest, FailureClass, ForbiddenFieldClass,
    LockfileDigest, ProducerKind, ReplaySpec, build_failure_artifact,
  };

  use super::{ArtifactCandidate, SensitiveCandidate};
  use crate::simulation::fixture::{ScenarioFixture, SimulationEvidenceSource};

  #[test]
  fn simulation_failure_artifact_security_rejects_every_forbidden_class_before_hashing() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let sentinel = b"do-not-retain-secret-sentinel";
    let classes = [
      ForbiddenFieldClass::Credential,
      ForbiddenFieldClass::PrivateKey,
      ForbiddenFieldClass::ProviderHandle,
      ForbiddenFieldClass::Proof,
      ForbiddenFieldClass::Hmac,
      ForbiddenFieldClass::Exporter,
      ForbiddenFieldClass::TlsTicket,
      ForbiddenFieldClass::Transcript,
      ForbiddenFieldClass::Payload,
      ForbiddenFieldClass::PayloadDigest,
      ForbiddenFieldClass::OpaqueValue,
      ForbiddenFieldClass::ResourceLabel,
      ForbiddenFieldClass::ResourceValue,
      ForbiddenFieldClass::Selector,
      ForbiddenFieldClass::RealAddress,
      ForbiddenFieldClass::HostPath,
      ForbiddenFieldClass::Environment,
      ForbiddenFieldClass::ArbitraryError,
      ForbiddenFieldClass::HostileText,
    ];
    let manifest = EvidenceManifest::new(
      ProducerKind::Simulation,
      EvidenceId::new("SC-G01-P0-04").unwrap(),
      EvidenceId::new("simulation-network-fault-matrix").unwrap(),
      Some(1),
      FailureClass::Invariant,
      EvidenceId::new("forbidden-field").unwrap(),
      CommitDigest::parse_hex("1111111111111111111111111111111111111111").unwrap(),
      LockfileDigest::from_bytes([0x22; 32]),
      ReplaySpec::simulation_network_fault_matrix(1),
    )
    .unwrap();

    for class in classes {
      let candidate = SensitiveCandidate::new(class, sentinel);
      assert_eq!(format!("{candidate:?}"), "SensitiveCandidate([REDACTED])");
      let candidates = [ArtifactCandidate::Forbidden(candidate)];
      let source = SimulationEvidenceSource::candidates(&fixture, &candidates);
      let result = build_failure_artifact(&manifest, &source);
      assert_eq!(result, Err(ArtifactError::ForbiddenField(class)));
      assert!(!format!("{result:?}").contains("do-not-retain"));
    }
  }
}

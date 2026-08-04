#[cfg(test)]
mod tests {
  use super::{ArtifactCandidate, ForbiddenFieldClass, RedactionError, SensitiveCandidate};
  use crate::simulation::fixture::ScenarioFixture;

  #[test]
  fn simulation_failure_artifact_security_rejects_forbidden_fields_before_normalization() {
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

    for class in classes {
      let candidate = SensitiveCandidate::new(class, sentinel);
      assert_eq!(format!("{candidate:?}"), "SensitiveCandidate([REDACTED])");
      let result = fixture.normalize_candidates([ArtifactCandidate::Forbidden(candidate)]);
      assert_eq!(result, Err(RedactionError::ForbiddenField(class)));
      assert!(!format!("{result:?}").contains("do-not-retain"));
    }
  }
}

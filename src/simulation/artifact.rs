use std::{
  fs::{self, File, OpenOptions},
  io::{self, Write},
  path::{Path, PathBuf},
  process::Command as ProcessCommand,
  sync::atomic::{AtomicU64, Ordering},
};

use minor_relay_test_support::{
  ArtifactBytes, CommitDigest, EvidenceId, EvidenceManifest, FailureClass, LockfileDigest,
  ProducerKind, ReplaySpec, build_failure_artifact,
};

use crate::simulation::{
  event::EventRecord,
  fixture::{ScenarioFixture, SimulationEvidenceSource},
  network::run_fault_matrix_seed,
};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatrixFailure {
  Run,
  DeterministicReplay,
  FaultCoverage,
  EventOrder,
  PendingEventBound,
  PendingByteBound,
  FingerprintCollision,
}

impl MatrixFailure {
  pub(crate) const fn diagnostic(self) -> &'static str {
    match self {
      Self::Run => "matrix-run",
      Self::DeterministicReplay => "deterministic-replay",
      Self::FaultCoverage => "complete-fault-matrix",
      Self::EventOrder => "ordered-event-stream",
      Self::PendingEventBound => "pending-event-bound",
      Self::PendingByteBound => "pending-byte-bound",
      Self::FingerprintCollision => "seed-fingerprint-uniqueness",
    }
  }

  const fn invariant_id(self) -> &'static str {
    self.diagnostic()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureCaptureError {
  GitUnavailable,
  InvalidCommit,
  LockfileUnavailable,
  InvalidMetadata,
  InvalidSource,
  Artifact,
  Directory,
  Write,
  Simulation,
}

#[derive(Clone, Copy)]
struct TrustedProvenance {
  commit: CommitDigest,
  lockfile: LockfileDigest,
}

fn trusted_provenance() -> Result<TrustedProvenance, FailureCaptureError> {
  let root = Path::new(env!("CARGO_MANIFEST_DIR"));
  let output = ProcessCommand::new("git")
    .args(["rev-parse", "HEAD"])
    .current_dir(root)
    .output()
    .map_err(|_| FailureCaptureError::GitUnavailable)?;
  if !output.status.success() {
    return Err(FailureCaptureError::GitUnavailable);
  }
  let commit_text = std::str::from_utf8(&output.stdout)
    .map_err(|_| FailureCaptureError::InvalidCommit)?
    .trim_end_matches(['\r', '\n']);
  let commit =
    CommitDigest::parse_hex(commit_text).map_err(|_| FailureCaptureError::InvalidCommit)?;
  let lockfile =
    fs::read(root.join("Cargo.lock")).map_err(|_| FailureCaptureError::LockfileUnavailable)?;
  Ok(TrustedProvenance {
    commit,
    lockfile: LockfileDigest::sha256(&lockfile),
  })
}

fn synthetic_fixture_provenance() -> Result<TrustedProvenance, FailureCaptureError> {
  let commit = CommitDigest::parse_hex("1111111111111111111111111111111111111111")
    .map_err(|_| FailureCaptureError::InvalidCommit)?;
  Ok(TrustedProvenance {
    commit,
    lockfile: LockfileDigest::from_bytes([0x22; 32]),
  })
}

fn matrix_manifest(
  seed: u64, failure: MatrixFailure, provenance: TrustedProvenance,
) -> Result<EvidenceManifest, FailureCaptureError> {
  let scenario =
    EvidenceId::new("SC-G01-P0-04").map_err(|_| FailureCaptureError::InvalidMetadata)?;
  let test = EvidenceId::new("simulation-network-fault-matrix")
    .map_err(|_| FailureCaptureError::InvalidMetadata)?;
  let invariant =
    EvidenceId::new(failure.invariant_id()).map_err(|_| FailureCaptureError::InvalidMetadata)?;
  EvidenceManifest::new(
    ProducerKind::Simulation,
    scenario,
    test,
    Some(seed),
    FailureClass::Invariant,
    invariant,
    provenance.commit,
    provenance.lockfile,
    ReplaySpec::simulation_network_fault_matrix(seed),
  )
  .map_err(|_| FailureCaptureError::InvalidMetadata)
}

fn build_matrix_artifact(
  seed: u64, failure: MatrixFailure, provenance: TrustedProvenance, records: &[EventRecord],
) -> Result<ArtifactBytes, FailureCaptureError> {
  let fixture =
    ScenarioFixture::network_fault_matrix().map_err(|_| FailureCaptureError::InvalidSource)?;
  let source = SimulationEvidenceSource::records(&fixture, records);
  let manifest = matrix_manifest(seed, failure, provenance)?;
  build_failure_artifact(&manifest, &source).map_err(|_| FailureCaptureError::Artifact)
}

pub(crate) fn retain_matrix_failure(
  seed: u64, failure: MatrixFailure, records: &[EventRecord],
) -> Result<(), FailureCaptureError> {
  let provenance = trusted_provenance()?;
  retain_matrix_failure_at(
    Path::new(env!("CARGO_MANIFEST_DIR")),
    seed,
    failure,
    records,
    provenance,
  )
  .map(|_| ())
}

fn retain_matrix_failure_at(
  repository_root: &Path, seed: u64, failure: MatrixFailure, records: &[EventRecord],
  provenance: TrustedProvenance,
) -> Result<PathBuf, FailureCaptureError> {
  let artifact = build_matrix_artifact(seed, failure, provenance, records)?;
  write_failure_artifact(repository_root, seed, failure, &artifact)
}

pub(crate) fn fail_matrix(seed: u64, failure: MatrixFailure, records: &[EventRecord]) -> ! {
  let diagnostic = failure.diagnostic();
  match retain_matrix_failure(seed, failure, records) {
    Ok(()) => panic!("simulation matrix failure: class={diagnostic}, seed={seed}"),
    Err(_) => panic!("simulation artifact retention failure: class={diagnostic}, seed={seed}"),
  }
}

fn write_failure_artifact(
  repository_root: &Path, seed: u64, failure: MatrixFailure, artifact: &ArtifactBytes,
) -> Result<PathBuf, FailureCaptureError> {
  let directory = repository_root.join("target/minor-relay-failures");
  fs::create_dir_all(&directory).map_err(|_| FailureCaptureError::Directory)?;
  let path = directory.join(format!(
    "simulation-network-fault-matrix-{}-seed-{seed}.json",
    failure.diagnostic()
  ));
  publish_new_file(&path, |file| {
    file.write_all(artifact.as_bytes())?;
    file.sync_all()
  })?;
  Ok(path)
}

fn publish_new_file(
  final_path: &Path, write_complete: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<(), FailureCaptureError> {
  let directory = final_path.parent().ok_or(FailureCaptureError::Directory)?;
  let file_name = final_path
    .file_name()
    .and_then(|value| value.to_str())
    .ok_or(FailureCaptureError::Write)?;
  let (temp_path, mut file) = create_temp_file(directory, file_name)?;
  let write_result = write_complete(&mut file);
  drop(file);
  let result = write_result.and_then(|()| fs::hard_link(&temp_path, final_path));
  let _ = fs::remove_file(&temp_path);
  result.map_err(|_| FailureCaptureError::Write)
}

fn create_temp_file(
  directory: &Path, final_name: &str,
) -> Result<(PathBuf, File), FailureCaptureError> {
  for _ in 0..64 {
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let path = directory.join(format!(
      ".{final_name}.tmp-{}-{sequence}",
      std::process::id()
    ));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
      Ok(file) => return Ok((path, file)),
      Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
      Err(_) => return Err(FailureCaptureError::Write),
    }
  }
  Err(FailureCaptureError::Write)
}

pub(crate) fn capture_network_fault_matrix_fixture(
  seed: u64,
) -> Result<ArtifactBytes, FailureCaptureError> {
  let run = run_fault_matrix_seed(seed).map_err(|_| FailureCaptureError::Simulation)?;
  build_matrix_artifact(
    seed,
    MatrixFailure::FaultCoverage,
    synthetic_fixture_provenance()?,
    run.records(),
  )
}

#[cfg(test)]
mod tests {
  use std::{
    fs,
    io::{self, Write},
    path::Path,
  };

  use minor_relay_test_support::MAX_ARTIFACT_BYTES;

  use super::{
    FailureCaptureError, MatrixFailure, build_matrix_artifact,
    capture_network_fault_matrix_fixture, publish_new_file, retain_matrix_failure_at,
    synthetic_fixture_provenance, trusted_provenance, write_failure_artifact,
  };

  #[test]
  fn simulation_failure_artifact_security_simulation_capture_is_byte_stable() {
    let first = capture_network_fault_matrix_fixture(4_242).unwrap();
    let second = capture_network_fault_matrix_fixture(4_242).unwrap();
    let changed = capture_network_fault_matrix_fixture(4_243).unwrap();
    assert_eq!(first, second);
    assert_ne!(first.as_bytes(), changed.as_bytes());
    assert_ne!(first.event_digest(), changed.event_digest());
    assert!(
      first
        .as_bytes()
        .windows(11)
        .any(|window| window == b"endpoint-5\"")
    );
    assert!(
      !first
        .as_bytes()
        .windows(10)
        .any(|window| window == b"\"address\":")
    );
  }

  #[test]
  fn simulation_failure_artifact_security_simulation_matches_golden_fixture() {
    let artifact = capture_network_fault_matrix_fixture(4_242).unwrap();
    let golden = include_bytes!("../../tests/fixtures/failure-artifacts/simulation-v1.json");
    assert_eq!(artifact.as_bytes(), golden);
  }

  #[test]
  fn simulation_failure_artifact_security_real_provenance_is_validated() {
    assert!(trusted_provenance().is_ok());
  }

  #[test]
  fn simulation_failure_artifact_security_actual_failure_retention_uses_real_provenance() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "minor-relay-real-provenance-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    let provenance = trusted_provenance().unwrap();
    let path = retain_matrix_failure_at(&root, 92, MatrixFailure::Run, &[], provenance).unwrap();
    let bytes = fs::read(&path).unwrap();
    let encoded = std::str::from_utf8(&bytes).unwrap();
    assert!(bytes.len() <= MAX_ARTIFACT_BYTES);
    assert!(bytes.starts_with(b"{\"schema\":\"relay.woooo.tech/schemas/failure-replay\""));
    assert!(encoded.contains(&format!(
      "\"commit_digest\":\"{}\"",
      provenance.commit.as_hex()
    )));
    assert!(encoded.contains(&format!(
      "\"lockfile_digest\":\"{}\"",
      provenance.lockfile.as_hex()
    )));
    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_partial_write_is_not_published() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "minor-relay-partial-artifact-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let final_path = root.join("simulation-network-fault-matrix-run-seed-1.json");

    let result = publish_new_file(&final_path, |file| {
      file.write_all(b"partial")?;
      Err(io::Error::other("injected write failure"))
    });

    assert_eq!(result, Err(FailureCaptureError::Write));
    assert!(!final_path.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(&root).unwrap();
  }

  #[test]
  fn simulation_failure_artifact_security_writer_uses_bounded_closed_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("target")
      .join(format!(
        "minor-relay-failure-artifact-test-{}",
        std::process::id()
      ));
    let _ = fs::remove_dir_all(&root);
    let artifact = build_matrix_artifact(
      91,
      MatrixFailure::DeterministicReplay,
      synthetic_fixture_provenance().unwrap(),
      &[],
    )
    .unwrap();
    let path =
      write_failure_artifact(&root, 91, MatrixFailure::DeterministicReplay, &artifact).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes, artifact.as_bytes());
    assert!(bytes.len() <= MAX_ARTIFACT_BYTES);
    assert!(bytes.starts_with(b"{\"schema\":\"relay.woooo.tech/schemas/failure-replay\""));
    assert!(bytes.ends_with(b"}"));
    assert_eq!(
      path.file_name().and_then(|value| value.to_str()),
      Some("simulation-network-fault-matrix-deterministic-replay-seed-91.json")
    );
    assert_eq!(
      write_failure_artifact(&root, 91, MatrixFailure::DeterministicReplay, &artifact,),
      Err(FailureCaptureError::Write),
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    fs::remove_dir_all(&root).unwrap();
  }
}

use std::collections::VecDeque;

use sha2::{Digest as ShaDigest, Sha256};

use crate::simulation::{
  fixture::ScenarioFixture,
  redaction::{ArtifactCandidate, ForbiddenFieldClass, NormalizedEvent, RedactionError},
  scenario::ReplaySpec,
};

pub(crate) const MAX_ARTIFACT_BYTES: usize = 1_048_576;
pub(crate) const MAX_RETAINED_EVENTS: usize = 10_000;
const EVENT_DIGEST_DOMAIN: &[u8] = b"relay.woooo.tech/failure-replay/event-stream/v1";
const FAILURE_SCHEMA: &str = "relay.woooo.tech/schemas/failure-replay";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceDigest([u8; 32]);

impl EvidenceDigest {
  pub(crate) const fn new(bytes: [u8; 32]) -> Self {
    Self(bytes)
  }

  pub(crate) fn as_hex(self) -> String {
    encode_hex(&self.0)
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureClass {
  Assertion,
  Invariant,
  Panic,
  Timeout,
  Capacity,
}

impl FailureClass {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Assertion => "assertion",
      Self::Invariant => "invariant",
      Self::Panic => "panic",
      Self::Timeout => "timeout",
      Self::Capacity => "capacity",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvariantId {
  CompleteFaultMatrix,
  DeterministicReplay,
  ConfiguredBounds,
}

impl InvariantId {
  const fn as_str(self) -> &'static str {
    match self {
      Self::CompleteFaultMatrix => "complete-fault-matrix",
      Self::DeterministicReplay => "deterministic-replay",
      Self::ConfiguredBounds => "configured-bounds",
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceManifest {
  seed: u64,
  failure_class: FailureClass,
  invariant_id: InvariantId,
  commit_digest: EvidenceDigest,
  lockfile_digest: EvidenceDigest,
  replay: ReplaySpec,
}

impl EvidenceManifest {
  pub(crate) fn network_fault_matrix(
    seed: u64, failure_class: FailureClass, invariant_id: InvariantId,
    commit_digest: EvidenceDigest, lockfile_digest: EvidenceDigest, replay: ReplaySpec,
  ) -> Result<Self, ArtifactError> {
    if replay.simulation_seed() != Some(seed) {
      return Err(ArtifactError::ReplaySeedMismatch);
    }
    Ok(Self {
      seed,
      failure_class,
      invariant_id,
      commit_digest,
      lockfile_digest,
      replay,
    })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactLimits {
  byte_ceiling: usize,
  event_ceiling: usize,
}

impl ArtifactLimits {
  const DEFAULT: Self = Self {
    byte_ceiling: MAX_ARTIFACT_BYTES,
    event_ceiling: MAX_RETAINED_EVENTS,
  };

  #[cfg(test)]
  pub(crate) const fn for_test(
    byte_ceiling: usize, event_ceiling: usize,
  ) -> Result<Self, ArtifactError> {
    if byte_ceiling == 0
      || byte_ceiling > MAX_ARTIFACT_BYTES
      || event_ceiling == 0
      || event_ceiling > MAX_RETAINED_EVENTS
    {
      return Err(ArtifactError::InvalidLimits);
    }
    Ok(Self {
      byte_ceiling,
      event_ceiling,
    })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactTruncation {
  total_events: usize,
  retained_events: usize,
  first_events: usize,
  last_events: usize,
  count_truncated: bool,
  byte_truncated: bool,
}

impl ArtifactTruncation {
  pub(crate) const fn total_events(self) -> usize {
    self.total_events
  }

  pub(crate) const fn retained_events(self) -> usize {
    self.retained_events
  }

  pub(crate) const fn omitted_events(self) -> usize {
    self.total_events - self.retained_events
  }

  pub(crate) const fn first_events(self) -> usize {
    self.first_events
  }

  pub(crate) const fn last_events(self) -> usize {
    self.last_events
  }

  pub(crate) const fn count_truncated(self) -> bool {
    self.count_truncated
  }

  pub(crate) const fn byte_truncated(self) -> bool {
    self.byte_truncated
  }

  const fn truncated(self) -> bool {
    self.count_truncated || self.byte_truncated
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactBytes {
  bytes: Vec<u8>,
  event_digest: EvidenceDigest,
  truncation: ArtifactTruncation,
  first_window: Vec<NormalizedEvent>,
  last_window: Vec<NormalizedEvent>,
}

impl ArtifactBytes {
  pub(crate) fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }

  pub(crate) const fn event_digest(&self) -> EvidenceDigest {
    self.event_digest
  }

  pub(crate) const fn truncation(&self) -> ArtifactTruncation {
    self.truncation
  }

  pub(crate) fn first_window(&self) -> &[NormalizedEvent] {
    &self.first_window
  }

  pub(crate) fn last_window(&self) -> &[NormalizedEvent] {
    &self.last_window
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactError {
  ForbiddenField(ForbiddenFieldClass),
  Redaction(RedactionError),
  Simulation(crate::simulation::topology::SimulationError),
  ReplaySeedMismatch,
  InvalidLimits,
  EventCountOverflow,
  EncodingOverflow,
  ByteCeiling,
  FixedFieldsExceedByteCeiling,
}

impl From<RedactionError> for ArtifactError {
  fn from(value: RedactionError) -> Self {
    match value {
      RedactionError::ForbiddenField(class) => Self::ForbiddenField(class),
      other => Self::Redaction(other),
    }
  }
}

impl From<crate::simulation::topology::SimulationError> for ArtifactError {
  fn from(value: crate::simulation::topology::SimulationError) -> Self {
    Self::Simulation(value)
  }
}

pub(crate) fn build_failure_artifact(
  manifest: &EvidenceManifest, fixture: &ScenarioFixture, candidates: &[ArtifactCandidate<'_>],
) -> Result<ArtifactBytes, ArtifactError> {
  build_failure_artifact_with_limits(manifest, fixture, candidates, ArtifactLimits::DEFAULT)
}

fn build_failure_artifact_with_limits(
  manifest: &EvidenceManifest, fixture: &ScenarioFixture, candidates: &[ArtifactCandidate<'_>],
  limits: ArtifactLimits,
) -> Result<ArtifactBytes, ArtifactError> {
  let mut total_events = 0_usize;
  for candidate in candidates {
    fixture.normalize_candidate(*candidate)?;
    total_events = total_events
      .checked_add(1)
      .ok_or(ArtifactError::EventCountOverflow)?;
  }

  let total_u64 = u64::try_from(total_events).map_err(|_| ArtifactError::EventCountOverflow)?;
  let domain_len =
    u16::try_from(EVENT_DIGEST_DOMAIN.len()).map_err(|_| ArtifactError::EncodingOverflow)?;
  let mut hasher = Sha256::new();
  hasher.update(domain_len.to_be_bytes());
  hasher.update(EVENT_DIGEST_DOMAIN);
  hasher.update(total_u64.to_be_bytes());

  let mut windows = EventWindows::new(limits.event_ceiling);
  for candidate in candidates {
    let event = fixture.normalize_candidate(*candidate)?;
    let encoded = encode_event(event)?;
    let encoded_len = u32::try_from(encoded.len()).map_err(|_| ArtifactError::EncodingOverflow)?;
    hasher.update(encoded_len.to_be_bytes());
    hasher.update(encoded);
    windows.push(event);
  }
  let event_digest = EvidenceDigest::new(hasher.finalize().into());

  let max_retained = total_events.min(limits.event_ceiling);
  let retained_events = select_retained_count(
    manifest,
    event_digest,
    total_events,
    max_retained,
    &windows,
    limits,
  )?;
  let (first_window, last_window) = windows.select(retained_events, total_events);
  let truncation = ArtifactTruncation {
    total_events,
    retained_events,
    first_events: first_window.len(),
    last_events: last_window.len(),
    count_truncated: total_events > limits.event_ceiling,
    byte_truncated: retained_events < max_retained,
  };
  let bytes = render_artifact(
    manifest,
    event_digest,
    truncation,
    &first_window,
    &last_window,
    limits.byte_ceiling,
  )?;
  Ok(ArtifactBytes {
    bytes,
    event_digest,
    truncation,
    first_window,
    last_window,
  })
}

fn select_retained_count(
  manifest: &EvidenceManifest, event_digest: EvidenceDigest, total_events: usize,
  max_retained: usize, windows: &EventWindows, limits: ArtifactLimits,
) -> Result<usize, ArtifactError> {
  if candidate_fits(
    manifest,
    event_digest,
    total_events,
    max_retained,
    windows,
    limits,
  ) {
    return Ok(max_retained);
  }
  if !candidate_fits(manifest, event_digest, total_events, 0, windows, limits) {
    return Err(ArtifactError::FixedFieldsExceedByteCeiling);
  }

  let mut fitting = 0_usize;
  let mut rejected = max_retained;
  while rejected - fitting > 1 {
    let candidate = fitting + (rejected - fitting) / 2;
    if candidate_fits(
      manifest,
      event_digest,
      total_events,
      candidate,
      windows,
      limits,
    ) {
      fitting = candidate;
    } else {
      rejected = candidate;
    }
  }
  Ok(fitting)
}

fn candidate_fits(
  manifest: &EvidenceManifest, event_digest: EvidenceDigest, total_events: usize,
  retained_events: usize, windows: &EventWindows, limits: ArtifactLimits,
) -> bool {
  let (first, last) = windows.select(retained_events, total_events);
  let truncation = ArtifactTruncation {
    total_events,
    retained_events,
    first_events: first.len(),
    last_events: last.len(),
    count_truncated: total_events > limits.event_ceiling,
    byte_truncated: retained_events < total_events.min(limits.event_ceiling),
  };
  render_artifact(
    manifest,
    event_digest,
    truncation,
    &first,
    &last,
    limits.byte_ceiling,
  )
  .is_ok()
}

struct EventWindows {
  first: Vec<NormalizedEvent>,
  last: VecDeque<NormalizedEvent>,
  first_capacity: usize,
  last_capacity: usize,
}

impl EventWindows {
  fn new(event_ceiling: usize) -> Self {
    let first_capacity = event_ceiling.div_ceil(2);
    let last_capacity = event_ceiling / 2;
    Self {
      first: Vec::with_capacity(first_capacity),
      last: VecDeque::with_capacity(last_capacity),
      first_capacity,
      last_capacity,
    }
  }

  fn push(&mut self, event: NormalizedEvent) {
    if self.first.len() < self.first_capacity {
      self.first.push(event);
    }
    if self.last_capacity == 0 {
      return;
    }
    if self.last.len() == self.last_capacity {
      self.last.pop_front();
    }
    self.last.push_back(event);
  }

  fn select(
    &self, retained_events: usize, total_events: usize,
  ) -> (Vec<NormalizedEvent>, Vec<NormalizedEvent>) {
    if retained_events == total_events {
      let first_count = total_events.min(self.first.len());
      let last_count = total_events - first_count;
      let first = self.first[..first_count].to_vec();
      let last = self
        .last
        .iter()
        .skip(self.last.len() - last_count)
        .copied()
        .collect::<Vec<_>>();
      return (first, last);
    }
    let first_count = retained_events.div_ceil(2);
    let last_count = retained_events / 2;
    let first = self.first[..first_count].to_vec();
    let last = self
      .last
      .iter()
      .skip(self.last.len() - last_count)
      .copied()
      .collect::<Vec<_>>();
    (first, last)
  }
}

fn render_artifact(
  manifest: &EvidenceManifest, event_digest: EvidenceDigest, truncation: ArtifactTruncation,
  first: &[NormalizedEvent], last: &[NormalizedEvent], byte_ceiling: usize,
) -> Result<Vec<u8>, ArtifactError> {
  let mut writer = JsonWriter::new(byte_ceiling);
  writer.raw(b"{\"schema\":")?;
  writer.quoted(FAILURE_SCHEMA)?;
  writer.raw(b",\"scenario_id\":\"SC-G01-P0-04\"")?;
  writer.raw(b",\"test_id\":\"simulation-network-fault-matrix\"")?;
  writer.raw(b",\"seed\":")?;
  writer.unsigned(manifest.seed)?;
  writer.raw(b",\"event_digest\":")?;
  writer.quoted(&event_digest.as_hex())?;
  writer.raw(b",\"failure_class\":")?;
  writer.quoted(manifest.failure_class.as_str())?;
  writer.raw(b",\"invariant_id\":")?;
  writer.quoted(manifest.invariant_id.as_str())?;
  writer.raw(b",\"commit_digest\":")?;
  writer.quoted(&manifest.commit_digest.as_hex())?;
  writer.raw(b",\"lockfile_digest\":")?;
  writer.quoted(&manifest.lockfile_digest.as_hex())?;
  writer.raw(b",\"bounds\":{\"artifact_bytes\":1048576,\"retained_events\":10000}")?;
  writer.raw(b",\"truncation\":{\"truncated\":")?;
  writer.boolean(truncation.truncated())?;
  writer.raw(b",\"count_truncated\":")?;
  writer.boolean(truncation.count_truncated)?;
  writer.raw(b",\"byte_truncated\":")?;
  writer.boolean(truncation.byte_truncated)?;
  writer.raw(b",\"total_events\":")?;
  writer.unsigned(truncation.total_events)?;
  writer.raw(b",\"retained_events\":")?;
  writer.unsigned(truncation.retained_events)?;
  writer.raw(b",\"omitted_events\":")?;
  writer.unsigned(truncation.omitted_events())?;
  writer.raw(b",\"first_events\":")?;
  writer.unsigned(truncation.first_events)?;
  writer.raw(b",\"last_events\":")?;
  writer.unsigned(truncation.last_events)?;
  writer.raw(b"},\"events\":{\"first\":")?;
  write_events(&mut writer, first)?;
  writer.raw(b",\"last\":")?;
  write_events(&mut writer, last)?;
  writer.raw(b"},\"replay\":{\"executable_id\":")?;
  writer.quoted(manifest.replay.executable_id().as_str())?;
  writer.raw(b",\"argv\":[")?;
  for (index, argument) in manifest.replay.argv().iter().enumerate() {
    if index > 0 {
      writer.raw(b",")?;
    }
    writer.quoted(argument)?;
  }
  writer.raw(b"]}}")?;
  Ok(writer.finish())
}

fn write_events(writer: &mut JsonWriter, events: &[NormalizedEvent]) -> Result<(), ArtifactError> {
  writer.raw(b"[")?;
  for (index, event) in events.iter().enumerate() {
    if index > 0 {
      writer.raw(b",")?;
    }
    write_event(writer, *event)?;
  }
  writer.raw(b"]")
}

fn encode_event(event: NormalizedEvent) -> Result<Vec<u8>, ArtifactError> {
  let mut writer = JsonWriter::new(MAX_ARTIFACT_BYTES);
  write_event(&mut writer, event)?;
  Ok(writer.finish())
}

fn write_event(writer: &mut JsonWriter, event: NormalizedEvent) -> Result<(), ArtifactError> {
  writer.raw(b"{\"kind\":")?;
  writer.quoted(event.kind().as_str())?;
  writer.raw(b",\"at_nanos\":")?;
  writer.unsigned(event.at_nanos())?;
  match event {
    NormalizedEvent::SendAccepted {
      message,
      path,
      copies,
      payload_len,
      ..
    } => {
      writer.raw(b",\"message\":")?;
      writer.unsigned(message)?;
      writer.raw(b",\"path\":")?;
      writer.alias("path", path.ordinal())?;
      writer.raw(b",\"copies\":")?;
      writer.unsigned(copies)?;
      writer.raw(b",\"payload_len\":")?;
      writer.unsigned(payload_len)?;
    }
    NormalizedEvent::Lost { message, .. } | NormalizedEvent::DuplicateCreated { message, .. } => {
      writer.raw(b",\"message\":")?;
      writer.unsigned(message)?;
    }
    NormalizedEvent::Reordered { message, copy, .. }
    | NormalizedEvent::Delivered { message, copy, .. } => {
      writer.raw(b",\"message\":")?;
      writer.unsigned(message)?;
      writer.raw(b",\"copy\":")?;
      writer.unsigned(copy)?;
    }
    NormalizedEvent::Dropped {
      message,
      copy,
      reason,
      ..
    } => {
      writer.raw(b",\"message\":")?;
      writer.unsigned(message)?;
      writer.raw(b",\"copy\":")?;
      writer.unsigned(copy)?;
      writer.raw(b",\"reason\":")?;
      writer.quoted(reason.as_str())?;
    }
    NormalizedEvent::Partitioned {
      path,
      fault,
      generation,
      ..
    }
    | NormalizedEvent::Healed {
      path,
      fault,
      generation,
      ..
    } => {
      writer.raw(b",\"path\":")?;
      writer.alias("path", path.ordinal())?;
      writer.raw(b",\"fault\":")?;
      writer.alias("fault", fault.ordinal())?;
      writer.raw(b",\"generation\":")?;
      writer.unsigned(generation)?;
    }
    NormalizedEvent::Restarted {
      node, boot_epoch, ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.alias("node", node.ordinal())?;
      writer.raw(b",\"boot_epoch\":")?;
      writer.unsigned(boot_epoch)?;
    }
    NormalizedEvent::AddressChanged {
      node,
      endpoint,
      generation,
      ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.alias("node", node.ordinal())?;
      writer.raw(b",\"endpoint\":")?;
      writer.alias("endpoint", endpoint.ordinal())?;
      writer.raw(b",\"generation\":")?;
      writer.unsigned(generation)?;
    }
    NormalizedEvent::ClockSkewChanged {
      node, skew_nanos, ..
    } => {
      writer.raw(b",\"node\":")?;
      writer.alias("node", node.ordinal())?;
      writer.raw(b",\"skew_nanos\":")?;
      writer.signed(skew_nanos)?;
    }
    NormalizedEvent::QueueRejected {
      message,
      copies,
      payload_len,
      ..
    } => {
      writer.raw(b",\"message\":")?;
      writer.unsigned(message)?;
      writer.raw(b",\"copies\":")?;
      writer.unsigned(copies)?;
      writer.raw(b",\"payload_len\":")?;
      writer.unsigned(payload_len)?;
    }
  }
  writer.raw(b"}")
}

struct JsonWriter {
  bytes: Vec<u8>,
  limit: usize,
}

impl JsonWriter {
  fn new(limit: usize) -> Self {
    Self {
      bytes: Vec::new(),
      limit,
    }
  }

  fn raw(&mut self, value: &[u8]) -> Result<(), ArtifactError> {
    let next = self
      .bytes
      .len()
      .checked_add(value.len())
      .ok_or(ArtifactError::EncodingOverflow)?;
    if next > self.limit {
      return Err(ArtifactError::ByteCeiling);
    }
    self.bytes.extend_from_slice(value);
    Ok(())
  }

  fn quoted(&mut self, value: &str) -> Result<(), ArtifactError> {
    self.raw(b"\"")?;
    for byte in value.bytes() {
      match byte {
        b'"' => self.raw(b"\\\"")?,
        b'\\' => self.raw(b"\\\\")?,
        0x00..=0x1F => {
          let escaped = [
            b'\\',
            b'u',
            b'0',
            b'0',
            hex_digit(byte >> 4),
            hex_digit(byte & 0x0F),
          ];
          self.raw(&escaped)?;
        }
        _ => self.raw(&[byte])?,
      }
    }
    self.raw(b"\"")
  }

  fn alias(&mut self, prefix: &str, ordinal: u16) -> Result<(), ArtifactError> {
    self.quoted(&format!("{prefix}-{ordinal}"))
  }

  fn unsigned<T: ToString>(&mut self, value: T) -> Result<(), ArtifactError> {
    self.raw(value.to_string().as_bytes())
  }

  fn signed(&mut self, value: i64) -> Result<(), ArtifactError> {
    self.raw(value.to_string().as_bytes())
  }

  fn boolean(&mut self, value: bool) -> Result<(), ArtifactError> {
    self.raw(if value { b"true" } else { b"false" })
  }

  fn finish(self) -> Vec<u8> {
    self.bytes
  }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
  let mut encoded = String::with_capacity(64);
  for byte in bytes {
    encoded.push(char::from(hex_digit(byte >> 4)));
    encoded.push(char::from(hex_digit(byte & 0x0F)));
  }
  encoded
}

const fn hex_digit(value: u8) -> u8 {
  match value {
    0..=9 => b'0' + value,
    _ => b'a' + (value - 10),
  }
}

#[cfg(test)]
mod tests {
  use super::{
    ArtifactError, ArtifactLimits, EvidenceDigest, EvidenceManifest, FailureClass, InvariantId,
    MAX_ARTIFACT_BYTES, MAX_RETAINED_EVENTS, build_failure_artifact,
    build_failure_artifact_with_limits,
  };
  use crate::simulation::{
    event::{EventRecord, MessageId},
    fixture::ScenarioFixture,
    redaction::{ArtifactCandidate, ForbiddenFieldClass, SensitiveCandidate},
    scenario::ReplaySpec,
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
  fn simulation_failure_artifact_security_failure_metadata_is_closed() {
    assert_eq!(FailureClass::Assertion.as_str(), "assertion");
    assert_eq!(FailureClass::Invariant.as_str(), "invariant");
    assert_eq!(FailureClass::Panic.as_str(), "panic");
    assert_eq!(FailureClass::Timeout.as_str(), "timeout");
    assert_eq!(FailureClass::Capacity.as_str(), "capacity");
    assert_eq!(
      InvariantId::CompleteFaultMatrix.as_str(),
      "complete-fault-matrix"
    );
    assert_eq!(
      InvariantId::DeterministicReplay.as_str(),
      "deterministic-replay"
    );
    assert_eq!(InvariantId::ConfiguredBounds.as_str(), "configured-bounds");
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
      first.truncation().retained_events().div_ceil(2),
    );
    assert_eq!(
      first.truncation().last_events(),
      first.truncation().retained_events() / 2,
    );

    let tighter =
      ArtifactLimits::for_test(first.as_bytes().len() - 1, MAX_RETAINED_EVENTS).unwrap();
    let tighter_artifact =
      build_failure_artifact_with_limits(&manifest(9), &fixture, &candidates, tighter).unwrap();
    assert!(tighter_artifact.truncation().retained_events() < first.truncation().retained_events());
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

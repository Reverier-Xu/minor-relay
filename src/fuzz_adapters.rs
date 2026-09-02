//! The bounded fuzz adapters for the canonical decoder and selector fuzz
//! targets (T-G10-03).
//!
//! The module exists only under `cfg(any(test, fuzzing))`: the corpus
//! replay suites reuse it for the out-of-libFuzzer ordered replay, the
//! libFuzzer targets drive it under `cargo fuzz`, and no production or
//! test-only surface outside this module changes. Every adapter is
//! panic-free by construction: it feeds the exact same fail-closed
//! decoders the production paths use and maps every outcome to a value.

use crate::{
  FeatureTag,
  identity::records::{
    AdmissionGrantV1, ClusterGenesisV1, CredentialUseV1, IdentityBindingV1, KeyCreationIntentV1,
    KeyDeletedV1, KeyDeletionIntentV1, LocalClusterPointerV1, LocalIdentityV1,
  },
  membership::page::decode_descriptor,
  packet::wire,
  protocol::{CONTROL_CBOR_LIMITS, wire as protocol_wire},
  resource::ResourceRecordV1,
  routing::trace::decode_trace_record,
  storage::{migration::decode_schema_record, pending::PendingTransactionV1},
};

/// One packet frame decoded by the wire target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireFrame {
  Open,
  Chunk,
  End,
  Ack,
}

/// The wire target (ADR-0004 `wire_decode`): prelude splitting, closed
/// kind lookups, and every packet frame body decoder. The prelude half
/// exercises the exact `split_message` boundary the transport uses; the
/// body half decodes the input as each packet frame shape directly.
pub fn wire_decode(input: &[u8]) -> Vec<WireFrame> {
  let mut decoded = Vec::new();
  // Prelude lane: any input carrying a valid 16-byte prelude with a
  // declared kind and a bounded body must split cleanly.
  let limit = u32::try_from(CONTROL_CBOR_LIMITS.max_body_len()).unwrap_or(u32::MAX);
  let _ =
    crate::protocol::envelope::split_message(input, 0, limit, limit, protocol_wire::is_declared);
  // Closed-registry lane: schema/kind bytes never resolve outside the
  // frozen registries.
  if input.len() >= 4 {
    let schema = u16::from_be_bytes([input[0], input[1]]);
    let kind = u16::from_be_bytes([input[2], input[3]]);
    if protocol_wire::lookup(schema, kind).is_some() {
      decoded.push(WireFrame::Open);
    }
  }
  // Frame-body lane: the same caller-selected limits production uses.
  if wire::decode_open(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Open);
  }
  if wire::decode_chunk(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Chunk);
  }
  if wire::decode_end(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::End);
  }
  if wire::decode_ack(input, CONTROL_CBOR_LIMITS).is_ok() {
    decoded.push(WireFrame::Ack);
  }
  decoded
}

/// The persisted target (ADR-0004 `persisted_decode`): every frozen
/// metadata record decoder across the identity, node, resource, trace,
/// transaction, and migration families. Each decoder is the exact
/// fail-closed production path; any outcome other than a clean
/// `Ok`/typed-`Err` is a fuzz finding.
pub fn persisted_decode(input: &[u8]) {
  let _ = LocalIdentityV1::decode(input);
  let _ = KeyCreationIntentV1::decode(input);
  let _ = KeyDeletionIntentV1::decode(input);
  let _ = KeyDeletedV1::decode(input);
  let _ = IdentityBindingV1::decode(input);
  let _ = ClusterGenesisV1::decode(input);
  let _ = LocalClusterPointerV1::decode(input);
  let _ = CredentialUseV1::decode(input);
  let _ = AdmissionGrantV1::decode(input);
  let _ = decode_descriptor(input);
  let _ = ResourceRecordV1::decode(input);
  let _ = decode_trace_record(input);
  let _ = PendingTransactionV1::decode(input);
  // The migration schema-record grammar is byte-framed: kind byte, tag
  // length, tag text, optional 32-byte digest.
  let _ = decode_schema_record(&crate::StoreValue::new(std::sync::Arc::from(input)));
}

/// The selector target (ADR-0004 `selector`): the bounded parser plus the
/// canonical round-trip invariant. Two parses of one input converge, the
/// canonical text reparses to itself, and every outcome is a value.
pub fn selector_parse(input: &[u8]) -> Option<String> {
  let text = std::str::from_utf8(input).ok()?;
  let selector = crate::Selector::parse(text).ok()?;
  let canonical = selector.as_str().to_owned();
  let reparsed = crate::Selector::parse(&canonical)
    .unwrap_or_else(|_| panic!("selector canonical text must reparse: {canonical}"));
  assert_eq!(
    reparsed.as_str(),
    canonical,
    "selector canonical form is not a fixed point: {canonical}"
  );
  // The canonical form is bounded by the same parser limits, so it can
  // never grow without bound across round trips.
  assert!(
    canonical.len() <= crate::routing::SELECTOR_INPUT_MAX_BYTES,
    "selector canonical form exceeded the frozen limit"
  );
  let _ = FeatureTag::parse("relay.woooo.tech/features/session-core").ok();
  Some(canonical)
}

#[cfg(test)]
mod replay_tests {
  //! Ordered corpus replay (T-G10-03, SC-G10-P0-10): every approved
  //! retained corpus input replays exactly once in filename order,
  //! outside libFuzzer scheduling. Malformed or over-bound inputs must
  //! fail closed with typed errors and never panic.

  use std::path::PathBuf;

  /// One retained corpus: the manifest digests and the directory listing
  /// must agree exactly, so an omitted fixture or an unscreened addition
  /// fails the suite.
  fn corpus_files(target: &str) -> Vec<(String, PathBuf, Vec<u8>)> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .join("fuzz")
      .join("corpus")
      .join(target);
    let manifest = std::fs::read_to_string(directory.join("manifest.toml"))
      .unwrap_or_else(|error| panic!("missing retained manifest for {target}: {error}"));
    let manifest_digests: Vec<String> = manifest
      .lines()
      .filter_map(|line| line.trim().strip_prefix("digest = \""))
      .map(|line| line.trim_end_matches('"').to_owned())
      .collect();
    assert!(
      !manifest_digests.is_empty(),
      "the retained corpus for {target} has no manifest entries"
    );

    let mut files: Vec<(String, PathBuf, Vec<u8>)> = std::fs::read_dir(&directory)
      .unwrap_or_else(|error| panic!("missing retained corpus directory for {target}: {error}"))
      .filter_map(|entry| entry.ok())
      .map(|entry| entry.path())
      .filter(|path| path.extension().is_some_and(|extension| extension == "bin"))
      .map(|path| {
        let name = path
          .file_stem()
          .and_then(|stem| stem.to_str())
          .expect("corpus file name")
          .to_owned();
        let bytes = std::fs::read(&path).expect("corpus file bytes");
        (name, path, bytes)
      })
      .collect();
    // Filename order: the frozen replay order.
    files.sort_by(|left, right| left.0.cmp(&right.0));

    // Every manifest entry exists and every file is manifest-listed.
    let mut listed = manifest_digests;
    listed.sort();
    let mut present: Vec<String> = files.iter().map(|(name, ..)| name.clone()).collect();
    present.sort();
    assert_eq!(listed, present, "the {target} manifest and corpus diverge");

    // Each file's bytes hash exactly to its frozen digest name.
    use sha2::Digest as _;
    for (name, path, bytes) in &files {
      let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
      assert_eq!(
        crate::hex::encode(&digest),
        *name,
        "corpus file {} does not match its frozen digest",
        path.display()
      );
    }
    files
  }

  /// Replays one input exactly once through the wire target.
  #[test]
  fn wire_corpus_replays_in_filename_order() {
    let files = corpus_files("wire_decode");
    for (name, path, bytes) in &files {
      // The replay result is a value: any clean frame list is
      // acceptable, a panic is a finding.
      let frames = super::wire_decode(bytes);
      assert!(
        frames.len() <= 4,
        "wire corpus entry {name} ({}) produced an impossible frame list",
        path.display()
      );
    }
  }

  /// Replays one input exactly once through the persisted target.
  #[test]
  fn persisted_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("persisted_decode") {
      super::persisted_decode(&bytes);
      let _ = (name, path);
    }
  }

  /// Replays one input exactly once through the selector target; valid
  /// entries must satisfy the canonical fixed-point invariant.
  #[test]
  fn selector_corpus_replays_in_filename_order() {
    for (name, path, bytes) in corpus_files("selector") {
      let canonical = super::selector_parse(&bytes);
      if let Some(canonical) = canonical {
        assert!(
          !canonical.is_empty(),
          "selector corpus entry {name} ({}) parsed to an empty canonical form",
          path.display()
        );
      }
    }
  }
}

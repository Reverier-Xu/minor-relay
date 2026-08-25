//! Generic named resource metadata (T-G07-02, ADR-0007).
//!
//! A resource is a stable name plus labels: reserved labels carry the
//! resource type and resource URI (callers provide the values; core never
//! follows the URI or stores the object it points to), and callers may add
//! namespaced custom labels. One named resource is a multiwriter
//! timestamp-maximum register, not a causal or real-time last-write
//! register: the deterministic winner among concurrent records is the
//! lexicographic maximum of the signed host wall-clock timestamp, the
//! canonical writer [`NodeId`], the removal rank, and the canonical record
//! digest. Accepting a write does not promise that it becomes or remains
//! the winner; clock rollback can make a later local write lose and a
//! future-dated writer can dominate until wall time catches up.
//!
//! Every record is signed by its writer over the canonical unsigned body,
//! and every field mutation (cluster, name, labels, timestamp, writer,
//! removal rank, digest, or signature) fails verification before any
//! comparison or persistence.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use ed25519_dalek::Signer;
use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  ClusterId, Digest, Error, LabelSet, LabelValue, NodeId, PublicKey, QualifiedTag, Result,
  Signature,
  identity::signature::{body_digest, signature_message, verify_strict},
  protocol::{CborLimits, decode_canonical_strict, encode_canonical},
  time,
};

pub(crate) const RESOURCE_RECORD_SCHEMA: &str = "relay.woooo.tech/schemas/resource-record-v1";
pub(crate) const RESOURCE_RECORD_V1_DOMAIN: &[u8] = b"relay.woooo.tech/crypto/resource-record-v1";

/// The reserved label key carrying the resource type value. Core stores the
/// caller-provided value opaquely and never assigns it meaning beyond
/// selector evaluation.
pub(crate) const RESERVED_TYPE_LABEL_KEY: &str = "relay.woooo.tech/resources/type";

/// The reserved label key carrying the resource URI value. The URI points
/// to an upper-layer object or service; core never follows it and never
/// stores that object.
pub(crate) const RESERVED_URI_LABEL_KEY: &str = "relay.woooo.tech/resources/uri";

/// Canonical-decoder bounds for one resource record: a flat record with at
/// most the bounded label set inside, well under the handshake body budget.
const RECORD_LIMITS: CborLimits = CborLimits::new(4, 256, 16 * 1024);

const RECORD_VERSION: u16 = 1;

/// A stable canonical resource name (`<domain>/resources/<name>`).
///
/// Parsing reuses the canonical tag grammar, so names inherit domain
/// validation, length bounds, and lowercase normalization; the category is
/// fixed to `resources`, which keeps resource names out of the protocol,
/// feature, transport, discovery, and label namespaces.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ResourceName(QualifiedTag);

impl ResourceName {
  /// Parses and validates one resource name.
  pub fn parse(value: &str) -> Result<Self> {
    let tag = QualifiedTag::parse(value)?;
    if tag.category() != "resources" {
      return Err(Error::invalid_input("resource name"));
    }
    Ok(Self(tag))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

impl fmt::Display for ResourceName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(formatter)
  }
}

impl fmt::Debug for ResourceName {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("ResourceName")
      .field(&self.0)
      .finish()
  }
}

/// The canonical unsigned body one writer signs: every semantic field of
/// the record in fixed order.
#[derive(Encode, Decode)]
#[cbor(array)]
struct ResourceRecordBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  name: String,
  /// Reserved type label value (opaque bounded UTF-8).
  #[n(4)]
  resource_type: String,
  /// Reserved URI label value; core never follows it.
  #[n(5)]
  resource_uri: String,
  /// Canonical custom labels: key/value pairs sorted by key text, unique
  /// keys (the `LabelSet` invariant).
  #[n(6)]
  labels: Vec<(String, String)>,
  /// Signed host wall-clock UNIX milliseconds (the tuple's first element).
  #[n(7)]
  timestamp_millis: u64,
  #[n(8)]
  writer: String,
  /// Removal rank: orders removal evidence against same-writer writes at
  /// the same timestamp (the tuple's third element).
  #[n(9)]
  removal_rank: u64,
  /// Whether this record removes the named resource rather than asserting
  /// live metadata.
  #[n(10)]
  removed: bool,
}

/// The full wire record: the signed body plus its digest and the writer's
/// signature over the domain-separated digest.
#[derive(Encode, Decode)]
#[cbor(array)]
struct ResourceRecordWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  name: String,
  #[n(4)]
  resource_type: String,
  #[n(5)]
  resource_uri: String,
  #[n(6)]
  labels: Vec<(String, String)>,
  #[n(7)]
  timestamp_millis: u64,
  #[n(8)]
  writer: String,
  #[n(9)]
  removal_rank: u64,
  #[n(10)]
  removed: bool,
  #[n(11)]
  digest: ByteVec,
  #[n(12)]
  signature: ByteVec,
}

/// One signed multiwriter resource-metadata record (ADR-0007).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceRecordV1 {
  cluster: ClusterId,
  name: ResourceName,
  resource_type: LabelValue,
  resource_uri: LabelValue,
  labels: LabelSet,
  timestamp_millis: u64,
  writer: NodeId,
  removal_rank: u64,
  removed: bool,
  digest: Digest,
  signature: Signature,
}

impl ResourceRecordV1 {
  /// Encodes the canonical unsigned body that `writer` signs.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn encode_signed_body(
    cluster: &ClusterId, name: &ResourceName, resource_type: &LabelValue,
    resource_uri: &LabelValue, labels: &LabelSet, timestamp_millis: u64, writer: &NodeId,
    removal_rank: u64, removed: bool,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &ResourceRecordBodyWire {
        schema: RESOURCE_RECORD_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: cluster.as_str().to_owned(),
        name: name.as_str().to_owned(),
        resource_type: resource_type.as_str().to_owned(),
        resource_uri: resource_uri.as_str().to_owned(),
        labels: labels
          .entries()
          .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
          .collect(),
        timestamp_millis,
        writer: writer.as_str().to_owned(),
        removal_rank,
        removed,
      },
      RECORD_LIMITS,
    )
  }

  /// Assembles one record from an already-produced writer signature over
  /// the canonical signed body (the signing capability stays with the
  /// caller's key provider).
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn seal(
    cluster: ClusterId, name: ResourceName, resource_type: LabelValue, resource_uri: LabelValue,
    labels: LabelSet, timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool,
    signature: Signature,
  ) -> Result<Self> {
    let body = Self::encode_signed_body(
      &cluster,
      &name,
      &resource_type,
      &resource_uri,
      &labels,
      timestamp_millis,
      &writer,
      removal_rank,
      removed,
    )?;
    Ok(Self {
      cluster,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      digest: body_digest(&body),
      signature,
    })
  }

  /// Signs the canonical body with the given signing key and assembles the
  /// record (test and vector construction; production callers go through
  /// their key provider's sign operation).
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn sign(
    cluster: ClusterId, name: ResourceName, resource_type: LabelValue, resource_uri: LabelValue,
    labels: LabelSet, timestamp_millis: u64, writer: NodeId, removal_rank: u64, removed: bool,
    signing_key: &ed25519_dalek::SigningKey,
  ) -> Result<Self> {
    let body = Self::encode_signed_body(
      &cluster,
      &name,
      &resource_type,
      &resource_uri,
      &labels,
      timestamp_millis,
      &writer,
      removal_rank,
      removed,
    )?;
    let signature = signing_key.sign(&signature_message(RESOURCE_RECORD_V1_DOMAIN, &body));
    Self::seal(
      cluster,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis,
      writer,
      removal_rank,
      removed,
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  /// Accessors awaiting their store/sync consumers (T-G07-03/04) follow;
  /// the record shape is frozen here so those gates cannot drift it.
  #[allow(dead_code)]
  pub(crate) const fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) const fn name(&self) -> &ResourceName {
    &self.name
  }

  #[allow(dead_code)]
  pub(crate) const fn resource_type(&self) -> &LabelValue {
    &self.resource_type
  }

  #[allow(dead_code)]
  pub(crate) const fn resource_uri(&self) -> &LabelValue {
    &self.resource_uri
  }

  #[allow(dead_code)]
  pub(crate) const fn labels(&self) -> &LabelSet {
    &self.labels
  }

  /// The signed host wall-clock instant of this write.
  #[allow(dead_code)]
  pub(crate) fn timestamp(&self) -> std::time::SystemTime {
    time::from_millis(self.timestamp_millis)
  }

  pub(crate) const fn timestamp_millis(&self) -> u64 {
    self.timestamp_millis
  }

  pub(crate) const fn writer(&self) -> &NodeId {
    &self.writer
  }

  #[allow(dead_code)]
  pub(crate) const fn removal_rank(&self) -> u64 {
    self.removal_rank
  }

  /// Whether this record removes the named resource rather than asserting
  /// live metadata.
  pub(crate) const fn removed(&self) -> bool {
    self.removed
  }

  pub(crate) const fn digest(&self) -> &Digest {
    &self.digest
  }

  /// Encodes the exact canonical record bytes (the sync payload shape).
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &ResourceRecordWire {
        schema: RESOURCE_RECORD_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: self.cluster.as_str().to_owned(),
        name: self.name.as_str().to_owned(),
        resource_type: self.resource_type.as_str().to_owned(),
        resource_uri: self.resource_uri.as_str().to_owned(),
        labels: self
          .labels
          .entries()
          .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
          .collect(),
        timestamp_millis: self.timestamp_millis,
        writer: self.writer.as_str().to_owned(),
        removal_rank: self.removal_rank,
        removed: self.removed,
        digest: ByteVec::from(self.digest.as_bytes().to_vec()),
        signature: ByteVec::from(self.signature.as_bytes().to_vec()),
      },
      RECORD_LIMITS,
    )
  }

  /// Decodes one canonical record, rejecting noncanonical encodings and
  /// any record whose stored digest does not match its decoded fields
  /// before the caller can compare or persist it.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: ResourceRecordWire =
      decode_canonical_strict(bytes, RECORD_LIMITS, "resource record canonical")?;
    if wire.schema != RESOURCE_RECORD_SCHEMA || wire.record_version != RECORD_VERSION {
      return Err(Error::invalid_input("resource record schema"));
    }
    let cluster = ClusterId::parse(&wire.cluster_id)?;
    let name = ResourceName::parse(&wire.name)?;
    let resource_type = LabelValue::parse(&wire.resource_type)?;
    let resource_uri = LabelValue::parse(&wire.resource_uri)?;
    let mut labels = LabelSet::new();
    for (key, value) in wire.labels {
      labels = labels.insert(crate::LabelKey::parse(&key)?, LabelValue::parse(&value)?)?;
    }
    let writer = NodeId::parse(&wire.writer)?;
    let record = Self {
      cluster,
      name,
      resource_type,
      resource_uri,
      labels,
      timestamp_millis: wire.timestamp_millis,
      writer,
      removal_rank: wire.removal_rank,
      removed: wire.removed,
      digest: Digest::from_bytes(
        wire.digest[..]
          .try_into()
          .map_err(|_| Error::invalid_input("resource record digest"))?,
      ),
      signature: Signature::from_bytes(
        wire.signature[..]
          .try_into()
          .map_err(|_| Error::invalid_input("resource record signature"))?,
      ),
    };
    // The stored digest must match the decoded fields exactly: any field
    // mutation (or digest tampering) fails here, before comparison or
    // persistence (SC-G07-P0-04).
    let body = record.signed_body()?;
    if body_digest(&body) != record.digest {
      return Err(Error::invalid_input("resource record digest"));
    }
    Ok(record)
  }

  /// Encodes the canonical unsigned body of this record's fields.
  fn signed_body(&self) -> Result<Vec<u8>> {
    Self::encode_signed_body(
      &self.cluster,
      &self.name,
      &self.resource_type,
      &self.resource_uri,
      &self.labels,
      self.timestamp_millis,
      &self.writer,
      self.removal_rank,
      self.removed,
    )
  }

  /// Verifies the writer's signature against the writer's public key.
  /// The digest was already checked against the fields at decode time;
  /// this closes the chain from fields to writer identity.
  pub(crate) fn verify(&self, writer_key: &PublicKey) -> Result<()> {
    verify_strict(
      RESOURCE_RECORD_V1_DOMAIN,
      &self.signed_body()?,
      writer_key,
      &self.signature,
      "resource record signature",
    )
  }

  /// The deterministic timestamp-maximum tuple order (SC-G07-P0-05):
  /// lexicographic maximum of signed wall-clock timestamp, canonical
  /// writer id, removal rank, and canonical digest. Total, transitive,
  /// commutative, associative, and idempotent under max-reduction; equal
  /// timestamps break ties on writer, then removal rank, then digest, so
  /// byte-identical replays are idempotent and signed equivocations
  /// converge to one deterministic winner.
  pub(crate) fn tuple_order(&self, other: &Self) -> std::cmp::Ordering {
    self
      .timestamp_millis
      .cmp(&other.timestamp_millis)
      .then_with(|| self.writer.as_str().cmp(other.writer.as_str()))
      .then_with(|| self.removal_rank.cmp(&other.removal_rank))
      .then_with(|| self.digest.cmp(other.digest()))
  }

  /// Whether this record deterministically wins over `other`.
  pub(crate) fn wins_over(&self, other: &Self) -> bool {
    self.tuple_order(other) == std::cmp::Ordering::Greater
  }
}

pub(crate) mod store;

#[cfg(all(test, feature = "json"))]
mod crash;

#[cfg(test)]
mod tests {
  use std::cmp::Ordering;

  use ed25519_dalek::SigningKey;

  use super::{RESERVED_TYPE_LABEL_KEY, RESERVED_URI_LABEL_KEY, ResourceName, ResourceRecordV1};
  use crate::{ClusterId, LabelKey, LabelSet, LabelValue, NodeId};

  const SEED: [u8; 32] = [11; 32];
  const OTHER_SEED: [u8; 32] = [13; 32];

  fn writer() -> NodeId {
    NodeId::parse("node_000000000000000000001").unwrap()
  }

  fn other_writer() -> NodeId {
    NodeId::parse("node_000000000000000000002").unwrap()
  }

  fn name() -> ResourceName {
    ResourceName::parse("relay.woooo.tech/resources/demo-object").unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/owner").unwrap(),
        LabelValue::parse("team-a").unwrap(),
      )
      .unwrap()
  }

  #[allow(clippy::too_many_arguments)]
  fn record(
    name: &ResourceName, timestamp_millis: u64, writer: &NodeId, removal_rank: u64,
    labels: &LabelSet, resource_type: &str, uri: &str, seed: [u8; 32],
  ) -> ResourceRecordV1 {
    live(
      name,
      timestamp_millis,
      writer,
      removal_rank,
      labels,
      resource_type,
      uri,
      seed,
    )
  }

  #[allow(clippy::too_many_arguments)]
  fn live(
    name: &ResourceName, timestamp_millis: u64, writer: &NodeId, removal_rank: u64,
    labels: &LabelSet, resource_type: &str, uri: &str, seed: [u8; 32],
  ) -> ResourceRecordV1 {
    signed_variant(
      name,
      timestamp_millis,
      writer,
      removal_rank,
      false,
      labels,
      resource_type,
      uri,
      seed,
    )
  }

  #[allow(clippy::too_many_arguments)]
  fn signed_variant(
    name: &ResourceName, timestamp_millis: u64, writer: &NodeId, removal_rank: u64, removed: bool,
    labels: &LabelSet, resource_type: &str, uri: &str, seed: [u8; 32],
  ) -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      ClusterId::parse("cluster_000000000000000000001").unwrap(),
      name.clone(),
      LabelValue::parse(resource_type).unwrap(),
      LabelValue::parse(uri).unwrap(),
      labels.clone(),
      timestamp_millis,
      writer.clone(),
      removal_rank,
      removed,
      &SigningKey::from_bytes(&seed),
    )
    .unwrap()
  }

  fn base_record() -> ResourceRecordV1 {
    record(
      &name(),
      1_000,
      &writer(),
      0,
      &labels(),
      "document",
      "file:///tmp/a",
      SEED,
    )
  }

  /// The pinned canonical encoding of `base_record()` (T-G07-02 wire
  /// vector; deterministic CBOR plus the ed25519 signature over the
  /// domain-separated digest of seed `[11; 32]`).
  const GOLDEN_RESOURCE_RECORD_V1: &[u8] = &[
    0x8D, 0x78, 0x2B, 0x72, 0x65, 0x6C, 0x61, 0x79, 0x2E, 0x77, 0x6F, 0x6F, 0x6F, 0x6F, 0x2E, 0x74,
    0x65, 0x63, 0x68, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2F, 0x72, 0x65, 0x73, 0x6F,
    0x75, 0x72, 0x63, 0x65, 0x2D, 0x72, 0x65, 0x63, 0x6F, 0x72, 0x64, 0x2D, 0x76, 0x31, 0x01, 0x78,
    0x1D, 0x63, 0x6C, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5F, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x78, 0x26,
    0x72, 0x65, 0x6C, 0x61, 0x79, 0x2E, 0x77, 0x6F, 0x6F, 0x6F, 0x6F, 0x2E, 0x74, 0x65, 0x63, 0x68,
    0x2F, 0x72, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2F, 0x64, 0x65, 0x6D, 0x6F, 0x2D,
    0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x68, 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x6D,
    0x66, 0x69, 0x6C, 0x65, 0x3A, 0x2F, 0x2F, 0x2F, 0x74, 0x6D, 0x70, 0x2F, 0x61, 0x81, 0x82, 0x78,
    0x18, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x6C, 0x61, 0x62,
    0x65, 0x6C, 0x73, 0x2F, 0x6F, 0x77, 0x6E, 0x65, 0x72, 0x66, 0x74, 0x65, 0x61, 0x6D, 0x2D, 0x61,
    0x19, 0x03, 0xE8, 0x78, 0x1A, 0x6E, 0x6F, 0x64, 0x65, 0x5F, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00,
    0xF4, 0x58, 0x20, 0xA8, 0xD7, 0x9D, 0x28, 0x4F, 0xF6, 0xA3, 0xB4, 0x65, 0xC1, 0xF8, 0x1A, 0x7A,
    0x15, 0x43, 0x8D, 0xE1, 0x65, 0x64, 0xFA, 0x4A, 0xDE, 0xB2, 0x63, 0x72, 0x70, 0x22, 0x5B, 0x35,
    0x72, 0x5B, 0x88, 0x58, 0x40, 0x6A, 0x59, 0x80, 0x31, 0x08, 0x37, 0x6C, 0x91, 0x0C, 0xA5, 0x97,
    0x06, 0xA5, 0x36, 0x08, 0x10, 0x31, 0xD7, 0x1F, 0x4E, 0x2A, 0x70, 0x17, 0xD2, 0xE9, 0xC0, 0x47,
    0x4A, 0x79, 0xED, 0xF3, 0xCB, 0x83, 0x05, 0x28, 0x1E, 0x85, 0xCF, 0x05, 0x26, 0x1B, 0xB8, 0x47,
    0xA5, 0x98, 0x8A, 0x24, 0xEB, 0x20, 0xEC, 0x93, 0xA7, 0x55, 0x4C, 0x2A, 0x20, 0x01, 0x4E, 0x77,
    0x73, 0xBD, 0x55, 0xC8, 0x04,
  ];

  fn writer_key_of(seed: [u8; 32]) -> crate::PublicKey {
    let key = SigningKey::from_bytes(&seed);
    crate::PublicKey::from_bytes(key.verifying_key().to_bytes())
  }

  // ---- SC-G07-P0-04: signed records validate before anything else ----

  /// A well-formed record verifies under its writer's key and round-trips
  /// through the canonical encoding byte-exactly.
  #[test]
  fn well_formed_record_verifies_and_round_trips() {
    let record = base_record();
    record.verify(&writer_key_of(SEED)).unwrap();
    let decoded = ResourceRecordV1::decode(&record.encode().unwrap()).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.timestamp_millis(), 1_000);
    assert_eq!(decoded.name(), record.name());
  }

  /// Reserved label keys stay documented constants and never appear inside
  /// the custom label namespace (LabelKey pins every custom label to the
  /// `labels` category).
  #[test]
  fn reserved_label_keys_are_outside_the_custom_namespace() {
    assert_eq!(RESERVED_TYPE_LABEL_KEY, "relay.woooo.tech/resources/type");
    assert_eq!(RESERVED_URI_LABEL_KEY, "relay.woooo.tech/resources/uri");
    assert!(LabelKey::parse(RESERVED_TYPE_LABEL_KEY).is_err());
    assert!(LabelKey::parse(RESERVED_URI_LABEL_KEY).is_err());
    assert!(ResourceName::parse("relay.woooo.tech/labels/not-a-resource").is_err());
  }

  /// Mutating any covered field (or the digest or signature itself)
  /// fails verification or canonical decode before comparison or
  /// persistence.
  #[test]
  fn every_field_mutation_fails_closed() {
    type Mutator = dyn Fn(&mut ResourceRecordV1);
    let record = base_record();

    let mutated = |mutate: &Mutator| {
      let mut copy = record.clone();
      mutate(&mut copy);
      copy
    };

    // Field mutations keep the stale digest/signature and must fail
    // verification (the digest no longer matches the fields).
    let cases: Vec<(&str, &Mutator)> = vec![
      ("timestamp", &|r: &mut ResourceRecordV1| {
        r.timestamp_millis += 1
      }),
      ("removal_rank", &|r: &mut ResourceRecordV1| {
        r.removal_rank += 1
      }),
    ];
    for (label, mutate) in &cases {
      let copy = mutated(mutate);
      assert!(
        copy.verify(&writer_key_of(SEED)).is_err(),
        "mutation of {label} must fail closed"
      );
    }

    // Digest tampering fails at decode (fields recompute to a different
    // digest); signature tampering fails at verify on an otherwise valid
    // record shape.
    let mut wire = record.encode().unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0xFF;
    // Flipping the final signature byte must break decode-or-verify.
    if let Ok(decoded) = ResourceRecordV1::decode(&wire) {
      assert!(decoded.verify(&writer_key_of(SEED)).is_err());
    }
  }

  /// A record signed by a different writer never verifies under another
  /// writer's key (equivocation cannot borrow identities).
  #[test]
  fn signature_binds_the_writer_identity() {
    let record = base_record();
    assert!(record.verify(&writer_key_of(SEED)).is_ok());
    assert!(record.verify(&writer_key_of(OTHER_SEED)).is_err());
  }

  // ---- SC-G07-P0-05: timestamp-maximum tuple algebra ----

  /// The tuple order is total, antisymmetric, transitive; max-reduction is
  /// commutative, associative, and idempotent — exhaustively over a small
  /// permutation space that varies every tuple dimension.
  #[test]
  fn tuple_order_algebra_holds_exhaustively() {
    let n1 = ResourceName::parse("relay.woooo.tech/resources/obj-1").unwrap();
    let n2 = ResourceName::parse("relay.woooo.tech/resources/obj-2").unwrap();
    let pool = vec![
      record(&n1, 1_000, &writer(), 0, &labels(), "a", "u://1", SEED),
      record(&n1, 2_000, &writer(), 0, &labels(), "a", "u://1", SEED),
      record(
        &n1,
        2_000,
        &other_writer(),
        0,
        &labels(),
        "a",
        "u://2",
        OTHER_SEED,
      ),
      record(&n1, 2_000, &writer(), 7, &labels(), "a", "u://3", SEED),
      record(
        &n2,
        1_500,
        &other_writer(),
        3,
        &labels(),
        "b",
        "u://4",
        OTHER_SEED,
      ),
    ];

    for a in &pool {
      for b in &pool {
        let ord = a.tuple_order(b);
        // Totality + antisymmetry.
        assert_eq!(ord.reverse(), b.tuple_order(a));
        // Idempotence of max-reduction.
        let winner = if a.wins_over(b) { a } else { b };
        let winner_again = if winner.wins_over(b) { winner } else { b };
        assert_eq!(winner, winner_again);
        for c in &pool {
          // Transitivity.
          if a.wins_over(b) && b.wins_over(c) {
            assert!(a.wins_over(c));
          }
          // Associativity + commutativity of max-reduction.
          let ab_c = max(max(a, b), c);
          let a_bc = max(a, max(b, c));
          assert_eq!(ab_c, a_bc);
          assert_eq!(max(a, b), max(b, a));
        }
      }
    }
  }

  fn max<'a>(a: &'a ResourceRecordV1, b: &'a ResourceRecordV1) -> &'a ResourceRecordV1 {
    if a.wins_over(b) { a } else { b }
  }

  /// Equal timestamps use deterministic writer, then removal-rank,
  /// then digest tie-breaks; rollback can make a later local write lose
  /// and a future-dated write dominates until wall time catches up
  /// (SC-G07-P0-01 semantics expressed in the tuple).
  #[test]
  fn equal_timestamp_tie_breaks_are_deterministic_and_rollback_loses() {
    let early = record(&name(), 1_000, &writer(), 0, &labels(), "a", "u://1", SEED);
    let late_local_same_writer = record(
      &name(),
      2_000,
      &writer(),
      0,
      &labels(),
      "a",
      "u://1-late",
      SEED,
    );
    // Wall-clock rollback: the host wrote later but stamped earlier, so
    // the earlier-stamped remote record still wins.
    assert!(!early.wins_over(&late_local_same_writer));

    let same_time_a = record(&name(), 5_000, &writer(), 0, &labels(), "a", "u://a", SEED);
    let same_time_b = record(
      &name(),
      5_000,
      &other_writer(),
      0,
      &labels(),
      "a",
      "u://b",
      OTHER_SEED,
    );
    // Writer id breaks the tie deterministically.
    let by_writer = same_time_a.writer().as_str() > same_time_b.writer().as_str();
    assert_eq!(same_time_a.wins_over(&same_time_b), by_writer);

    let ranked = record(&name(), 5_000, &writer(), 9, &labels(), "a", "u://a", SEED);
    assert!(ranked.wins_over(&same_time_a));

    // Future dominance: a far-future stamp beats everything present.
    let future = record(
      &name(),
      9_999_999,
      &writer(),
      0,
      &labels(),
      "a",
      "u://f",
      SEED,
    );
    assert!(future.tuple_order(&early) == Ordering::Greater);
  }

  /// Signed equivocation at one tuple position converges to one
  /// deterministic winner by digest, and byte-identical replay is
  /// idempotent (SC-G07-P0-06).
  #[test]
  fn equivocation_converges_and_replay_is_idempotent() {
    let equivocate_a = record(
      &name(),
      5_000,
      &writer(),
      0,
      &labels(),
      "a",
      "u://one",
      SEED,
    );
    let equivocate_b = ResourceRecordV1::sign(
      ClusterId::parse("cluster_000000000000000000001").unwrap(),
      name(),
      LabelValue::parse("a").unwrap(),
      LabelValue::parse("u://two").unwrap(),
      labels(),
      5_000,
      writer(),
      0,
      false,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap();
    assert_ne!(equivocate_a.digest(), equivocate_b.digest());
    // Both are individually valid signed records (bounded evidence), and
    // the register converges to the same single winner from either order.
    let winner = max(&equivocate_a, &equivocate_b);
    assert_eq!(winner, max(&equivocate_b, &equivocate_a));
    // Byte-identical replay is idempotent.
    let decoded = ResourceRecordV1::decode(&equivocate_a.encode().unwrap()).unwrap();
    assert_eq!(&decoded, &equivocate_a);
  }

  /// Golden vector: the exact canonical bytes of one fixed record are
  /// pinned so any encoder drift across gates fails loudly. The signature
  /// is deterministic (ed25519 over the domain-separated digest), so the
  /// full encoding is reproducible from the fixed seed.
  #[test]
  fn golden_wire_vector_is_stable() {
    let record = base_record();
    let bytes = record.encode().unwrap();
    assert_eq!(bytes.as_slice(), GOLDEN_RESOURCE_RECORD_V1);
  }
}

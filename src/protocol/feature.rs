//! Domain-qualified feature label definitions and the closed validation
//! registry from ADR-0002.
//!
//! A [`FeatureDefinition`] is the immutable contract behind one feature
//! label. Its definition digest is SHA-256 over the deterministic-CBOR
//! encoding of the full canonical record: tag, contract fingerprint, sorted
//! dependencies, sorted conflicts, sorted protocol handlers, owned limit
//! definitions sorted by tag, and the test-contract owner.
//!
//! Built-in contract fingerprints are fixed 32-byte values derived as
//! SHA-256 of one exact frozen seed string per feature:
//!
//! ```text
//! seed = "relay.woooo.tech/crypto/feature-fingerprint-v1/" ++ <full feature tag>
//! ```
//!
//! The five frozen seeds are:
//!
//! - `relay.woooo.tech/crypto/feature-fingerprint-v1/relay.woooo.tech/features/
//!   auth-ed25519-session`
//! - `relay.woooo.tech/crypto/feature-fingerprint-v1/relay.woooo.tech/features/
//!   session-core`
//! - `relay.woooo.tech/crypto/feature-fingerprint-v1/relay.woooo.tech/features/
//!   data-messages`
//! - `relay.woooo.tech/crypto/feature-fingerprint-v1/relay.woooo.tech/features/
//!   direct-request`
//! - `relay.woooo.tech/crypto/feature-fingerprint-v1/relay.woooo.tech/features/
//!   routed-delivery`
//!
//! `handshake_feature_registry_golden_fixture_is_frozen` pins the exact
//! fingerprints and definition digests those seeds produce.

use std::collections::BTreeMap;

use minicbor::Encode;
use sha2::{Digest as ShaDigest, Sha256};

use super::{CborLimits, FeatureTag, ProtocolTag, QualifiedTag, encode_canonical};
use crate::{Digest, Error, Result};

const BUILTIN_DOMAIN: &str = "relay.woooo.tech";
const BUILTIN_TEST_OWNER: &str = "VERIFY-G03-01";
const FINGERPRINT_SEED_PREFIX: &str = "relay.woooo.tech/crypto/feature-fingerprint-v1/";

pub(crate) const AUTH_ED25519_SESSION: &str = "relay.woooo.tech/features/auth-ed25519-session";
pub(crate) const SESSION_CORE: &str = "relay.woooo.tech/features/session-core";
pub(crate) const DATA_MESSAGES: &str = "relay.woooo.tech/features/data-messages";
pub(crate) const DIRECT_REQUEST: &str = "relay.woooo.tech/features/direct-request";
pub(crate) const ROUTED_DELIVERY: &str = "relay.woooo.tech/features/routed-delivery";
pub(crate) const DATA_BODY_BYTES_LIMIT: &str = "relay.woooo.tech/limits/data-body-bytes";

/// The five built-in feature labels in declaration order. Fixtures and
/// tests reuse this single list so adding a built-in feature cannot
/// silently desynchronize the offer and selection fixtures.
pub(crate) const BUILTIN_FEATURE_LABELS: [&str; 5] = [
  AUTH_ED25519_SESSION,
  SESSION_CORE,
  DATA_MESSAGES,
  DIRECT_REQUEST,
  ROUTED_DELIVERY,
];
const IN_FLIGHT_REQUESTS_LIMIT: &str = "relay.woooo.tech/limits/in-flight-requests";
const DIRECT_REQUEST_PROTOCOL: &str = "relay.woooo.tech/protocols/direct-request";

const DATA_BODY_FLOOR: u64 = 64 * 1_024;
const DATA_BODY_DEFAULT: u64 = 1_024 * 1_024;
const DATA_BODY_CEILING: u64 = 8 * 1_024 * 1_024;
const IN_FLIGHT_FLOOR: u64 = 1;
const IN_FLIGHT_DEFAULT: u64 = 256;
const IN_FLIGHT_CEILING: u64 = 1_024;

const DEFINITION_LIMITS: CborLimits = CborLimits::new(16, 1_024, 65_536);

/// The canonical immutable contract behind one negotiated feature label.
#[derive(Debug)]
pub struct FeatureDefinition {
  tag: FeatureTag,
  fingerprint: Digest,
  dependencies: Vec<FeatureTag>,
  conflicts: Vec<FeatureTag>,
  protocols: Vec<ProtocolTag>,
  limits: Vec<LimitDefinition>,
  test_owner: String,
}

impl FeatureDefinition {
  /// Starts a definition for an extension feature label with its immutable
  /// 32-byte contract fingerprint.
  ///
  /// The built-in `relay.woooo.tech` domain is reserved for the frozen
  /// built-in definitions and is rejected here.
  pub fn new(tag: FeatureTag, fingerprint: Digest) -> Result<Self> {
    if tag_domain(tag.as_str()) == BUILTIN_DOMAIN {
      return Err(Error::invalid_input(
        "feature definition reserved namespace",
      ));
    }
    Ok(Self::unchecked(tag, fingerprint, String::new()))
  }

  /// Adds an immutable required feature label.
  pub fn dependency(mut self, tag: FeatureTag) -> Result<Self> {
    if tag == self.tag {
      return Err(Error::invalid_input("feature dependency self"));
    }
    if self.dependencies.contains(&tag) {
      return Err(Error::invalid_input("feature dependency duplicate"));
    }
    self.dependencies.push(tag);
    Ok(self)
  }

  /// Adds a symmetric, irreflexive conflicting feature label.
  pub fn conflict(mut self, tag: FeatureTag) -> Result<Self> {
    if tag == self.tag {
      return Err(Error::invalid_input("feature conflict self"));
    }
    if self.conflicts.contains(&tag) {
      return Err(Error::invalid_input("feature conflict duplicate"));
    }
    self.conflicts.push(tag);
    Ok(self)
  }

  /// Claims ownership of a domain-qualified protocol handler tag.
  pub fn protocol(mut self, tag: ProtocolTag) -> Result<Self> {
    if self.protocols.contains(&tag) {
      return Err(Error::invalid_input("feature protocol duplicate"));
    }
    self.protocols.push(tag);
    Ok(self)
  }

  fn unchecked(tag: FeatureTag, fingerprint: Digest, test_owner: String) -> Self {
    Self {
      tag,
      fingerprint,
      dependencies: Vec::new(),
      conflicts: Vec::new(),
      protocols: Vec::new(),
      limits: Vec::new(),
      test_owner,
    }
  }

  pub(crate) fn limit(mut self, limit: LimitDefinition) -> Result<Self> {
    if limit.owner() != self.tag() {
      return Err(Error::invalid_input("feature limit owner"));
    }
    if self
      .limits
      .iter()
      .any(|existing| existing.tag() == limit.tag())
    {
      return Err(Error::invalid_input("feature limit duplicate"));
    }
    self.limits.push(limit);
    Ok(self)
  }

  pub(crate) const fn tag(&self) -> &FeatureTag {
    &self.tag
  }

  /// The immutable contract fingerprint (definition content input; G3-04
  /// exposes it through negotiated evidence).
  #[allow(dead_code)]
  pub(crate) const fn fingerprint(&self) -> &Digest {
    &self.fingerprint
  }

  pub(crate) fn dependencies(&self) -> &[FeatureTag] {
    &self.dependencies
  }

  pub(crate) fn conflicts(&self) -> &[FeatureTag] {
    &self.conflicts
  }

  pub(crate) fn protocols(&self) -> &[ProtocolTag] {
    &self.protocols
  }

  pub(crate) fn limits(&self) -> &[LimitDefinition] {
    &self.limits
  }

  /// Computes SHA-256 over the deterministic-CBOR canonical definition.
  pub(crate) fn definition_digest(&self) -> Result<Digest> {
    let bytes = encode_canonical(&self.wire(), DEFINITION_LIMITS)?;
    Ok(Digest::from_bytes(Sha256::digest(bytes).into()))
  }

  fn wire(&self) -> DefinitionWire {
    let mut dependencies = string_tags(&self.dependencies);
    dependencies.sort();
    let mut conflicts = string_tags(&self.conflicts);
    conflicts.sort();
    let mut protocols = string_tags(&self.protocols);
    protocols.sort();
    let mut limits: Vec<LimitDefinitionWire> =
      self.limits.iter().map(LimitDefinition::wire).collect();
    limits.sort_by(|first, second| first.tag.cmp(&second.tag));
    DefinitionWire {
      tag: self.tag.as_str().to_owned(),
      fingerprint: self.fingerprint.as_bytes().to_vec(),
      dependencies,
      conflicts,
      protocols,
      limits,
      test_owner: self.test_owner.clone(),
    }
  }
}

/// The unsigned integer width fixed by a numeric limit definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LimitWidth {
  U16,
  U32,
  /// No built-in limit uses a 64-bit width yet; reserved by the limit
  /// definition schema for extension limits.
  #[allow(dead_code)]
  U64,
}

impl LimitWidth {
  const fn wire(self) -> u64 {
    match self {
      Self::U16 => 16,
      Self::U32 => 32,
      Self::U64 => 64,
    }
  }

  const fn maximum(self) -> u64 {
    match self {
      Self::U16 => u16::MAX as u64,
      Self::U32 => u32::MAX as u64,
      Self::U64 => u64::MAX,
    }
  }
}

/// The unit fixed by a numeric limit definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LimitUnit {
  Bytes,
  Count,
}

impl LimitUnit {
  const fn wire(self) -> u64 {
    match self {
      Self::Bytes => 0,
      Self::Count => 1,
    }
  }
}

/// The legal range and local default fixed by a numeric limit definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LimitRange {
  floor: u64,
  ceiling: u64,
  default: u64,
}

impl LimitRange {
  pub(crate) const fn new(floor: u64, ceiling: u64, default: u64) -> Result<Self> {
    if floor > ceiling || default < floor || default > ceiling {
      return Err(Error::invalid_input("limit definition range"));
    }
    Ok(Self {
      floor,
      ceiling,
      default,
    })
  }

  const fn contains(&self, value: u64) -> bool {
    value >= self.floor && value <= self.ceiling
  }
}

/// The immutable definition of one negotiated numeric limit ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LimitDefinition {
  tag: QualifiedTag,
  width: LimitWidth,
  unit: LimitUnit,
  range: LimitRange,
  owner: FeatureTag,
  mandatory: bool,
}

impl LimitDefinition {
  pub(crate) fn new(
    tag: QualifiedTag, width: LimitWidth, unit: LimitUnit, range: LimitRange, owner: FeatureTag,
    mandatory: bool,
  ) -> Result<Self> {
    if tag.category() != "limits" {
      return Err(Error::invalid_input("limit definition category"));
    }
    if range.ceiling > width.maximum() {
      return Err(Error::invalid_input("limit definition width"));
    }
    Ok(Self {
      tag,
      width,
      unit,
      range,
      owner,
      mandatory,
    })
  }

  pub(crate) const fn tag(&self) -> &QualifiedTag {
    &self.tag
  }

  pub(crate) const fn default(&self) -> u64 {
    self.range.default
  }

  pub(crate) const fn owner(&self) -> &FeatureTag {
    &self.owner
  }

  pub(crate) const fn mandatory(&self) -> bool {
    self.mandatory
  }

  pub(crate) const fn contains(&self, value: u64) -> bool {
    self.range.contains(value)
  }

  fn wire(&self) -> LimitDefinitionWire {
    LimitDefinitionWire {
      tag: self.tag.as_str().to_owned(),
      width: self.width.wire(),
      unit: self.unit.wire(),
      floor: self.range.floor,
      ceiling: self.range.ceiling,
      default: self.range.default,
      owner: self.owner.as_str().to_owned(),
      mandatory: self.mandatory,
    }
  }
}

#[derive(Encode)]
#[cbor(array)]
struct LimitDefinitionWire {
  #[n(0)]
  tag: String,
  #[n(1)]
  width: u64,
  #[n(2)]
  unit: u64,
  #[n(3)]
  floor: u64,
  #[n(4)]
  ceiling: u64,
  #[n(5)]
  default: u64,
  #[n(6)]
  owner: String,
  #[n(7)]
  mandatory: bool,
}

#[derive(Encode)]
#[cbor(array)]
struct DefinitionWire {
  #[n(0)]
  tag: String,
  #[n(1)]
  #[cbor(with = "minicbor::bytes")]
  fingerprint: Vec<u8>,
  #[n(2)]
  dependencies: Vec<String>,
  #[n(3)]
  conflicts: Vec<String>,
  #[n(4)]
  protocols: Vec<String>,
  #[n(5)]
  limits: Vec<LimitDefinitionWire>,
  #[n(6)]
  test_owner: String,
}

/// The closed, validated set of locally implemented feature definitions.
#[derive(Debug)]
pub(crate) struct FeatureRegistry {
  definitions: BTreeMap<FeatureTag, FeatureDefinition>,
}

impl FeatureRegistry {
  /// Builds a registry, rejecting duplicate labels, reserved-namespace
  /// misuse, missing dependencies, dependency cycles, asymmetric or self
  /// conflicts, and duplicate limit or protocol handler ownership.
  pub(crate) fn build(definitions: Vec<FeatureDefinition>) -> Result<Self> {
    let mut map: BTreeMap<FeatureTag, FeatureDefinition> = BTreeMap::new();
    for definition in definitions {
      if map.insert(definition.tag().clone(), definition).is_some() {
        return Err(Error::invalid_input("feature registry duplicate label"));
      }
    }
    for definition in map.values() {
      check_reserved_namespace(definition)?;
    }
    check_dependencies(&map)?;
    check_conflicts(&map)?;
    check_unique_ownership(&map)?;
    Ok(Self { definitions: map })
  }

  /// Builds the frozen built-in registry from ADR-0002.
  pub(crate) fn builtin() -> Result<Self> {
    Self::build(builtin_definitions()?)
  }

  pub(crate) fn get(&self, tag: &FeatureTag) -> Option<&FeatureDefinition> {
    self.definitions.get(tag)
  }

  /// Iterates every registered definition in canonical tag order.
  pub(crate) fn iter(&self) -> impl Iterator<Item = (&FeatureTag, &FeatureDefinition)> {
    self.definitions.iter()
  }
}

/// The built-in features every session requires: the ADR-0001 Ed25519
/// session authentication and the session core it anchors.
pub(crate) fn required_session_features() -> Result<[FeatureTag; 2]> {
  Ok([
    feature_tag(AUTH_ED25519_SESSION)?,
    feature_tag(SESSION_CORE)?,
  ])
}

fn check_reserved_namespace(definition: &FeatureDefinition) -> Result<()> {
  if tag_domain(definition.tag().as_str()) != BUILTIN_DOMAIN {
    return Ok(());
  }
  let actual = definition.definition_digest()?;
  for candidate in builtin_definitions()? {
    if candidate.tag() == definition.tag() && candidate.definition_digest()? == actual {
      return Ok(());
    }
  }
  Err(Error::invalid_input("feature registry reserved namespace"))
}

fn check_dependencies(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  #[derive(Clone, Copy, Eq, PartialEq)]
  enum Mark {
    Visiting,
    Done,
  }

  fn visit<'registry>(
    tag: &'registry FeatureTag, definitions: &'registry BTreeMap<FeatureTag, FeatureDefinition>,
    marks: &mut BTreeMap<&'registry FeatureTag, Mark>,
  ) -> Result<()> {
    match marks.get(tag) {
      Some(Mark::Done) => return Ok(()),
      Some(Mark::Visiting) => {
        return Err(Error::invalid_input("feature registry dependency cycle"));
      }
      None => {}
    }
    marks.insert(tag, Mark::Visiting);
    let definition = definitions
      .get(tag)
      .ok_or_else(|| Error::invalid_input("feature registry missing dependency"))?;
    for dependency in definition.dependencies() {
      visit(dependency, definitions, marks)?;
    }
    marks.insert(tag, Mark::Done);
    Ok(())
  }

  let mut marks = BTreeMap::new();
  for tag in definitions.keys() {
    visit(tag, definitions, &mut marks)?;
  }
  Ok(())
}

fn check_conflicts(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  for definition in definitions.values() {
    for conflict in definition.conflicts() {
      if conflict == definition.tag() {
        return Err(Error::invalid_input("feature registry self conflict"));
      }
      let Some(other) = definitions.get(conflict) else {
        return Err(Error::invalid_input("feature registry asymmetric conflict"));
      };
      if !other.conflicts().contains(definition.tag()) {
        return Err(Error::invalid_input("feature registry asymmetric conflict"));
      }
    }
  }
  Ok(())
}

fn check_unique_ownership(definitions: &BTreeMap<FeatureTag, FeatureDefinition>) -> Result<()> {
  let mut limits: BTreeMap<&QualifiedTag, ()> = BTreeMap::new();
  let mut protocols: BTreeMap<&ProtocolTag, ()> = BTreeMap::new();
  for definition in definitions.values() {
    for limit in definition.limits() {
      if limits.insert(limit.tag(), ()).is_some() {
        return Err(Error::invalid_input(
          "feature registry duplicate limit owner",
        ));
      }
    }
    for protocol in definition.protocols() {
      if protocols.insert(protocol, ()).is_some() {
        return Err(Error::invalid_input(
          "feature registry duplicate protocol owner",
        ));
      }
    }
  }
  Ok(())
}

fn builtin_definitions() -> Result<Vec<FeatureDefinition>> {
  let auth = builtin(AUTH_ED25519_SESSION)?;
  let session = builtin(SESSION_CORE)?.dependency(feature_tag(AUTH_ED25519_SESSION)?)?;
  let data = builtin(DATA_MESSAGES)?
    .dependency(feature_tag(SESSION_CORE)?)?
    .limit(LimitDefinition::new(
      QualifiedTag::parse(DATA_BODY_BYTES_LIMIT)?,
      LimitWidth::U32,
      LimitUnit::Bytes,
      LimitRange::new(DATA_BODY_FLOOR, DATA_BODY_CEILING, DATA_BODY_DEFAULT)?,
      feature_tag(DATA_MESSAGES)?,
      true,
    )?)?;
  let direct = builtin(DIRECT_REQUEST)?
    .dependency(feature_tag(DATA_MESSAGES)?)?
    .limit(LimitDefinition::new(
      QualifiedTag::parse(IN_FLIGHT_REQUESTS_LIMIT)?,
      LimitWidth::U16,
      LimitUnit::Count,
      LimitRange::new(IN_FLIGHT_FLOOR, IN_FLIGHT_CEILING, IN_FLIGHT_DEFAULT)?,
      feature_tag(DIRECT_REQUEST)?,
      true,
    )?)?
    .protocol(ProtocolTag::parse(DIRECT_REQUEST_PROTOCOL)?)?;
  let routed = builtin(ROUTED_DELIVERY)?.dependency(feature_tag(DATA_MESSAGES)?)?;
  Ok(vec![auth, session, data, direct, routed])
}

fn builtin(tag: &str) -> Result<FeatureDefinition> {
  let tag = FeatureTag::parse(tag)?;
  let fingerprint = builtin_fingerprint(&tag);
  Ok(FeatureDefinition::unchecked(
    tag,
    fingerprint,
    BUILTIN_TEST_OWNER.to_owned(),
  ))
}

fn builtin_fingerprint(tag: &FeatureTag) -> Digest {
  let mut seed = String::with_capacity(FINGERPRINT_SEED_PREFIX.len() + tag.as_str().len());
  seed.push_str(FINGERPRINT_SEED_PREFIX);
  seed.push_str(tag.as_str());
  Digest::from_bytes(Sha256::digest(seed.as_bytes()).into())
}

fn feature_tag(value: &str) -> Result<FeatureTag> {
  FeatureTag::parse(value)
}

fn tag_domain(tag: &str) -> &str {
  tag.split('/').next().unwrap_or(tag)
}

trait TagText {
  fn text(&self) -> &str;
}

impl TagText for FeatureTag {
  fn text(&self) -> &str {
    self.as_str()
  }
}

impl TagText for ProtocolTag {
  fn text(&self) -> &str {
    self.as_str()
  }
}

fn string_tags<T: TagText>(tags: &[T]) -> Vec<String> {
  tags.iter().map(|tag| tag.text().to_owned()).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::hex::encode as hex;

  fn extension_tag(name: &str) -> FeatureTag {
    FeatureTag::parse(&format!("testing.example/features/{name}")).unwrap()
  }

  fn extension_feature(name: &str, fingerprint_byte: u8) -> FeatureDefinition {
    FeatureDefinition::new(
      extension_tag(name),
      Digest::from_bytes([fingerprint_byte; 32]),
    )
    .unwrap()
  }

  fn extension_limit(name: &str, owner: &FeatureTag) -> LimitDefinition {
    LimitDefinition::new(
      QualifiedTag::parse(&format!("testing.example/limits/{name}")).unwrap(),
      LimitWidth::U32,
      LimitUnit::Count,
      LimitRange::new(1, 16, 4).unwrap(),
      owner.clone(),
      true,
    )
    .unwrap()
  }

  fn builtin_definition(name: &str) -> FeatureDefinition {
    builtin_definitions()
      .unwrap()
      .into_iter()
      .find(|definition| definition.tag().as_str() == name)
      .unwrap()
  }

  #[test]
  fn handshake_feature_registry_golden_fixture_is_frozen() {
    let registry = FeatureRegistry::builtin().unwrap();
    let cases = [
      (
        AUTH_ED25519_SESSION,
        "7dbfa709e756d554e6d4ad91eb3131fc461dbba784ad3882b1c21efcdba02c05",
        "dcf0f5c2311f4d3fb01919c600ddc46c5abe3c2a7c2f77bb835d46611538246a",
      ),
      (
        SESSION_CORE,
        "74866469a726a75c18a4d5c7b40554d4013fe6723655215a0e6950effab3d56b",
        "b1b39a64e28a6d98a80804d0ace98e329c763f329ab491f723c345e59ff07585",
      ),
      (
        DATA_MESSAGES,
        "a5dbb6f8bd50975d07882da5cfa9f0483719e5ca68153f876a2719935fef1e9a",
        "1a5ab4973d0b0ba3ee8a8e96fa581e37f50fef152a771db2f387b1ba4bb61215",
      ),
      (
        DIRECT_REQUEST,
        "140bb8e0863402c38e4543ac1c23f5256e10a68d148717db94ad2ea2866e3fb0",
        "ff93e869ead739645e025052f910eabb3350034cbbe109e3fc39d7dd5bac73b8",
      ),
      (
        ROUTED_DELIVERY,
        "44af681cc82e9a4a8ff0f58bc242218e4bb64af00553385e4222b52e23770210",
        "9cd2873e2f70befc684a8f6a137838b4e3136a7e5b863d9db7c16c2fe72163ef",
      ),
    ];
    for (name, fingerprint, digest) in cases {
      let definition = registry.get(&FeatureTag::parse(name).unwrap()).unwrap();
      assert_eq!(
        hex(definition.fingerprint().as_bytes()),
        fingerprint,
        "{name}"
      );
      assert_eq!(
        hex(definition.definition_digest().unwrap().as_bytes()),
        digest,
        "{name}"
      );
    }
  }

  #[test]
  fn handshake_feature_registry_rejects_invalid_graphs() {
    let duplicate = FeatureRegistry::build(vec![
      extension_feature("alpha", 1),
      extension_feature("alpha", 2),
    ])
    .unwrap_err();
    assert_eq!(duplicate.context(), "feature registry duplicate label");

    let missing = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .dependency(extension_tag("beta"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(missing.context(), "feature registry missing dependency");

    let cycle = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .dependency(extension_tag("beta"))
        .unwrap(),
      extension_feature("beta", 2)
        .dependency(extension_tag("alpha"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(cycle.context(), "feature registry dependency cycle");

    let self_dependency = extension_feature("alpha", 1).dependency(extension_tag("alpha"));
    assert_eq!(
      self_dependency.unwrap_err().context(),
      "feature dependency self"
    );

    let asymmetric = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .conflict(extension_tag("beta"))
        .unwrap(),
      extension_feature("beta", 2),
    ])
    .unwrap_err();
    assert_eq!(asymmetric.context(), "feature registry asymmetric conflict");

    let unknown_conflict = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .conflict(extension_tag("gamma"))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(
      unknown_conflict.context(),
      "feature registry asymmetric conflict"
    );

    let self_conflict = extension_feature("alpha", 1).conflict(extension_tag("alpha"));
    assert_eq!(
      self_conflict.unwrap_err().context(),
      "feature conflict self"
    );

    let duplicate_limit = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .limit(extension_limit("shared", &extension_tag("alpha")))
        .unwrap(),
      extension_feature("beta", 2)
        .limit(extension_limit("shared", &extension_tag("beta")))
        .unwrap(),
    ])
    .unwrap_err();
    assert_eq!(
      duplicate_limit.context(),
      "feature registry duplicate limit owner"
    );

    let protocol = ProtocolTag::parse("testing.example/protocols/shared").unwrap();
    let duplicate_protocol = FeatureRegistry::build(vec![
      extension_feature("alpha", 1)
        .protocol(protocol.clone())
        .unwrap(),
      extension_feature("beta", 2).protocol(protocol).unwrap(),
    ])
    .unwrap_err();
    assert_eq!(
      duplicate_protocol.context(),
      "feature registry duplicate protocol owner"
    );

    let reserved = FeatureDefinition::new(
      FeatureTag::parse(AUTH_ED25519_SESSION).unwrap(),
      Digest::from_bytes([7; 32]),
    );
    assert_eq!(
      reserved.unwrap_err().context(),
      "feature definition reserved namespace"
    );

    let crypto = QualifiedTag::parse("relay.woooo.tech/crypto/session-v1");
    assert!(crypto.is_err());

    let valid = FeatureRegistry::build(vec![
      extension_feature("alpha", 1),
      extension_feature("beta", 2)
        .dependency(extension_tag("alpha"))
        .unwrap()
        .conflict(extension_tag("gamma"))
        .unwrap(),
      extension_feature("gamma", 3)
        .conflict(extension_tag("beta"))
        .unwrap(),
    ]);
    assert!(valid.is_ok());
  }

  #[test]
  fn handshake_mutated_builtin_definitions_are_detected() {
    let names = [
      AUTH_ED25519_SESSION,
      SESSION_CORE,
      DATA_MESSAGES,
      DIRECT_REQUEST,
      ROUTED_DELIVERY,
    ];
    for name in names {
      let definition = builtin_definition(name);
      let digest = definition.definition_digest().unwrap();
      assert_eq!(digest, definition.definition_digest().unwrap(), "{name}");
    }

    assert_mutation_detected(AUTH_ED25519_SESSION, |definition| {
      definition.fingerprint = Digest::from_bytes([0xFF; 32]);
    });
    assert_mutation_detected(SESSION_CORE, |definition| {
      definition
        .dependencies
        .push(feature_tag(ROUTED_DELIVERY).unwrap());
    });
    assert_mutation_detected(ROUTED_DELIVERY, |definition| {
      definition
        .conflicts
        .push(feature_tag(SESSION_CORE).unwrap());
    });
    assert_mutation_detected(DATA_MESSAGES, |definition| {
      definition.limits[0].range.floor += 1;
    });
    assert_mutation_detected(DATA_MESSAGES, |definition| {
      definition.limits[0].mandatory = false;
    });
    assert_mutation_detected(DIRECT_REQUEST, |definition| {
      definition.limits[0].width = LimitWidth::U32;
    });
    assert_mutation_detected(DIRECT_REQUEST, |definition| {
      definition
        .protocols
        .push(ProtocolTag::parse("relay.woooo.tech/protocols/routed-delivery").unwrap());
    });
    assert_mutation_detected(AUTH_ED25519_SESSION, |definition| {
      definition.test_owner = "VERIFY-OTHER".to_owned();
    });
  }

  fn assert_mutation_detected(name: &str, mutate: impl FnOnce(&mut FeatureDefinition)) {
    let mut definitions = builtin_definitions().unwrap();
    let index = definitions
      .iter()
      .position(|definition| definition.tag().as_str() == name)
      .unwrap();
    let frozen = definitions[index].definition_digest().unwrap();
    mutate(&mut definitions[index]);
    assert_ne!(
      definitions[index].definition_digest().unwrap(),
      frozen,
      "{name}"
    );
    let error = FeatureRegistry::build(definitions).unwrap_err();
    assert_eq!(
      error.context(),
      "feature registry reserved namespace",
      "{name}"
    );
  }
}

use std::sync::Arc;

use minicbor::{Decode, Encode};
use sha2::{Digest as ShaDigest, Sha256};

use super::signature::{ADMISSION_GRANT_V1_DOMAIN, CLUSTER_GENESIS_V1_DOMAIN, verify_strict};
use crate::{
  ClusterId, Digest, Error, KeyHandle, KeyOperationId, NodeId, OperationId, PublicKey,
  QualifiedTag, Result, Signature, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreRevision, StoreValue, TransactionId,
  api::Entropy,
  protocol::{CborLimits, decode_canonical, encode_canonical},
  storage::receipt::{ReceiptIdentity, ReceiptReferenceToken, recover_self_referenced_transaction},
};

const RECORD_VERSION: u64 = 1;
const ED25519_ALGORITHM: &str = "relay.woooo.tech/crypto/ed25519";
const MAX_PURPOSE_LEN: usize = 128;

const LOCAL_IDENTITY_SCHEMA: &str = "relay.woooo.tech/schemas/local-identity-v1";
const KEY_CREATION_INTENT_SCHEMA: &str = "relay.woooo.tech/schemas/key-creation-intent-v1";
const IDENTITY_BINDING_SCHEMA: &str = "relay.woooo.tech/schemas/identity-binding-v1";
const CLUSTER_GENESIS_SCHEMA: &str = "relay.woooo.tech/schemas/cluster-genesis-v1";
const LOCAL_CLUSTER_POINTER_SCHEMA: &str = "relay.woooo.tech/schemas/local-cluster-pointer-v1";
const CREDENTIAL_USE_SCHEMA: &str = "relay.woooo.tech/schemas/credential-use-v1";
const ADMISSION_GRANT_SCHEMA: &str = "relay.woooo.tech/schemas/admission-grant-v1";

const LOCAL_IDENTITY_NAMESPACE: &str = "relay.woooo.tech/metadata/local-identity-v1";
const KEY_CREATION_INTENT_NAMESPACE: &str = "relay.woooo.tech/metadata/key-creation-intent-v1";
const IDENTITY_BINDING_NAMESPACE: &str = "relay.woooo.tech/metadata/identity-binding-v1";
const CLUSTER_GENESIS_NAMESPACE: &str = "relay.woooo.tech/metadata/cluster-genesis-v1";
const LOCAL_CLUSTER_POINTER_NAMESPACE: &str = "relay.woooo.tech/metadata/local-cluster-pointer-v1";
const CREDENTIAL_USE_NAMESPACE: &str = "relay.woooo.tech/metadata/credential-use-v1";
const ADMISSION_GRANT_NAMESPACE: &str = "relay.woooo.tech/metadata/admission-grant-v1";

const SINGLETON_KEY: &[u8] = b"self";
const RECORD_LIMITS: CborLimits = CborLimits::new(1, 16, 1_024);

fn record_digest(bytes: &[u8]) -> Digest {
  Digest::from_bytes(Sha256::digest(bytes).into())
}

fn decode_wire<'bytes, T>(bytes: &'bytes [u8]) -> Result<T>
where
  T: Decode<'bytes, ()> + Encode<()>, {
  let wire: T = decode_canonical(bytes, RECORD_LIMITS)?;
  if encode_canonical(&wire, RECORD_LIMITS)? != bytes {
    return Err(Error::invalid_input("identity record canonical form"));
  }
  Ok(wire)
}

fn expect_schema(actual: &str, expected: &str) -> Result<()> {
  if actual != expected {
    return Err(Error::invalid_input("identity record schema"));
  }
  Ok(())
}

fn expect_version(actual: u64) -> Result<()> {
  if actual != RECORD_VERSION {
    return Err(Error::invalid_input("identity record version"));
  }
  Ok(())
}

fn expect_algorithm(actual: &str) -> Result<()> {
  if actual != ED25519_ALGORITHM {
    return Err(Error::invalid_input("identity record algorithm"));
  }
  Ok(())
}

fn fixed_bytes<const LENGTH: usize>(bytes: &[u8], context: &'static str) -> Result<[u8; LENGTH]> {
  <[u8; LENGTH]>::try_from(bytes).map_err(|_| Error::invalid_input(context))
}

fn metadata_namespace(tag: &str) -> Result<StoreNamespace> {
  let tag = QualifiedTag::parse(tag)?;
  if tag.category() != "metadata" {
    return Err(Error::invalid_input("identity record namespace"));
  }
  StoreNamespace::new(tag)
}

fn store_key(bytes: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(bytes))
}

pub(crate) fn local_identity_key() -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(LOCAL_IDENTITY_NAMESPACE)?,
    store_key(SINGLETON_KEY),
  ))
}

pub(crate) fn key_creation_intent_namespace() -> Result<StoreNamespace> {
  metadata_namespace(KEY_CREATION_INTENT_NAMESPACE)
}

pub(crate) fn identity_binding_namespace() -> Result<StoreNamespace> {
  metadata_namespace(IDENTITY_BINDING_NAMESPACE)
}

pub(crate) fn cluster_genesis_namespace() -> Result<StoreNamespace> {
  metadata_namespace(CLUSTER_GENESIS_NAMESPACE)
}

pub(crate) fn credential_use_namespace() -> Result<StoreNamespace> {
  metadata_namespace(CREDENTIAL_USE_NAMESPACE)
}

pub(crate) fn admission_grant_namespace() -> Result<StoreNamespace> {
  metadata_namespace(ADMISSION_GRANT_NAMESPACE)
}

pub(crate) fn key_creation_intent_key(
  operation: &KeyOperationId,
) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(KEY_CREATION_INTENT_NAMESPACE)?,
    store_key(operation.as_str().as_bytes()),
  ))
}

pub(crate) fn identity_binding_key(node: &NodeId) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(IDENTITY_BINDING_NAMESPACE)?,
    store_key(node.as_str().as_bytes()),
  ))
}

pub(crate) fn cluster_genesis_key(cluster: &ClusterId) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(CLUSTER_GENESIS_NAMESPACE)?,
    store_key(cluster.as_str().as_bytes()),
  ))
}

pub(crate) fn local_cluster_pointer_key() -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(LOCAL_CLUSTER_POINTER_NAMESPACE)?,
    store_key(SINGLETON_KEY),
  ))
}

pub(crate) fn credential_use_key(
  issuer: &NodeId, generation: &GenerationId,
) -> Result<(StoreNamespace, StoreKey)> {
  let mut key = Vec::with_capacity(issuer.as_str().len() + generation.as_bytes().len());
  key.extend_from_slice(issuer.as_str().as_bytes());
  key.extend_from_slice(generation.as_bytes());
  Ok((
    metadata_namespace(CREDENTIAL_USE_NAMESPACE)?,
    store_key(&key),
  ))
}

pub(crate) fn admission_grant_key(admission: &AdmissionId) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(ADMISSION_GRANT_NAMESPACE)?,
    store_key(admission.as_bytes()),
  ))
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct GenerationId(OperationId);

impl GenerationId {
  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    OperationId::generate(entropy).map(Self)
  }

  pub(crate) const fn from_operation(operation: OperationId) -> Self {
    Self(operation)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
    self.0.as_bytes()
  }
}

impl std::fmt::Debug for GenerationId {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("GenerationId(..)")
  }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AdmissionId(OperationId);

impl AdmissionId {
  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    OperationId::generate(entropy).map(Self)
  }

  pub(crate) const fn from_operation(operation: OperationId) -> Self {
    Self(operation)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
    self.0.as_bytes()
  }
}

impl std::fmt::Debug for AdmissionId {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("AdmissionId(..)")
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct LocalIdentityWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  node_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(4)]
  algorithm: String,
  #[n(5)]
  key_operation_id: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  key_handle: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalIdentityV1 {
  node: NodeId,
  public_key: PublicKey,
  operation: KeyOperationId,
  handle: KeyHandle,
}

impl LocalIdentityV1 {
  pub(crate) const fn new(
    node: NodeId, public_key: PublicKey, operation: KeyOperationId, handle: KeyHandle,
  ) -> Self {
    Self {
      node,
      public_key,
      operation,
      handle,
    }
  }

  pub(crate) fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) fn operation(&self) -> &KeyOperationId {
    &self.operation
  }

  pub(crate) fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &LocalIdentityWire {
        schema: LOCAL_IDENTITY_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: self.node.as_str().to_owned(),
        public_key: self.public_key.as_bytes().to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        key_operation_id: self.operation.as_str().to_owned(),
        key_handle: self.handle.expose_provider_handle().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: LocalIdentityWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, LOCAL_IDENTITY_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Ok(Self {
      node: NodeId::parse(&wire.node_id)?,
      public_key: PublicKey::from_bytes(fixed_bytes(&wire.public_key, "identity public key")?),
      operation: KeyOperationId::parse(&wire.key_operation_id)?,
      handle: KeyHandle::from_provider_bytes(Arc::from(wire.key_handle))?,
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct KeyCreationIntentWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  operation: String,
  #[n(3)]
  intended_node: String,
  #[n(4)]
  purpose: String,
  #[n(5)]
  algorithm: String,
  #[n(6)]
  transaction: String,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  base_revision: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyCreationIntentV1 {
  operation: KeyOperationId,
  intended_node: NodeId,
  purpose: String,
  transaction: TransactionId,
  base_revision: StoreRevision,
}

impl KeyCreationIntentV1 {
  pub(crate) fn new(
    operation: KeyOperationId, intended_node: NodeId, purpose: String, transaction: TransactionId,
    base_revision: StoreRevision,
  ) -> Result<Self> {
    if purpose.is_empty()
      || purpose.len() > MAX_PURPOSE_LEN
      || !purpose.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
    {
      return Err(Error::invalid_input("key creation intent purpose"));
    }
    Ok(Self {
      operation,
      intended_node,
      purpose,
      transaction,
      base_revision,
    })
  }

  pub(crate) fn operation(&self) -> &KeyOperationId {
    &self.operation
  }

  pub(crate) fn intended_node(&self) -> &NodeId {
    &self.intended_node
  }

  pub(crate) fn purpose(&self) -> &str {
    &self.purpose
  }

  pub(crate) const fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  pub(crate) const fn base_revision(&self) -> &StoreRevision {
    &self.base_revision
  }

  /// Reconstructs the exact storage receipt identity committed with this
  /// intent from the stored intent value.
  ///
  /// The original commit paired the intent `Put` with an `AddSelf` receipt
  /// reference carrying the intent record token, so recovery needs only the
  /// stored value and the transaction coordinates recorded in the intent.
  pub(crate) fn recovery_identity(&self, stored_value: &StoreValue) -> Result<ReceiptIdentity> {
    let (namespace, key) = key_creation_intent_key(&self.operation)?;
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    recover_self_referenced_transaction(
      &self.transaction,
      &self.base_revision,
      vec![StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value: stored_value.clone(),
      }],
      &[token],
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &KeyCreationIntentWire {
        schema: KEY_CREATION_INTENT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        operation: self.operation.as_str().to_owned(),
        intended_node: self.intended_node.as_str().to_owned(),
        purpose: self.purpose.clone(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        transaction: self.transaction.as_str().to_owned(),
        base_revision: self.base_revision.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: KeyCreationIntentWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, KEY_CREATION_INTENT_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Self::new(
      KeyOperationId::parse(&wire.operation)?,
      NodeId::parse(&wire.intended_node)?,
      wire.purpose,
      TransactionId::parse(&wire.transaction)?,
      StoreRevision::new(Arc::from(wire.base_revision))?,
    )
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct IdentityBindingWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  node_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(4)]
  algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityBindingV1 {
  node: NodeId,
  public_key: PublicKey,
}

impl IdentityBindingV1 {
  pub(crate) const fn new(node: NodeId, public_key: PublicKey) -> Self {
    Self { node, public_key }
  }

  pub(crate) fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: self.node.as_str().to_owned(),
        public_key: self.public_key.as_bytes().to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: IdentityBindingWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, IDENTITY_BINDING_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Ok(Self {
      node: NodeId::parse(&wire.node_id)?,
      public_key: PublicKey::from_bytes(fixed_bytes(&wire.public_key, "identity public key")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ClusterGenesisBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  creator_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  creator_key: Vec<u8>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ClusterGenesisWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  creator_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  creator_key: Vec<u8>,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterGenesisV1 {
  cluster: ClusterId,
  creator: NodeId,
  creator_key: PublicKey,
  signature: Signature,
}

impl ClusterGenesisV1 {
  pub(crate) const fn new(
    cluster: ClusterId, creator: NodeId, creator_key: PublicKey, signature: Signature,
  ) -> Self {
    Self {
      cluster,
      creator,
      creator_key,
      signature,
    }
  }

  pub(crate) fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) fn creator(&self) -> &NodeId {
    &self.creator
  }

  pub(crate) fn creator_key(&self) -> &PublicKey {
    &self.creator_key
  }

  /// Encodes the canonical body that the creator signs.
  pub(crate) fn encode_signed_body(
    cluster: &ClusterId, creator: &NodeId, creator_key: &PublicKey,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &ClusterGenesisBodyWire {
        schema: CLUSTER_GENESIS_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: cluster.as_str().to_owned(),
        creator_id: creator.as_str().to_owned(),
        creator_key: creator_key.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn signed_body(&self) -> Result<Vec<u8>> {
    Self::encode_signed_body(&self.cluster, &self.creator, &self.creator_key)
  }

  pub(crate) fn verify(&self) -> Result<()> {
    verify_strict(
      CLUSTER_GENESIS_V1_DOMAIN,
      &self.signed_body()?,
      &self.creator_key,
      &self.signature,
      "cluster genesis signature",
    )
  }

  pub(crate) fn digest(&self) -> Result<Digest> {
    Ok(record_digest(&self.encode()?))
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &ClusterGenesisWire {
        schema: CLUSTER_GENESIS_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: self.cluster.as_str().to_owned(),
        creator_id: self.creator.as_str().to_owned(),
        creator_key: self.creator_key.as_bytes().to_vec(),
        signature: self.signature.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: ClusterGenesisWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, CLUSTER_GENESIS_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      cluster: ClusterId::parse(&wire.cluster_id)?,
      creator: NodeId::parse(&wire.creator_id)?,
      creator_key: PublicKey::from_bytes(fixed_bytes(&wire.creator_key, "identity public key")?),
      signature: Signature::from_bytes(fixed_bytes(&wire.signature, "identity signature")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct LocalClusterPointerWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  genesis_digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalClusterPointerV1 {
  cluster: ClusterId,
  genesis_digest: Digest,
}

impl LocalClusterPointerV1 {
  pub(crate) const fn new(cluster: ClusterId, genesis_digest: Digest) -> Self {
    Self {
      cluster,
      genesis_digest,
    }
  }

  pub(crate) fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) fn genesis_digest(&self) -> &Digest {
    &self.genesis_digest
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &LocalClusterPointerWire {
        schema: LOCAL_CLUSTER_POINTER_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: self.cluster.as_str().to_owned(),
        genesis_digest: self.genesis_digest.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: LocalClusterPointerWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, LOCAL_CLUSTER_POINTER_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      cluster: ClusterId::parse(&wire.cluster_id)?,
      genesis_digest: Digest::from_bytes(fixed_bytes(&wire.genesis_digest, "genesis digest")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct CredentialUseWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  issuer_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  admission_id: Vec<u8>,
  #[n(6)]
  subject_id: String,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialUseV1 {
  cluster: ClusterId,
  issuer: NodeId,
  generation: GenerationId,
  admission: AdmissionId,
  subject: NodeId,
  subject_key: PublicKey,
}

impl CredentialUseV1 {
  pub(crate) const fn new(
    cluster: ClusterId, issuer: NodeId, generation: GenerationId, admission: AdmissionId,
    subject: NodeId, subject_key: PublicKey,
  ) -> Self {
    Self {
      cluster,
      issuer,
      generation,
      admission,
      subject,
      subject_key,
    }
  }

  pub(crate) fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) fn generation(&self) -> &GenerationId {
    &self.generation
  }

  pub(crate) fn admission(&self) -> &AdmissionId {
    &self.admission
  }

  pub(crate) fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) fn subject_key(&self) -> &PublicKey {
    &self.subject_key
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &CredentialUseWire {
        schema: CREDENTIAL_USE_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: self.cluster.as_str().to_owned(),
        issuer_id: self.issuer.as_str().to_owned(),
        generation_id: self.generation.as_bytes().to_vec(),
        admission_id: self.admission.as_bytes().to_vec(),
        subject_id: self.subject.as_str().to_owned(),
        subject_key: self.subject_key.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: CredentialUseWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, CREDENTIAL_USE_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      cluster: ClusterId::parse(&wire.cluster_id)?,
      issuer: NodeId::parse(&wire.issuer_id)?,
      generation: GenerationId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.generation_id,
        "credential generation id",
      )?)),
      admission: AdmissionId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.admission_id,
        "admission id",
      )?)),
      subject: NodeId::parse(&wire.subject_id)?,
      subject_key: PublicKey::from_bytes(fixed_bytes(&wire.subject_key, "identity public key")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct AdmissionGrantBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  admission_id: Vec<u8>,
  #[n(4)]
  subject_id: String,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(6)]
  issuer_id: String,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct AdmissionGrantWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  cluster_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  admission_id: Vec<u8>,
  #[n(4)]
  subject_id: String,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(6)]
  issuer_id: String,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
  #[n(8)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionGrantV1 {
  cluster: ClusterId,
  admission: AdmissionId,
  subject: NodeId,
  subject_key: PublicKey,
  issuer: NodeId,
  generation: GenerationId,
  signature: Signature,
}

impl AdmissionGrantV1 {
  pub(crate) const fn new(
    cluster: ClusterId, admission: AdmissionId, subject: NodeId, subject_key: PublicKey,
    issuer: NodeId, generation: GenerationId, signature: Signature,
  ) -> Self {
    Self {
      cluster,
      admission,
      subject,
      subject_key,
      issuer,
      generation,
      signature,
    }
  }

  pub(crate) fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) fn admission(&self) -> &AdmissionId {
    &self.admission
  }

  pub(crate) fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) fn subject_key(&self) -> &PublicKey {
    &self.subject_key
  }

  pub(crate) fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) fn generation(&self) -> &GenerationId {
    &self.generation
  }

  /// Encodes the canonical body that the issuer signs.
  pub(crate) fn encode_signed_body(
    cluster: &ClusterId, admission: &AdmissionId, subject: &NodeId, subject_key: &PublicKey,
    issuer: &NodeId, generation: &GenerationId,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &AdmissionGrantBodyWire {
        schema: ADMISSION_GRANT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: cluster.as_str().to_owned(),
        admission_id: admission.as_bytes().to_vec(),
        subject_id: subject.as_str().to_owned(),
        subject_key: subject_key.as_bytes().to_vec(),
        issuer_id: issuer.as_str().to_owned(),
        generation_id: generation.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn signed_body(&self) -> Result<Vec<u8>> {
    Self::encode_signed_body(
      &self.cluster,
      &self.admission,
      &self.subject,
      &self.subject_key,
      &self.issuer,
      &self.generation,
    )
  }

  pub(crate) fn verify(&self, issuer_key: &PublicKey) -> Result<()> {
    verify_strict(
      ADMISSION_GRANT_V1_DOMAIN,
      &self.signed_body()?,
      issuer_key,
      &self.signature,
      "admission grant signature",
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &AdmissionGrantWire {
        schema: ADMISSION_GRANT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: self.cluster.as_str().to_owned(),
        admission_id: self.admission.as_bytes().to_vec(),
        subject_id: self.subject.as_str().to_owned(),
        subject_key: self.subject_key.as_bytes().to_vec(),
        issuer_id: self.issuer.as_str().to_owned(),
        generation_id: self.generation.as_bytes().to_vec(),
        signature: self.signature.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: AdmissionGrantWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, ADMISSION_GRANT_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      cluster: ClusterId::parse(&wire.cluster_id)?,
      admission: AdmissionId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.admission_id,
        "admission id",
      )?)),
      subject: NodeId::parse(&wire.subject_id)?,
      subject_key: PublicKey::from_bytes(fixed_bytes(&wire.subject_key, "identity public key")?),
      issuer: NodeId::parse(&wire.issuer_id)?,
      generation: GenerationId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.generation_id,
        "credential generation id",
      )?)),
      signature: Signature::from_bytes(fixed_bytes(&wire.signature, "identity signature")?),
    })
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::VecDeque, sync::Mutex};

  use ed25519_dalek::{Signer, SigningKey};

  use super::*;
  use crate::{ErrorKind, TransactionId};

  const SUBJECT_NODE: &str = "node_100000000000000000000";
  const ISSUER_NODE: &str = "node_200000000000000000000";
  const CREATOR_NODE: &str = "node_300000000000000000000";
  const CLUSTER: &str = "cluster_400000000000000000000";
  const OPERATION: &str = "keyop_500000000000000000000";
  const TRANSACTION: &str = "txn_600000000000000000000";
  const BASE_REVISION: &[u8] = &[0x07];
  const PURPOSE: &str = "node-identity";
  const SIGNING_SEED: [u8; 32] = [0x42; 32];
  const SUBJECT_KEY: [u8; 32] = [0xA1; 32];
  const HANDLE_BYTES: &[u8] = b"opaque-handle-01";
  const GENERATION_BYTES: [u8; 16] = [0xC3; 16];
  const ADMISSION_BYTES: [u8; 16] = [0xD4; 16];

  fn node(value: &str) -> NodeId {
    NodeId::parse(value).unwrap()
  }

  fn cluster() -> ClusterId {
    ClusterId::parse(CLUSTER).unwrap()
  }

  fn operation() -> KeyOperationId {
    KeyOperationId::parse(OPERATION).unwrap()
  }

  fn transaction() -> TransactionId {
    TransactionId::parse(TRANSACTION).unwrap()
  }

  fn base_revision() -> StoreRevision {
    StoreRevision::new(Arc::from(BASE_REVISION)).unwrap()
  }

  fn handle() -> KeyHandle {
    KeyHandle::from_provider_bytes(Arc::from(HANDLE_BYTES)).unwrap()
  }

  fn generation() -> GenerationId {
    GenerationId::from_operation(OperationId::from_bytes(GENERATION_BYTES))
  }

  fn admission() -> AdmissionId {
    AdmissionId::from_operation(OperationId::from_bytes(ADMISSION_BYTES))
  }

  fn issuer_signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_SEED)
  }

  fn issuer_key() -> PublicKey {
    PublicKey::from_bytes(issuer_signing_key().verifying_key().to_bytes())
  }

  fn local_identity() -> LocalIdentityV1 {
    LocalIdentityV1::new(
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
      operation(),
      handle(),
    )
  }

  fn key_creation_intent() -> KeyCreationIntentV1 {
    KeyCreationIntentV1::new(
      operation(),
      node(SUBJECT_NODE),
      PURPOSE.to_owned(),
      transaction(),
      base_revision(),
    )
    .unwrap()
  }

  fn identity_binding() -> IdentityBindingV1 {
    IdentityBindingV1::new(node(SUBJECT_NODE), PublicKey::from_bytes(SUBJECT_KEY))
  }

  fn cluster_genesis() -> ClusterGenesisV1 {
    let creator_key = issuer_key();
    let body = ClusterGenesisBodyWire {
      schema: CLUSTER_GENESIS_SCHEMA.to_owned(),
      record_version: RECORD_VERSION,
      cluster_id: CLUSTER.to_owned(),
      creator_id: CREATOR_NODE.to_owned(),
      creator_key: creator_key.as_bytes().to_vec(),
    };
    let body_bytes = encode_canonical(&body, RECORD_LIMITS).unwrap();
    let signature = issuer_signing_key().sign(&super::super::signature::signature_message(
      CLUSTER_GENESIS_V1_DOMAIN,
      &body_bytes,
    ));
    ClusterGenesisV1::new(
      cluster(),
      node(CREATOR_NODE),
      creator_key,
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  fn local_cluster_pointer() -> LocalClusterPointerV1 {
    LocalClusterPointerV1::new(cluster(), cluster_genesis().digest().unwrap())
  }

  fn credential_use() -> CredentialUseV1 {
    CredentialUseV1::new(
      cluster(),
      node(ISSUER_NODE),
      generation(),
      admission(),
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
    )
  }

  fn admission_grant() -> AdmissionGrantV1 {
    let body = AdmissionGrantBodyWire {
      schema: ADMISSION_GRANT_SCHEMA.to_owned(),
      record_version: RECORD_VERSION,
      cluster_id: CLUSTER.to_owned(),
      admission_id: ADMISSION_BYTES.to_vec(),
      subject_id: SUBJECT_NODE.to_owned(),
      subject_key: SUBJECT_KEY.to_vec(),
      issuer_id: ISSUER_NODE.to_owned(),
      generation_id: GENERATION_BYTES.to_vec(),
    };
    let body_bytes = encode_canonical(&body, RECORD_LIMITS).unwrap();
    let signature = issuer_signing_key().sign(&super::super::signature::signature_message(
      ADMISSION_GRANT_V1_DOMAIN,
      &body_bytes,
    ));
    AdmissionGrantV1::new(
      cluster(),
      admission(),
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
      node(ISSUER_NODE),
      generation(),
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  fn golden(hex: &str) -> Vec<u8> {
    (0..hex.len())
      .step_by(2)
      .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
      .collect()
  }

  const LOCAL_IDENTITY_GOLDEN: &str = "87782a72656c61792e776f6f6f6f2e746563682f736368656d61732f6c6f63616c2d6964656e746974792d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781f72656c61792e776f6f6f6f2e746563682f63727970746f2f65643235353139781b6b65796f705f353030303030303030303030303030303030303030506f70617175652d68616e646c652d3031";
  const KEY_CREATION_INTENT_GOLDEN: &str = "88782f72656c61792e776f6f6f6f2e746563682f736368656d61732f6b65792d6372656174696f6e2d696e74656e742d763101781b6b65796f705f353030303030303030303030303030303030303030781a6e6f64655f3130303030303030303030303030303030303030306d6e6f64652d6964656e74697479781f72656c61792e776f6f6f6f2e746563682f63727970746f2f65643235353139781974786e5f3630303030303030303030303030303030303030304107";
  const IDENTITY_BINDING_GOLDEN: &str = "85782c72656c61792e776f6f6f6f2e746563682f736368656d61732f6964656e746974792d62696e64696e672d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781f72656c61792e776f6f6f6f2e746563682f63727970746f2f65643235353139";
  const CLUSTER_GENESIS_GOLDEN: &str = "86782b72656c61792e776f6f6f6f2e746563682f736368656d61732f636c75737465722d67656e657369732d763101781d636c75737465725f343030303030303030303030303030303030303030781a6e6f64655f33303030303030303030303030303030303030303058202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12584013e7b8206f1b16110b29bd10d8dd1c6aa7e3237bbc8981f446ff5655485b293be590907e7857012e7fc455b7d5526da59255a7430abc068d362eb8bd8ed5e703";
  const CLUSTER_GENESIS_BODY_GOLDEN: &str = "85782b72656c61792e776f6f6f6f2e746563682f736368656d61732f636c75737465722d67656e657369732d763101781d636c75737465725f343030303030303030303030303030303030303030781a6e6f64655f33303030303030303030303030303030303030303058202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
  const LOCAL_CLUSTER_POINTER_GOLDEN: &str = "84783172656c61792e776f6f6f6f2e746563682f736368656d61732f6c6f63616c2d636c75737465722d706f696e7465722d763101781d636c75737465725f3430303030303030303030303030303030303030305820300527f955297c6e361c97b7f0bc466f8c39e94f7c63301de3606c9dfce0ce2b";
  const CREDENTIAL_USE_GOLDEN: &str = "88782a72656c61792e776f6f6f6f2e746563682f736368656d61732f63726564656e7469616c2d7573652d763101781d636c75737465725f343030303030303030303030303030303030303030781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c350d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
  const ADMISSION_GRANT_GOLDEN: &str = "89782b72656c61792e776f6f6f6f2e746563682f736368656d61732f61646d697373696f6e2d6772616e742d763101781d636c75737465725f34303030303030303030303030303030303030303050d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3584045b05768301f6ebd3e0180773dcd8846c4c39da774ccbc495f755bed38e2c108afe82d8377ed631d8b30fe365e6f3b8658b91132478d99adfba7f12970b6c703";
  const ADMISSION_GRANT_BODY_GOLDEN: &str = "88782b72656c61792e776f6f6f6f2e746563682f736368656d61732f61646d697373696f6e2d6772616e742d763101781d636c75737465725f34303030303030303030303030303030303030303050d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

  #[test]
  fn identity_records_golden_vectors_match_exact_bytes() {
    assert_eq!(
      local_identity().encode().unwrap(),
      golden(LOCAL_IDENTITY_GOLDEN)
    );
    assert_eq!(
      key_creation_intent().encode().unwrap(),
      golden(KEY_CREATION_INTENT_GOLDEN)
    );
    assert_eq!(
      identity_binding().encode().unwrap(),
      golden(IDENTITY_BINDING_GOLDEN)
    );
    assert_eq!(
      cluster_genesis().encode().unwrap(),
      golden(CLUSTER_GENESIS_GOLDEN)
    );
    assert_eq!(
      cluster_genesis().signed_body().unwrap(),
      golden(CLUSTER_GENESIS_BODY_GOLDEN)
    );
    assert_eq!(
      local_cluster_pointer().encode().unwrap(),
      golden(LOCAL_CLUSTER_POINTER_GOLDEN)
    );
    assert_eq!(
      credential_use().encode().unwrap(),
      golden(CREDENTIAL_USE_GOLDEN)
    );
    assert_eq!(
      admission_grant().encode().unwrap(),
      golden(ADMISSION_GRANT_GOLDEN)
    );
    assert_eq!(
      admission_grant().signed_body().unwrap(),
      golden(ADMISSION_GRANT_BODY_GOLDEN)
    );
  }

  #[test]
  fn identity_records_golden_vectors_decode_to_exact_records() {
    assert_eq!(
      LocalIdentityV1::decode(&golden(LOCAL_IDENTITY_GOLDEN)).unwrap(),
      local_identity()
    );
    assert_eq!(
      KeyCreationIntentV1::decode(&golden(KEY_CREATION_INTENT_GOLDEN)).unwrap(),
      key_creation_intent()
    );
    assert_eq!(
      IdentityBindingV1::decode(&golden(IDENTITY_BINDING_GOLDEN)).unwrap(),
      identity_binding()
    );
    assert_eq!(
      ClusterGenesisV1::decode(&golden(CLUSTER_GENESIS_GOLDEN)).unwrap(),
      cluster_genesis()
    );
    assert_eq!(
      LocalClusterPointerV1::decode(&golden(LOCAL_CLUSTER_POINTER_GOLDEN)).unwrap(),
      local_cluster_pointer()
    );
    assert_eq!(
      CredentialUseV1::decode(&golden(CREDENTIAL_USE_GOLDEN)).unwrap(),
      credential_use()
    );
    assert_eq!(
      AdmissionGrantV1::decode(&golden(ADMISSION_GRANT_GOLDEN)).unwrap(),
      admission_grant()
    );
  }

  #[test]
  fn identity_records_signed_records_verify_against_golden_bytes() {
    ClusterGenesisV1::decode(&golden(CLUSTER_GENESIS_GOLDEN))
      .unwrap()
      .verify()
      .unwrap();
    AdmissionGrantV1::decode(&golden(ADMISSION_GRANT_GOLDEN))
      .unwrap()
      .verify(&issuer_key())
      .unwrap();
  }

  #[test]
  fn identity_records_local_cluster_pointer_tracks_genesis_digest() {
    let pointer = local_cluster_pointer();
    let genesis = cluster_genesis();

    assert_eq!(pointer.cluster(), genesis.cluster());
    assert_eq!(pointer.genesis_digest(), &genesis.digest().unwrap());
    let expected = record_digest(&genesis.encode().unwrap());
    assert_eq!(pointer.genesis_digest(), &expected);
  }

  fn wrong_schema(schema: &str) -> String {
    let stem = schema.strip_suffix("v1").unwrap();
    format!("{stem}v0")
  }

  #[test]
  fn identity_records_reject_wrong_schema_tags() {
    let mut identity = local_identity().encode().unwrap();
    replace_text(
      &mut identity,
      LOCAL_IDENTITY_SCHEMA,
      &wrong_schema(LOCAL_IDENTITY_SCHEMA),
    );
    assert!(LocalIdentityV1::decode(&identity).is_err());

    let mut intent = key_creation_intent().encode().unwrap();
    replace_text(
      &mut intent,
      KEY_CREATION_INTENT_SCHEMA,
      &wrong_schema(KEY_CREATION_INTENT_SCHEMA),
    );
    assert!(KeyCreationIntentV1::decode(&intent).is_err());

    let mut binding = identity_binding().encode().unwrap();
    replace_text(
      &mut binding,
      IDENTITY_BINDING_SCHEMA,
      &wrong_schema(IDENTITY_BINDING_SCHEMA),
    );
    assert!(IdentityBindingV1::decode(&binding).is_err());

    let mut genesis = cluster_genesis().encode().unwrap();
    replace_text(
      &mut genesis,
      CLUSTER_GENESIS_SCHEMA,
      &wrong_schema(CLUSTER_GENESIS_SCHEMA),
    );
    assert!(ClusterGenesisV1::decode(&genesis).is_err());

    let mut pointer = local_cluster_pointer().encode().unwrap();
    replace_text(
      &mut pointer,
      LOCAL_CLUSTER_POINTER_SCHEMA,
      &wrong_schema(LOCAL_CLUSTER_POINTER_SCHEMA),
    );
    assert!(LocalClusterPointerV1::decode(&pointer).is_err());

    let mut credential = credential_use().encode().unwrap();
    replace_text(
      &mut credential,
      CREDENTIAL_USE_SCHEMA,
      &wrong_schema(CREDENTIAL_USE_SCHEMA),
    );
    assert!(CredentialUseV1::decode(&credential).is_err());

    let mut grant = admission_grant().encode().unwrap();
    replace_text(
      &mut grant,
      ADMISSION_GRANT_SCHEMA,
      &wrong_schema(ADMISSION_GRANT_SCHEMA),
    );
    assert!(AdmissionGrantV1::decode(&grant).is_err());
  }

  #[test]
  fn identity_records_reject_wrong_record_version() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      cluster_genesis().encode().unwrap(),
      local_cluster_pointer().encode().unwrap(),
      credential_use().encode().unwrap(),
      admission_grant().encode().unwrap(),
    ] {
      let mut mutated = bytes.clone();
      let version = version_position(&bytes);
      mutated[version] = 0x02;
      assert!(decode_any(&mutated));
    }
  }

  fn decode_any(bytes: &[u8]) -> bool {
    LocalIdentityV1::decode(bytes).is_err()
      && KeyCreationIntentV1::decode(bytes).is_err()
      && IdentityBindingV1::decode(bytes).is_err()
      && ClusterGenesisV1::decode(bytes).is_err()
      && LocalClusterPointerV1::decode(bytes).is_err()
      && CredentialUseV1::decode(bytes).is_err()
      && AdmissionGrantV1::decode(bytes).is_err()
  }

  fn replace_text(bytes: &mut [u8], from: &str, to: &str) {
    assert_eq!(from.len(), to.len());
    let needle = from.as_bytes();
    let start = bytes
      .windows(needle.len())
      .position(|window| window == needle)
      .unwrap();
    bytes[start..start + needle.len()].copy_from_slice(to.as_bytes());
  }

  fn version_position(bytes: &[u8]) -> usize {
    // [array header][text header 0x78 len][schema bytes][version]
    assert_eq!(bytes[1], 0x78);
    1 + 2 + bytes[2] as usize
  }

  #[test]
  fn identity_records_reject_trailing_bytes() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      cluster_genesis().encode().unwrap(),
      local_cluster_pointer().encode().unwrap(),
      credential_use().encode().unwrap(),
      admission_grant().encode().unwrap(),
    ] {
      let mut trailed = bytes;
      trailed.push(0x00);
      assert!(decode_any(&trailed));
    }
  }

  #[test]
  fn identity_records_reject_noncanonical_arguments() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      cluster_genesis().encode().unwrap(),
      local_cluster_pointer().encode().unwrap(),
      credential_use().encode().unwrap(),
      admission_grant().encode().unwrap(),
    ] {
      let version = version_position(&bytes);
      let mut widened = bytes[..version].to_vec();
      widened.extend_from_slice(&[0x18, bytes[version]]);
      widened.extend_from_slice(&bytes[version + 1..]);
      assert!(decode_any(&widened));
    }
  }

  #[test]
  fn identity_records_reject_wrong_field_counts() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      cluster_genesis().encode().unwrap(),
      local_cluster_pointer().encode().unwrap(),
      credential_use().encode().unwrap(),
      admission_grant().encode().unwrap(),
    ] {
      let mut extra = bytes.clone();
      extra[0] += 1;
      extra.push(0x00);
      assert!(decode_any(&extra));

      let mut missing = bytes;
      missing[0] -= 1;
      missing.pop();
      assert!(decode_any(&missing));
    }
  }

  #[test]
  fn identity_records_reject_field_value_mutations() {
    let malformed_node = {
      let mut bytes = identity_binding().encode().unwrap();
      replace_text(&mut bytes, SUBJECT_NODE, "node_!00000000000000000000");
      bytes
    };
    assert!(IdentityBindingV1::decode(&malformed_node).is_err());

    let short_key = {
      let wire_bytes = identity_binding().encode().unwrap();
      let mut mutated = wire_bytes;
      let key_start = mutated
        .windows(SUBJECT_KEY.len())
        .position(|window| window == SUBJECT_KEY)
        .unwrap();
      mutated[key_start] ^= 0xFF;
      mutated
    };
    let decoded = IdentityBindingV1::decode(&short_key).unwrap();
    assert_ne!(decoded, identity_binding());

    let short_public_key = encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: vec![0xA1; 31],
        algorithm: ED25519_ALGORITHM.to_owned(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(IdentityBindingV1::decode(&short_public_key).is_err());

    let empty_handle = encode_canonical(
      &LocalIdentityWire {
        schema: LOCAL_IDENTITY_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: SUBJECT_KEY.to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        key_operation_id: OPERATION.to_owned(),
        key_handle: Vec::new(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(LocalIdentityV1::decode(&empty_handle).is_err());

    let wrong_algorithm = encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: SUBJECT_KEY.to_vec(),
        algorithm: "relay.woooo.tech/crypto/ed25519ph".to_owned(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(IdentityBindingV1::decode(&wrong_algorithm).is_err());

    let short_generation = encode_canonical(
      &CredentialUseWire {
        schema: CREDENTIAL_USE_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        cluster_id: CLUSTER.to_owned(),
        issuer_id: ISSUER_NODE.to_owned(),
        generation_id: vec![0xC3; 15],
        admission_id: ADMISSION_BYTES.to_vec(),
        subject_id: SUBJECT_NODE.to_owned(),
        subject_key: SUBJECT_KEY.to_vec(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(CredentialUseV1::decode(&short_generation).is_err());
  }

  #[test]
  fn identity_records_genesis_signature_covers_every_body_field() {
    let genesis = cluster_genesis();
    genesis.verify().unwrap();

    let other_cluster = ClusterId::parse("cluster_900000000000000000000").unwrap();
    let other_node = node("node_900000000000000000000");
    let other_key = PublicKey::from_bytes([0xB2; 32]);
    let signature = genesis_signature(&genesis).clone();

    for mutated in [
      ClusterGenesisV1::new(
        other_cluster,
        node(CREATOR_NODE),
        issuer_key(),
        signature.clone(),
      ),
      ClusterGenesisV1::new(cluster(), other_node, issuer_key(), signature.clone()),
      ClusterGenesisV1::new(cluster(), node(CREATOR_NODE), other_key, signature),
    ] {
      let error = mutated.verify().unwrap_err();
      assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    }

    let other_signature = Signature::from_bytes([0x5A; 64]);
    let mutated =
      ClusterGenesisV1::new(cluster(), node(CREATOR_NODE), issuer_key(), other_signature);
    assert_eq!(
      mutated.verify().unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );
  }

  fn genesis_signature(genesis: &ClusterGenesisV1) -> &Signature {
    &genesis.signature
  }

  #[test]
  fn identity_records_admission_signature_covers_every_body_field() {
    let grant = admission_grant();
    grant.verify(&issuer_key()).unwrap();

    let signature = grant_signature(&grant);
    let other_cluster = ClusterId::parse("cluster_900000000000000000000").unwrap();
    let other_admission = AdmissionId::from_operation(OperationId::from_bytes([0xE5; 16]));
    let other_generation = GenerationId::from_operation(OperationId::from_bytes([0xE5; 16]));
    let other_node = node("node_900000000000000000000");
    let other_key = PublicKey::from_bytes([0xB2; 32]);

    for mutated in [
      AdmissionGrantV1::new(
        other_cluster,
        admission(),
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      AdmissionGrantV1::new(
        cluster(),
        other_admission,
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      AdmissionGrantV1::new(
        cluster(),
        admission(),
        other_node.clone(),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      AdmissionGrantV1::new(
        cluster(),
        admission(),
        node(SUBJECT_NODE),
        other_key,
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      AdmissionGrantV1::new(
        cluster(),
        admission(),
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        other_node,
        generation(),
        signature.clone(),
      ),
      AdmissionGrantV1::new(
        cluster(),
        admission(),
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        other_generation,
        signature.clone(),
      ),
    ] {
      let error = mutated.verify(&issuer_key()).unwrap_err();
      assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    }

    let wrong_issuer_key = PublicKey::from_bytes(
      SigningKey::from_bytes(&[0x24; 32])
        .verifying_key()
        .to_bytes(),
    );
    assert_eq!(
      grant.verify(&wrong_issuer_key).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );
  }

  fn grant_signature(grant: &AdmissionGrantV1) -> Signature {
    grant.signature.clone()
  }

  #[test]
  fn identity_records_debug_redacts_handles_signatures_and_operation_bytes() {
    let identity_debug = format!("{:?}", local_identity());
    assert!(!identity_debug.contains("opaque-handle-01"));
    let handle_hex: String = HANDLE_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!identity_debug.contains(&handle_hex));

    let genesis = cluster_genesis();
    let genesis_debug = format!("{genesis:?}");
    let signature = genesis_signature(&genesis);
    let signature_hex: String = signature
      .as_bytes()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!genesis_debug.contains(&signature_hex));
    assert!(genesis_debug.contains("Signature(..)"));

    let use_debug = format!("{:?}", credential_use());
    let generation_hex: String = GENERATION_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    let admission_hex: String = ADMISSION_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!use_debug.contains(&generation_hex));
    assert!(!use_debug.contains(&admission_hex));
    assert!(use_debug.contains("GenerationId(..)"));
    assert!(use_debug.contains("AdmissionId(..)"));

    let grant_debug = format!("{:?}", admission_grant());
    assert!(!grant_debug.contains(&generation_hex));
    assert!(!grant_debug.contains(&admission_hex));
    assert!(!grant_debug.contains(&signature_hex));

    assert_eq!(format!("{:?}", generation()), "GenerationId(..)");
    assert_eq!(format!("{:?}", admission()), "AdmissionId(..)");
  }

  #[test]
  fn identity_records_storage_keys_use_metadata_namespaces() {
    let builders: Vec<(StoreNamespace, StoreKey)> = vec![
      local_identity_key().unwrap(),
      key_creation_intent_key(&operation()).unwrap(),
      identity_binding_key(&node(SUBJECT_NODE)).unwrap(),
      cluster_genesis_key(&cluster()).unwrap(),
      local_cluster_pointer_key().unwrap(),
      credential_use_key(&node(ISSUER_NODE), &generation()).unwrap(),
      admission_grant_key(&admission()).unwrap(),
    ];

    let mut namespaces = Vec::new();
    for (namespace, _) in &builders {
      let parsed = QualifiedTag::parse(namespace.as_str()).unwrap();
      assert_eq!(parsed.category(), "metadata");
      namespaces.push(namespace.as_str().to_owned());
    }
    namespaces.sort();
    namespaces.dedup();
    assert_eq!(namespaces.len(), builders.len());
  }

  #[test]
  fn identity_records_storage_key_bytes_are_exact() {
    let (identity_namespace, identity_key) = local_identity_key().unwrap();
    assert_eq!(
      identity_namespace.as_str(),
      "relay.woooo.tech/metadata/local-identity-v1"
    );
    assert_eq!(identity_key.as_bytes(), b"self");

    let (intent_namespace, intent_key) = key_creation_intent_key(&operation()).unwrap();
    assert_eq!(
      intent_namespace.as_str(),
      "relay.woooo.tech/metadata/key-creation-intent-v1"
    );
    assert_eq!(intent_key.as_bytes(), OPERATION.as_bytes());

    let (binding_namespace, binding_key) = identity_binding_key(&node(SUBJECT_NODE)).unwrap();
    assert_eq!(
      binding_namespace.as_str(),
      "relay.woooo.tech/metadata/identity-binding-v1"
    );
    assert_eq!(binding_key.as_bytes(), SUBJECT_NODE.as_bytes());

    let (genesis_namespace, genesis_key) = cluster_genesis_key(&cluster()).unwrap();
    assert_eq!(
      genesis_namespace.as_str(),
      "relay.woooo.tech/metadata/cluster-genesis-v1"
    );
    assert_eq!(genesis_key.as_bytes(), CLUSTER.as_bytes());

    let (pointer_namespace, pointer_key) = local_cluster_pointer_key().unwrap();
    assert_eq!(
      pointer_namespace.as_str(),
      "relay.woooo.tech/metadata/local-cluster-pointer-v1"
    );
    assert_eq!(pointer_key.as_bytes(), b"self");

    let (use_namespace, use_key) = credential_use_key(&node(ISSUER_NODE), &generation()).unwrap();
    assert_eq!(
      use_namespace.as_str(),
      "relay.woooo.tech/metadata/credential-use-v1"
    );
    let mut expected_use_key = ISSUER_NODE.as_bytes().to_vec();
    expected_use_key.extend_from_slice(&GENERATION_BYTES);
    assert_eq!(use_key.as_bytes(), expected_use_key.as_slice());

    let (grant_namespace, grant_key) = admission_grant_key(&admission()).unwrap();
    assert_eq!(
      grant_namespace.as_str(),
      "relay.woooo.tech/metadata/admission-grant-v1"
    );
    assert_eq!(grant_key.as_bytes(), &ADMISSION_BYTES);
  }

  #[test]
  fn identity_records_key_creation_intent_purpose_is_bounded_printable_ascii() {
    let valid = || {
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
    };
    assert!(valid().is_ok());
    let with_purpose = |purpose: String| {
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        purpose,
        transaction(),
        base_revision(),
      )
    };
    assert!(with_purpose(String::new()).is_err());
    assert!(with_purpose("x".repeat(129)).is_err());
    assert!(with_purpose("bad\tpurpose".to_owned()).is_err());
    assert!(with_purpose("bad\u{7f}purpose".to_owned()).is_err());
    assert!(with_purpose("node identity".to_owned()).is_ok());

    let long_purpose = with_purpose("p".repeat(128)).unwrap();
    assert_eq!(
      KeyCreationIntentV1::decode(&long_purpose.encode().unwrap()).unwrap(),
      long_purpose
    );
  }

  #[test]
  fn identity_records_key_creation_intent_recovers_exact_storage_identity() {
    use crate::{
      StoreTransaction,
      storage::receipt::{
        ACTIVE_MARKER_VALUE, encode_reference_count, internal_namespace, reference_edge_key,
        reference_head_key, used_id_key,
      },
    };

    let intent = key_creation_intent();
    let stored_value = StoreValue::new(Arc::from(intent.encode().unwrap()));
    let recovered = intent.recovery_identity(&stored_value).unwrap();

    // Directly prepare the paired storage transaction: the caller intent Put,
    // the AddSelf receipt head and edge, and the permanent used-ID marker.
    let (namespace, key) = key_creation_intent_key(intent.operation()).unwrap();
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    let internal = internal_namespace().unwrap();
    let direct = StoreTransaction::new(
      intent.transaction().clone(),
      intent.base_revision().clone(),
      vec![
        StoreOperation::Put {
          namespace,
          key,
          expected: StoreExpectation::Absent,
          value: stored_value.clone(),
        },
        StoreOperation::Put {
          namespace: internal.clone(),
          key: reference_head_key(intent.transaction()).unwrap(),
          expected: StoreExpectation::Absent,
          value: encode_reference_count(1),
        },
        StoreOperation::Put {
          namespace: internal.clone(),
          key: reference_edge_key(intent.transaction(), &token).unwrap(),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from([])),
        },
        StoreOperation::Put {
          namespace: internal,
          key: used_id_key(intent.transaction()).unwrap(),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(ACTIVE_MARKER_VALUE)),
        },
      ],
    )
    .unwrap();
    assert_eq!(recovered.transaction(), direct.id());
    assert_eq!(recovered.operation_digest(), direct.operation_digest());

    // Mutating any single intent field changes the recovered identity.
    for mutated in [
      KeyCreationIntentV1::new(
        KeyOperationId::parse("keyop_600000000000000000000").unwrap(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(ISSUER_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        "cluster-identity".to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        TransactionId::parse("txn_700000000000000000000").unwrap(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        StoreRevision::new(Arc::from([0x08])).unwrap(),
      )
      .unwrap(),
    ] {
      let mutated_value = StoreValue::new(Arc::from(mutated.encode().unwrap()));
      assert_ne!(
        mutated.recovery_identity(&mutated_value).unwrap(),
        recovered
      );
    }

    // Mutating the stored value itself also changes the recovered identity.
    let mut corrupted = intent.encode().unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let corrupted = StoreValue::new(Arc::from(corrupted));
    assert_ne!(intent.recovery_identity(&corrupted).unwrap(), recovered);
  }

  #[derive(Debug)]
  struct ScriptedEntropy {
    chunks: Mutex<VecDeque<Vec<u8>>>,
  }

  impl ScriptedEntropy {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
      Self {
        chunks: Mutex::new(chunks.into()),
      }
    }
  }

  impl Entropy for ScriptedEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
      let chunk = self
        .chunks
        .lock()
        .map_err(|_| Error::internal("scripted entropy lock"))?
        .pop_front()
        .ok_or_else(|| Error::internal("scripted entropy exhausted"))?;
      if chunk.len() != output.len() {
        return Err(Error::internal("scripted entropy length"));
      }
      output.copy_from_slice(&chunk);
      Ok(())
    }
  }

  #[derive(Debug)]
  struct FailingEntropy;

  impl Entropy for FailingEntropy {
    fn fill(&self, _output: &mut [u8]) -> Result<()> {
      Err(Error::internal("injected entropy failure"))
    }
  }

  fn suffix_space() -> u128 {
    let mut space = 1_u128;
    for _ in 0..21 {
      space *= 62;
    }
    space
  }

  fn entropy_word(value: u128) -> Vec<u8> {
    value.to_be_bytes().to_vec()
  }

  #[test]
  fn identity_records_generated_ids_use_canonical_unbiased_suffixes() {
    let zero = ScriptedEntropy::new(vec![entropy_word(0)]);
    let id = NodeId::generate(&zero).unwrap();
    assert_eq!(id.as_str(), "node_000000000000000000000");
    assert_eq!(NodeId::parse(id.as_str()).unwrap(), id);

    let max = ScriptedEntropy::new(vec![entropy_word(suffix_space() - 1)]);
    let id = ClusterId::generate(&max).unwrap();
    assert_eq!(id.as_str(), "cluster_ZZZZZZZZZZZZZZZZZZZZZ");
    assert_eq!(ClusterId::parse(id.as_str()).unwrap(), id);

    let one = ScriptedEntropy::new(vec![entropy_word(1)]);
    let id = TransactionId::generate(&one).unwrap();
    assert_eq!(id.as_str(), "txn_000000000000000000001");

    let digit_run = ScriptedEntropy::new(vec![entropy_word(61)]);
    let id = KeyOperationId::generate(&digit_run).unwrap();
    assert_eq!(id.as_str(), "keyop_00000000000000000000Z");
    assert_eq!(KeyOperationId::parse(id.as_str()).unwrap(), id);
  }

  #[test]
  fn identity_records_generator_rejects_out_of_range_candidates() {
    let entropy = ScriptedEntropy::new(vec![entropy_word(suffix_space()), entropy_word(5)]);
    let id = NodeId::generate(&entropy).unwrap();
    assert_eq!(id.as_str(), "node_000000000000000000005");

    let entropy = ScriptedEntropy::new(vec![
      entropy_word(u128::MAX),
      entropy_word(suffix_space()),
      entropy_word(61),
    ]);
    let id = ClusterId::generate(&entropy).unwrap();
    assert_eq!(id.as_str(), "cluster_00000000000000000000Z");
  }

  #[test]
  fn identity_records_entropy_failure_precedes_any_id_output() {
    let error = NodeId::generate(&FailingEntropy).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "injected entropy failure");

    assert!(ClusterId::generate(&FailingEntropy).is_err());
    assert!(TransactionId::generate(&FailingEntropy).is_err());
    assert!(KeyOperationId::generate(&FailingEntropy).is_err());
    assert!(OperationId::generate(&FailingEntropy).is_err());
    assert!(GenerationId::generate(&FailingEntropy).is_err());
    assert!(AdmissionId::generate(&FailingEntropy).is_err());
  }

  #[test]
  fn identity_records_operation_id_generation_is_deterministic_and_redacted() {
    let entropy = ScriptedEntropy::new(vec![GENERATION_BYTES.to_vec()]);
    let operation = OperationId::generate(&entropy).unwrap();
    assert_eq!(operation.as_bytes(), &GENERATION_BYTES);
    assert_eq!(format!("{operation:?}"), "OperationId(..)");

    let entropy = ScriptedEntropy::new(vec![ADMISSION_BYTES.to_vec()]);
    let wrapper = AdmissionId::generate(&entropy).unwrap();
    assert_eq!(wrapper, admission());
  }
}

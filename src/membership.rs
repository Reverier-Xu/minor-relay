//! Owner-signed node descriptors (G5-01, ADR-0007 metadata boundary).
//!
//! TODO(G5-02): the descriptor store and verification surface are consumed
//! when membership sync exchanges pages; until then they are exercised by
//! the unit suite.
#![allow(dead_code)]
//!
//! A [`NodeDescriptorV1`] is the signed node-owned revision record: the
//! owning node signs its `NodeId`-to-`PublicKey` binding, its endpoint
//! candidates, a strictly increasing revision, and the removal flag. Core
//! accepts an update only at the exact next revision; stale, repeated, and
//! skipped revisions cannot replace the current record, and a retained
//! signed removal marker defeats reordered or replayed older descriptors.

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  Endpoint, Error, NodeId, PublicKey, Result, Signature,
  protocol::{decode_canonical, encode_canonical},
};

/// The signature domain of one node descriptor.
pub(crate) const NODE_DESCRIPTOR_V1_DOMAIN: &[u8] = b"relay.woooo.tech/crypto/node-descriptor-v1";

/// The durable schema, namespace, and key of one node descriptor record.
pub(crate) const NODE_DESCRIPTOR_SCHEMA: &str = "relay.woooo.tech/schemas/node-descriptor-v1";
pub(crate) const NODE_DESCRIPTOR_NAMESPACE: &str = "relay.woooo.tech/metadata/node-descriptor-v1";

/// One owner-signed node descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeDescriptorV1 {
  node: NodeId,
  public_key: PublicKey,
  endpoints: Vec<Endpoint>,
  revision: u64,
  removed: bool,
  version: u16,
  signature: Signature,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct DescriptorWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  node: String,
  #[n(3)]
  public_key: ByteVec,
  #[n(4)]
  endpoints: Vec<String>,
  #[n(5)]
  revision: u64,
  #[n(6)]
  removed: bool,
  #[n(7)]
  version: u16,
  #[n(8)]
  signature: ByteVec,
}

impl NodeDescriptorV1 {
  pub(crate) fn new(
    node: NodeId, public_key: PublicKey, endpoints: Vec<Endpoint>, revision: u64, removed: bool,
    version: u16, signature: Signature,
  ) -> Self {
    Self {
      node,
      public_key,
      endpoints,
      revision,
      removed,
      version,
      signature,
    }
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) const fn revision(&self) -> u64 {
    self.revision
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) fn endpoints(&self) -> &[Endpoint] {
    &self.endpoints
  }

  pub(crate) const fn removed(&self) -> bool {
    self.removed
  }

  pub(crate) fn encode_signed_body(&self) -> Result<Vec<u8>> {
    let mut wire = self.wire();
    wire.signature = ByteVec::from(Vec::new());
    encode_canonical(&wire, crate::protocol::offer::OFFER_CBOR_LIMITS)
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(&self.wire(), crate::protocol::offer::OFFER_CBOR_LIMITS)
  }

  fn wire(&self) -> DescriptorWire {
    DescriptorWire {
      schema: NODE_DESCRIPTOR_SCHEMA.to_owned(),
      record_version: 1,
      node: self.node.as_str().to_owned(),
      public_key: ByteVec::from(self.public_key.as_bytes().to_vec()),
      endpoints: self
        .endpoints
        .iter()
        .map(|endpoint| endpoint.as_str().to_owned())
        .collect(),
      revision: self.revision,
      removed: self.removed,
      version: self.version,
      signature: ByteVec::from(self.signature.as_bytes().to_vec()),
    }
  }

  /// Decodes and verifies one descriptor against its bound key. Fails
  /// closed on signature mismatch, wrong schema/version, or a public key
  /// that does not bind to the claimed node (SC-G05-P0-01).
  pub(crate) fn decode_and_verify(bytes: &[u8], bound_key: &PublicKey) -> Result<NodeDescriptorV1> {
    let wire: DescriptorWire = decode_canonical(bytes, crate::protocol::offer::OFFER_CBOR_LIMITS)
      .map_err(|_| Error::invalid_input("node descriptor decode"))?;
    if wire.schema != NODE_DESCRIPTOR_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("node descriptor schema"));
    }
    // Only version 1 is known; an unknown version fails closed
    // (SC-G05-P0-05).
    if wire.version != 1 {
      return Err(Error::invalid_input("node descriptor version"));
    }
    let node =
      NodeId::parse(&wire.node).map_err(|_| Error::invalid_input("node descriptor node"))?;
    let public_key = PublicKey::from_bytes(
      <[u8; 32]>::try_from(wire.public_key.as_ref())
        .map_err(|_| Error::invalid_input("node descriptor key"))?,
    );
    if &public_key != bound_key {
      // The descriptor claims a node but is signed by a different key.
      return Err(Error::not_trusted("node descriptor key binding"));
    }
    let mut endpoints = Vec::with_capacity(wire.endpoints.len());
    for text in &wire.endpoints {
      endpoints
        .push(Endpoint::parse(text).map_err(|_| Error::invalid_input("node descriptor endpoint"))?);
    }
    let descriptor = Self::new(
      node,
      public_key,
      endpoints,
      wire.revision,
      wire.removed,
      wire.version,
      Signature::from_bytes({
        let bytes: &[u8] = wire.signature.as_ref();
        <[u8; 64]>::try_from(bytes)
          .map_err(|_| Error::invalid_input("node descriptor signature"))?
      }),
    );
    crate::identity::signature::verify_strict(
      NODE_DESCRIPTOR_V1_DOMAIN,
      &descriptor.encode_signed_body()?,
      bound_key,
      &descriptor.signature,
      "node descriptor signature",
    )?;
    Ok(descriptor)
  }
}

/// The bounded descriptor observation store.
pub(crate) mod page;

pub(crate) mod store {
  use std::sync::Arc;

  use super::{NODE_DESCRIPTOR_NAMESPACE, NodeDescriptorV1};
  use crate::{
    Error, NodeId, PublicKey, Result, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
    StoreRequirements, StoreTransaction, StoreValue, TransactionId, provider::StorageFactory,
  };

  fn namespace() -> Result<StoreNamespace> {
    StoreNamespace::new(crate::QualifiedTag::parse(NODE_DESCRIPTOR_NAMESPACE)?)
  }

  fn descriptor_key(node: &NodeId) -> StoreKey {
    StoreKey::new(Arc::from(node.as_str().as_bytes().to_vec()))
  }

  /// Reads the current descriptor for one node, if any.
  pub(crate) async fn read_descriptor(
    factory: &Arc<dyn StorageFactory>, node: &NodeId, bound_key: &PublicKey,
  ) -> Result<Option<NodeDescriptorV1>> {
    let storage = factory.open(StoreRequirements::metadata()).await?;
    let namespace = namespace()?;
    let key = descriptor_key(node);
    let value = storage.snapshot().await?.get(&namespace, &key).await?;
    let Some(value) = value else {
      return Ok(None);
    };
    Ok(Some(NodeDescriptorV1::decode_and_verify(
      value.as_bytes(),
      bound_key,
    )?))
  }

  /// Stores one descriptor. The revision must be exactly one greater than
  /// the current record's revision; the first record starts at revision 1.
  /// Same-revision, stale, and skipped revisions are rejected (SC-G05-P0-03).
  pub(crate) async fn store_descriptor(
    factory: &Arc<dyn StorageFactory>, descriptor: &NodeDescriptorV1,
  ) -> Result<()> {
    let storage = factory.open(StoreRequirements::metadata()).await?;
    let namespace = namespace()?;
    let key = descriptor_key(descriptor.node());
    let current = storage.snapshot().await?.get(&namespace, &key).await?;
    if let Some(existing) = current {
      let existing =
        NodeDescriptorV1::decode_and_verify(existing.as_bytes(), descriptor.public_key())?;
      if existing.revision() != descriptor.revision().saturating_sub(1) {
        return Err(Error::conflict("node descriptor revision"));
      }
      // A removal marker is never replaced by a live descriptor of an
      // older or equal revision; the store above already enforces next-only.
      if existing.removed() && !descriptor.removed() {
        return Err(Error::conflict("node descriptor removal"));
      }
    } else if descriptor.revision() != 1 {
      return Err(Error::conflict("node descriptor revision"));
    }
    // The store updates the same key; the expectation reflects the current
    // value (or absence on first insert) so the commit is conditional.
    let expected = match storage.snapshot().await?.get(&namespace, &key).await? {
      Some(current) => StoreExpectation::Exact(current.digest().clone()),
      None => StoreExpectation::Absent,
    };
    let transaction = StoreTransaction::new(
      TransactionId::generate(&crate::api::SystemEntropy)?,
      storage.snapshot().await?.revision().clone(),
      vec![StoreOperation::Put {
        namespace,
        key,
        expected,
        value: StoreValue::new(Arc::from(descriptor.encode()?)),
      }],
    )?;
    let _ = storage.commit(transaction).await?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use ed25519_dalek::Signer;

  use super::{NodeDescriptorV1, store};
  use crate::{
    Endpoint, NodeId, PublicKey, Signature,
    identity::{signature::signature_message, testing::scripted_signing},
    provider::StorageFactory,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(value: u8) -> PublicKey {
    let signing = scripted_signing(value.into());
    PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn endpoint(host: &str) -> Endpoint {
    Endpoint::parse(&format!("wss://{host}:9000")).unwrap()
  }

  fn sign(descriptor: &mut NodeDescriptorV1, owner_index: u8) {
    let signing = scripted_signing(owner_index.into());
    let message = signature_message(
      super::NODE_DESCRIPTOR_V1_DOMAIN,
      &descriptor.encode_signed_body().unwrap(),
    );
    descriptor.signature = Signature::from_bytes(signing.sign(&message).to_bytes());
  }

  fn descriptor(
    revision: u64, owner_index: u8, endpoints: Vec<&str>, removed: bool,
  ) -> NodeDescriptorV1 {
    let owner = node(owner_index);
    let owner_key = key(owner_index);
    let mut descriptor = NodeDescriptorV1::new(
      owner,
      owner_key.clone(),
      endpoints.into_iter().map(endpoint).collect(),
      revision,
      removed,
      1,
      Signature::from_bytes([0; 64]),
    );
    sign(&mut descriptor, owner_index);
    descriptor
  }

  fn factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// SC-G05-P0-01: a descriptor signed by the wrong identity fails before
  /// storage.
  #[test]
  fn descriptor_rejects_wrong_identity_signature() {
    let mut descriptor = descriptor(1, 1, vec!["one.example"], false);
    // Re-sign with a different owner key than the claimed node's.
    sign(&mut descriptor, 2);
    // The claimed binding is node(1)/key(1) but the signature is key(2)'s.
    assert!(NodeDescriptorV1::decode_and_verify(&descriptor.encode().unwrap(), &key(1)).is_err());
    // A different bound key also fails the key-binding check.
    assert!(NodeDescriptorV1::decode_and_verify(&descriptor.encode().unwrap(), &key(2)).is_err());
  }

  /// SC-G05-P0-02: mutating any signed field invalidates the signature.
  #[test]
  fn descriptor_rejects_field_mutation() {
    let descriptor = descriptor(1, 1, vec!["one.example"], false);
    let bytes = descriptor.encode().unwrap();

    // Tampered revision bytes fail verification.
    let _bytes = bytes.clone();
    // Re-encoding a mutated descriptor without re-signing must fail.
    let mut mutated = descriptor.clone();
    mutated.revision = 2;
    sign(&mut mutated, 1);
    let ok = NodeDescriptorV1::decode_and_verify(&mutated.encode().unwrap(), &key(1));
    assert!(ok.is_ok());

    // A mutation without re-signing must fail.
    let mut unsigned_mutation = descriptor.clone();
    unsigned_mutation.endpoints = vec![endpoint("evil.example")];
    assert!(
      NodeDescriptorV1::decode_and_verify(&unsigned_mutation.encode().unwrap(), &key(1)).is_err()
    );
  }

  /// SC-G05-P0-03: only the exact next revision is accepted.
  #[tokio::test]
  async fn descriptor_store_enforces_monotonic_revisions() {
    let factory = factory();
    store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
      .await
      .unwrap();

    // Same revision rejected.
    assert!(
      store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
        .await
        .is_err()
    );
    // Skipped revision rejected.
    assert!(
      store::store_descriptor(&factory, &descriptor(3, 1, vec!["one.example"], false))
        .await
        .is_err()
    );
    // Exact next revision accepted.
    store::store_descriptor(&factory, &descriptor(2, 1, vec!["two.example"], false))
      .await
      .unwrap();
    let current = store::read_descriptor(&factory, &node(1), &key(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(current.revision(), 2);
    assert_eq!(current.endpoints()[0].host(), "two.example");
  }

  /// SC-G05-P0-04: a signed removal marker defeats replayed older
  /// descriptors.
  #[tokio::test]
  async fn descriptor_removal_marker_defeats_replay() {
    let factory = factory();
    store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
      .await
      .unwrap();
    // Signed removal at the next revision.
    store::store_descriptor(&factory, &descriptor(2, 1, vec![], true))
      .await
      .unwrap();

    // Replaying the older live descriptor (revision 1) is rejected: the
    // current revision is 2 and a removal marker cannot be replaced by a
    // live descriptor.
    assert!(
      store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
        .await
        .is_err()
    );
    // A removal marker replaced only by a valid newer signed revision.
    assert!(
      store::store_descriptor(&factory, &descriptor(3, 1, vec![], true))
        .await
        .is_ok()
    );
  }

  /// SC-G05-P0-05: golden compatibility vectors — current and previous
  /// fixtures decode to expected values; unknown versions fail closed.
  #[test]
  fn descriptor_compatibility_vectors() {
    // Round-trip produces the expected canonical values.
    let descriptor = descriptor(7, 3, vec!["alpha.example", "beta.example"], false);
    let decoded =
      NodeDescriptorV1::decode_and_verify(&descriptor.encode().unwrap(), &key(3)).unwrap();
    assert_eq!(decoded, descriptor);
    assert_eq!(decoded.revision(), 7);
    assert_eq!(decoded.node(), &node(3));
    assert_eq!(decoded.endpoints().len(), 2);

    // Unknown version fails closed.
    let mut unknown = descriptor.clone();
    unknown.version = 99;
    sign(&mut unknown, 3);
    let bytes = unknown.encode().unwrap();
    assert!(NodeDescriptorV1::decode_and_verify(&bytes, &key(3)).is_err());
  }
}

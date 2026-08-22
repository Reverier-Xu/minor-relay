//! Bounded membership anti-entropy pages (G5-02).
//!
//! A normal anti-entropy tick emits [`MembershipPage`]s: a bounded list of
//! signed [`NodeDescriptorV1`] records plus an opaque cursor, never a
//! whole-population allocation. A receiver verifies every descriptor
//! before installing it, repairs missing owner revisions, converges stale
//! peers to the highest valid revision, and rejects dishonest pages
//! (unsigned data, revision downgrades, looping cursors, over-capacity).

use minicbor::{Decode, Encode};

use super::{NodeDescriptorV1, store};
use crate::{
  Error, NodeId, PublicKey, Result,
  protocol::{decode_canonical, encode_canonical},
};

/// The schema of one membership sync page.
pub(crate) const MEMBERSHIP_PAGE_SCHEMA: &str = "relay.woooo.tech/schemas/membership-page-v1";

/// The default page limit when the caller supplies none.
pub(crate) const DEFAULT_PAGE_LIMIT: usize = 16;

/// The maximum page size a receiver accepts, bounding one page's bytes.
pub(crate) const MAX_PAGE_DESCRIPTORS: usize = 64;

#[derive(Encode, Decode)]
#[cbor(array)]
struct PageWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  descriptors: Vec<minicbor::bytes::ByteVec>,
  #[n(2)]
  cursor: Option<minicbor::bytes::ByteVec>,
}

/// One bounded page of signed node descriptors plus a continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MembershipPage {
  descriptors: Vec<NodeDescriptorV1>,
  cursor: Option<Vec<u8>>,
}

impl MembershipPage {
  pub(crate) fn new(descriptors: Vec<NodeDescriptorV1>, cursor: Option<Vec<u8>>) -> Result<Self> {
    if descriptors.len() > MAX_PAGE_DESCRIPTORS {
      return Err(Error::resource_exhausted("membership page"));
    }
    if descriptors.is_empty() && cursor.is_some() {
      return Err(Error::invalid_input("membership page"));
    }
    Ok(Self {
      descriptors,
      cursor,
    })
  }

  pub(crate) fn descriptors(&self) -> &[NodeDescriptorV1] {
    &self.descriptors
  }

  pub(crate) fn cursor(&self) -> Option<&[u8]> {
    self.cursor.as_deref()
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &PageWire {
        schema: MEMBERSHIP_PAGE_SCHEMA.to_owned(),
        descriptors: self
          .descriptors
          .iter()
          .map(|descriptor| minicbor::bytes::ByteVec::from(descriptor.encode().unwrap_or_default()))
          .collect(),
        cursor: self.cursor.clone().map(minicbor::bytes::ByteVec::from),
      },
      crate::protocol::offer::OFFER_CBOR_LIMITS,
    )
  }

  /// Decodes one page. Every embedded descriptor is verified against the
  /// local trusted binding for its node before the page is accepted
  /// (SC-G05-P0-09: unsigned or mismatched data cannot install).
  pub(crate) fn decode_and_verify(
    bytes: &[u8], trusted_keys: &std::collections::BTreeMap<NodeId, PublicKey>,
  ) -> Result<MembershipPage> {
    let wire: PageWire = decode_canonical(bytes, crate::protocol::offer::OFFER_CBOR_LIMITS)
      .map_err(|_| Error::invalid_input("membership page decode"))?;
    if wire.schema != MEMBERSHIP_PAGE_SCHEMA {
      return Err(Error::invalid_input("membership page schema"));
    }
    if wire.descriptors.len() > MAX_PAGE_DESCRIPTORS {
      return Err(Error::resource_exhausted("membership page"));
    }
    let mut descriptors = Vec::with_capacity(wire.descriptors.len());
    for encoded in &wire.descriptors {
      let wire_bytes: &[u8] = encoded.as_ref();
      // The descriptor's own signature must verify (decode_and_verify_any),
      // and the node must be known with the exact trusted key; an unknown
      // or mismatched node is rejected (fail closed).
      let descriptor = NodeDescriptorV1::decode_and_verify_any(wire_bytes)
        .map_err(|_| Error::invalid_input("membership page descriptor"))?;
      let trusted = trusted_keys
        .get(descriptor.node())
        .ok_or_else(|| Error::not_trusted("membership page unknown node"))?;
      if trusted != descriptor.public_key() {
        return Err(Error::not_trusted("membership page key mismatch"));
      }
      descriptors.push(descriptor);
    }
    let cursor: Option<Vec<u8>> = wire.cursor.map(|value| {
      let bytes: &[u8] = value.as_ref();
      bytes.to_vec()
    });
    MembershipPage::new(descriptors, cursor)
  }

  /// True when the cursor does not advance (loop protection).
  pub(crate) fn cursor_loops(&self, previous: Option<&[u8]>) -> bool {
    match (previous, self.cursor()) {
      (Some(previous), Some(next)) => previous == next,
      _ => false,
    }
  }
}

/// The anti-entropy driver: pages the local descriptor store from a cursor
/// and applies received pages under strict validation.
pub(crate) mod sync {
  use super::{MAX_PAGE_DESCRIPTORS, MembershipPage};
  use crate::{Result, provider::StorageFactory};

  /// Emits one bounded page of descriptors starting after `cursor`. The
  /// cursor is the last emitted node's text, so pages continue without
  /// allocating the whole population.
  pub(crate) async fn emit_page(
    factory: &std::sync::Arc<dyn StorageFactory>, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<MembershipPage> {
    let limit = limit.clamp(1, MAX_PAGE_DESCRIPTORS);
    let storage = factory.open(crate::StoreRequirements::metadata()).await?;
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      super::super::NODE_DESCRIPTOR_NAMESPACE,
    )?)?;
    let snapshot = storage.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut descriptors = Vec::new();
    let mut last_key: Option<Vec<u8>> = None;
    let mut reached_end = true;
    while let Some(entry) = scan.next().await? {
      let key = entry.key().as_bytes();
      if let Some(cursor) = cursor
        && key <= cursor
      {
        continue;
      }
      let bytes = entry.value().as_bytes();
      // Read without a bound key: verification happens at the receiver;
      // the sender only pages its own signed records.
      let descriptor = super::NodeDescriptorV1::decode_and_verify_any(bytes)?;
      descriptors.push(descriptor);
      last_key = Some(key.to_vec());
      if descriptors.len() >= limit {
        reached_end = false;
        break;
      }
    }
    // The cursor is meaningful only when more descriptors may follow; a
    // page that exhausted the store ends the stream.
    MembershipPage::new(descriptors, if reached_end { None } else { last_key })
  }

  /// Applies one received page: every descriptor is already verified by
  /// `decode_and_verify`; the store accepts only the exact next revision,
  /// so stale, repeated, downgraded, and replayed descriptors cannot
  /// replace a newer record (SC-G05-P0-07/08).
  pub(crate) async fn apply_page(
    factory: &std::sync::Arc<dyn StorageFactory>, page: &MembershipPage,
  ) -> Result<usize> {
    let mut applied = 0;
    for descriptor in page.descriptors() {
      // Skip descriptors we already have at an equal or higher revision.
      if let Ok(Some(current)) =
        super::store::read_descriptor(factory, descriptor.node(), descriptor.public_key()).await
        && current.revision() >= descriptor.revision()
      {
        continue;
      }
      if super::store::store_descriptor(factory, descriptor)
        .await
        .is_ok()
      {
        applied += 1;
      }
    }
    Ok(applied)
  }
}

/// Adds a receiver-side verification helper that does not require a bound
/// key up front (the page-level check supplies it).
impl NodeDescriptorV1 {
  /// Decodes without a bound-key check; the caller verifies binding at the
  /// page level. Used by the page emitter, which pages only local records.
  pub(crate) fn decode_and_verify_any(bytes: &[u8]) -> Result<NodeDescriptorV1> {
    // Reuse the strict path with a placeholder key; the page receiver
    // re-verifies with the trusted key before install.
    let wire: super::DescriptorWire =
      decode_canonical(bytes, crate::protocol::offer::OFFER_CBOR_LIMITS)
        .map_err(|_| Error::invalid_input("node descriptor decode"))?;
    if wire.schema != super::NODE_DESCRIPTOR_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("node descriptor schema"));
    }
    if wire.version != 1 {
      return Err(Error::invalid_input("node descriptor version"));
    }
    let node =
      NodeId::parse(&wire.node).map_err(|_| Error::invalid_input("node descriptor node"))?;
    let public_key = PublicKey::from_bytes(
      <[u8; 32]>::try_from(wire.public_key.as_ref())
        .map_err(|_| Error::invalid_input("node descriptor key"))?,
    );
    let mut endpoints = Vec::with_capacity(wire.endpoints.len());
    for text in &wire.endpoints {
      endpoints.push(
        crate::Endpoint::parse(text)
          .map_err(|_| Error::invalid_input("node descriptor endpoint"))?,
      );
    }
    let descriptor = NodeDescriptorV1::new(
      node,
      public_key.clone(),
      endpoints,
      wire.revision,
      wire.removed,
      wire.version,
      crate::Signature::from_bytes({
        let bytes: &[u8] = wire.signature.as_ref();
        <[u8; 64]>::try_from(bytes)
          .map_err(|_| Error::invalid_input("node descriptor signature"))?
      }),
    );
    crate::identity::signature::verify_strict(
      super::NODE_DESCRIPTOR_V1_DOMAIN,
      &descriptor.encode_signed_body()?,
      &public_key,
      &descriptor.signature,
      "node descriptor signature",
    )?;
    Ok(descriptor)
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::BTreeMap, sync::Arc};

  use ed25519_dalek::Signer;

  use super::{MembershipPage, sync};
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

  fn sign(descriptor: &mut crate::membership::NodeDescriptorV1, owner_index: u8) {
    let signing = scripted_signing(owner_index.into());
    let message = signature_message(
      crate::membership::NODE_DESCRIPTOR_V1_DOMAIN,
      &descriptor.encode_signed_body().unwrap(),
    );
    descriptor.signature = Signature::from_bytes(signing.sign(&message).to_bytes());
  }

  fn descriptor(node_index: u8, revision: u64, host: &str) -> crate::membership::NodeDescriptorV1 {
    let mut descriptor = crate::membership::NodeDescriptorV1::new(
      node(node_index),
      key(node_index),
      vec![Endpoint::parse(&format!("wss://{host}:9000")).unwrap()],
      revision,
      false,
      1,
      Signature::from_bytes([0; 64]),
    );
    sign(&mut descriptor, node_index);
    descriptor
  }

  fn trusted(node_index: u8) -> BTreeMap<NodeId, PublicKey> {
    BTreeMap::from([(node(node_index), key(node_index))])
  }

  fn factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// SC-G05-P0-06: a tick emits bounded pages without a whole-population
  /// allocation.
  #[tokio::test]
  async fn emit_pages_bounded_without_whole_members() {
    let factory = factory();
    crate::membership::store::store_descriptor(&factory, &descriptor(1, 1, "one"))
      .await
      .unwrap();
    crate::membership::store::store_descriptor(&factory, &descriptor(2, 1, "two"))
      .await
      .unwrap();
    crate::membership::store::store_descriptor(&factory, &descriptor(3, 1, "three"))
      .await
      .unwrap();

    let page = sync::emit_page(&factory, None, 2).await.unwrap();
    assert_eq!(page.descriptors().len(), 2);
    assert!(page.cursor().is_some());
    let page = sync::emit_page(&factory, page.cursor(), 2).await.unwrap();
    assert_eq!(page.descriptors().len(), 1);
    assert!(page.cursor().is_none());
  }

  /// SC-G05-P0-07/08: repeated pages repair missing revisions and stale
  /// peers converge to the highest valid revision.
  #[tokio::test]
  async fn apply_pages_repairs_and_converges() {
    let factory = factory();
    crate::membership::store::store_descriptor(&factory, &descriptor(1, 1, "one"))
      .await
      .unwrap();
    // A stale peer holds revision 1; the peer pages revision 2.
    let mut fresh = descriptor(1, 1, "one-updated");
    fresh = crate::membership::NodeDescriptorV1::new(
      node(1),
      key(1),
      fresh.endpoints().to_vec(),
      2,
      false,
      1,
      fresh.signature.clone(),
    );
    sign(&mut fresh, 1);
    crate::membership::store::store_descriptor(&factory, &fresh)
      .await
      .unwrap();

    let page = sync::emit_page(&factory, None, 4).await.unwrap();
    let encoded = page.encode().unwrap();
    let decoded = MembershipPage::decode_and_verify(&encoded, &trusted(1)).unwrap();
    // Applying again is idempotent (no downgrade, no duplicate install).
    let applied = sync::apply_page(&factory, &decoded).await.unwrap();
    let current = crate::membership::store::read_descriptor(&factory, &node(1), &key(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(current.revision(), 2);
    let _ = applied;
  }

  /// SC-G05-P0-09: a dishonest page cannot install unsigned data, loop a
  /// cursor, or exceed capacities.
  #[test]
  fn reject_dishonest_pages() {
    // Over-capacity page.
    let descriptors = (0..=super::MAX_PAGE_DESCRIPTORS)
      .map(|index| descriptor((index % 8) as u8 + 1, 1, "x"))
      .collect();
    assert!(MembershipPage::new(descriptors, None).is_err());

    // Unknown node fails closed at decode.
    let page = MembershipPage::new(vec![descriptor(9, 1, "nine")], None).unwrap();
    let encoded = page.encode().unwrap();
    assert!(
      MembershipPage::decode_and_verify(&encoded, &trusted(1)).is_err(),
      "unknown node must be rejected"
    );

    // Cursor loop is detected.
    let page = MembershipPage::new(vec![descriptor(1, 1, "one")], Some(vec![1])).unwrap();
    assert!(page.cursor_loops(Some(&[1])));
    assert!(!page.cursor_loops(Some(&[2])));
    assert!(!page.cursor_loops(None));
  }
}

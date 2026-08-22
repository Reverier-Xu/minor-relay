//! Session-carried membership sync (G5-05/06 wiring).
//!
//! An authenticated session carries two bounded sync payloads in one
//! direction: a [`MembershipPage`] of signed node descriptors and the
//! issuer-signed [`TrustSnapshotV1`] grant set. The receiver verifies
//! every payload at its own strict surface before installing anything:
//! descriptors must match the trusted bindings (SC-G05-P0-09), and a
//! snapshot must verify against the cluster creator, the trusted issuer
//! (the grant-carrying reconnect path). The issuer refreshes its snapshot
//! when its admitted binding set changes, and every member pages its local
//! descriptors, so reciprocal trust, exact descriptors, and topology
//! converge over the same authenticated sessions the facade observes.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  ClusterId, Error, IncomingPacket, NodeId, PacketBody, ProtocolTag, PublicKey, Result, TraceId,
  api::{BoxFuture, Entropy},
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::{
    genesis::existing_cluster,
    lifecycle::LocalIdentityContext,
    signature::signature_message,
    trust::{TrustBinding, TrustSnapshotV1, store as trust_store},
  },
  membership::page::{MembershipPage, sync as page_sync},
  protocol::{decode_canonical, encode_canonical},
  provider::KeyProvider,
  runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The canonical protocol tag of the membership sync stream.
pub(crate) const MEMBERSHIP_SYNC_PROTOCOL: &str = "relay.woooo.tech/protocols/membership-sync";

/// The wire schema of one sync payload.
const SYNC_PAYLOAD_SCHEMA: &str = "relay.woooo.tech/schemas/membership-sync-payload-v1";

/// Payload kinds: a membership page of descriptors, or an issuer-signed
/// trust snapshot (grant set).
pub(crate) const SYNC_KIND_PAGE: u8 = 1;
pub(crate) const SYNC_KIND_SNAPSHOT: u8 = 2;

/// The receiver-side body cap: one page is at most
/// [`super::page::MAX_PAGE_DESCRIPTORS`] descriptors and one snapshot is
/// a bounded binding list, so a generous but finite byte budget bounds a
/// malicious stream (SC-G05-P0-09).
const MAX_SYNC_BYTES: usize = 256 * 1_024;
const MAX_SYNC_CHUNKS: usize = 4_096;

/// One sync payload: an encoded membership page or an encoded issuer-signed
/// trust snapshot. Signatures are verified at the payload-specific surface
/// immediately before install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SyncPayload {
  /// An encoded [`MembershipPage`].
  Page(ByteVec),
  /// An encoded [`TrustSnapshotV1`].
  Snapshot(ByteVec),
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct SyncPayloadWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  kind: u8,
  #[n(2)]
  payload: ByteVec,
}

impl SyncPayload {
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    let (kind, payload) = match self {
      Self::Page(encoded) => (SYNC_KIND_PAGE, encoded.clone()),
      Self::Snapshot(encoded) => (SYNC_KIND_SNAPSHOT, encoded.clone()),
    };
    encode_canonical(
      &SyncPayloadWire {
        schema: SYNC_PAYLOAD_SCHEMA.to_owned(),
        kind,
        payload,
      },
      crate::protocol::offer::OFFER_CBOR_LIMITS,
    )
  }

  /// Decodes one payload, rejecting unknown schemas and kinds (fail
  /// closed).
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: SyncPayloadWire = decode_canonical(bytes, crate::protocol::offer::OFFER_CBOR_LIMITS)
      .map_err(|_| Error::invalid_input("membership sync payload"))?;
    if wire.schema != SYNC_PAYLOAD_SCHEMA {
      return Err(Error::invalid_input("membership sync payload schema"));
    }
    match wire.kind {
      SYNC_KIND_PAGE => Ok(Self::Page(wire.payload)),
      SYNC_KIND_SNAPSHOT => Ok(Self::Snapshot(wire.payload)),
      _ => Err(Error::invalid_input("membership sync payload kind")),
    }
  }
}

/// The core receiver of membership sync streams over authenticated
/// sessions. Every page descriptor is verified against the local trusted
/// bindings before install; every snapshot is verified against the cluster
/// creator before its bindings are adopted into the identity store
/// (SC-G05-P0-09, the grant-carrying reconnect path).
#[derive(Debug)]
pub(crate) struct MembershipSyncConsumer {
  // Held weakly so the registry shared with a live node handle never pins
  // the node's metadata store after shutdown; a packet arriving after the
  // runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn Entropy>,
}

impl MembershipSyncConsumer {
  pub(crate) fn new(context: Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>) -> Self {
    Self {
      context: Arc::downgrade(&context),
      entropy,
    }
  }
}

impl PacketConsumer for MembershipSyncConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingPacket) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let bytes = drain_body(packet.body()).await?;
      let payload = SyncPayload::decode(&bytes)?;
      let context = self
        .context
        .upgrade()
        .ok_or_else(|| Error::shutting_down("membership sync"))?;
      accept_payload(&context, self.entropy.clone(), &payload).await
    })
  }
}

async fn accept_payload(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>, payload: &SyncPayload,
) -> Result<()> {
  let store = context.store();
  match payload {
    SyncPayload::Page(encoded) => {
      let trusted = trust_store::trusted_bindings(store).await?;
      let page = MembershipPage::decode_and_verify(encoded.as_ref(), &trusted)?;
      let _ = page_sync::apply_page_ctx(store, entropy.as_ref(), &page).await?;
    }
    SyncPayload::Snapshot(encoded) => {
      let (cluster, issuer, issuer_key) = resolve_trusted_anchor(context).await?;
      let snapshot =
        TrustSnapshotV1::decode_and_verify(encoded.as_ref(), &cluster, &issuer, &issuer_key)?;
      trust_store::persist_snapshot_ctx(store, entropy.as_ref(), &snapshot).await?;
      // Binding adoption is best effort per record: a transient store
      // contention on one binding must not abort the remaining bindings of
      // the snapshot; the next delivery retries what was skipped
      // (anti-entropy repair, SC-G05-P0-07).
      for binding in snapshot.bindings() {
        if let Err(error) =
          trust_store::persist_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
            .await
        {
          tracing::debug!(node = %binding.node(), kind = ?error.kind(), "trust binding persist skipped");
          continue;
        }
        let _ =
          trust_store::adopt_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
            .await;
      }
    }
  }
  Ok(())
}

/// Reads one complete bounded body from an admitted sync stream.
async fn drain_body(body: &mut dyn PacketBody) -> Result<Vec<u8>> {
  let mut bytes = Vec::new();
  let mut chunks: usize = 0;
  while let Some(chunk) = body.next_chunk().await? {
    chunks = chunks.saturating_add(1);
    if chunks > MAX_SYNC_CHUNKS || bytes.len().saturating_add(chunk.len()) > MAX_SYNC_BYTES {
      return Err(Error::resource_exhausted("membership sync body"));
    }
    bytes.extend_from_slice(&chunk);
  }
  Ok(bytes)
}

/// The protocol definition that gates the sync stream on authenticated
/// sessions: owned by the data-messages feature both sides select.
pub(crate) fn sync_protocol_definition() -> Result<ProtocolDefinition> {
  Ok(ProtocolDefinition::new(
    ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?,
    crate::FeatureTag::parse(crate::protocol::feature::DATA_MESSAGES)?,
  ))
}

/// Ensures the local signed descriptor exists (revision 1) with the given
/// endpoint candidates, so the anti-entropy tick can page it. Publishes a
/// revision bump when the endpoint set changes and the caller requests it.
pub(crate) async fn ensure_local_descriptor(
  context: &Arc<LocalIdentityContext>, keys: &Arc<dyn KeyProvider>, entropy: &Arc<dyn Entropy>,
  endpoints: Vec<crate::Endpoint>,
) -> Result<()> {
  let store = context.store();
  let node = context.identity().node().clone();
  let public_key = context.identity().public_key().clone();
  let existing = crate::membership::store::read_descriptor_ctx(store, &node, &public_key).await?;
  if let Some(current) = &existing {
    let same_endpoints = current.endpoints().len() == endpoints.len()
      && current
        .endpoints()
        .iter()
        .zip(&endpoints)
        .all(|(left, right)| left == right);
    if same_endpoints {
      return Ok(());
    }
    // An empty candidate set never downgrades published endpoints: the
    // startup tick fires before any listener exists and must not bump the
    // revision (SC-G05-P0-28 endpoint stability).
    if endpoints.is_empty() {
      return Ok(());
    }
  }
  let revision = existing
    .as_ref()
    .map_or(1, |current| current.revision().saturating_add(1));
  let mut descriptor = crate::membership::NodeDescriptorV1::new(
    node,
    public_key,
    endpoints,
    revision,
    false,
    1,
    crate::Signature::from_bytes([0; 64]),
  );
  let handle = context.identity().handle().clone();
  let message = crate::identity::signature::signature_message(
    crate::membership::NODE_DESCRIPTOR_V1_DOMAIN,
    &descriptor.encode_signed_body()?,
  );
  let signature = keys.sign(&handle, &message).await?;
  descriptor.set_signature(signature);
  crate::membership::store::store_descriptor_ctx(store, entropy.as_ref(), &descriptor).await?;
  Ok(())
}

/// The local highest verified issuer snapshot, resolved through the
/// trusted issuer anchor (the cluster creator, or the member's admission
/// grant issuer).
pub(crate) async fn local_latest_snapshot(
  context: &Arc<LocalIdentityContext>,
) -> Result<Option<TrustSnapshotV1>> {
  let (cluster, issuer, issuer_key) = resolve_trusted_anchor(context).await?;
  trust_store::latest_snapshot_ctx(context.store(), &cluster, &issuer, &issuer_key).await
}

/// Resolves the trusted issuer anchor: the cluster creator when the full
/// genesis is present, otherwise the issuer of this node's own admission
/// grant. Cluster/pointer corruption surfaces as a typed error instead of
/// being mistaken for "not the creator".
async fn resolve_trusted_anchor(
  context: &Arc<LocalIdentityContext>,
) -> Result<(ClusterId, NodeId, PublicKey)> {
  let store = context.store();
  // A member holds a cluster pointer but no genesis record, so
  // `existing_cluster` reports the missing genesis as corruption; either
  // outcome falls through to the member's admission-grant anchor (the
  // authoritative trusted-issuer resolution for members). Only the
  // creator holds the full genesis.
  if let Ok(Some(genesis)) = existing_cluster(context).await {
    return Ok((
      genesis.cluster().clone(),
      genesis.creator().clone(),
      genesis.creator_key().clone(),
    ));
  }
  let local = context.identity().node().clone();
  let (issuer, key) = trust_store::trusted_issuer(store, &local)
    .await?
    .ok_or_else(|| Error::not_ready("local cluster"))?;
  let cluster = crate::identity::genesis::local_cluster(context)
    .await?
    .ok_or_else(|| Error::not_ready("local cluster"))?
    .cluster()
    .clone();
  Ok((cluster, issuer, key))
}

/// The issuer refreshes its trust snapshot when its admitted binding set
/// changed: enumerate the durable bindings, sign revision `latest + 1`,
/// and persist. Non-creators are a no-op. Returns the latest snapshot.
pub(crate) async fn refresh_issuer_snapshot(
  context: &Arc<LocalIdentityContext>, keys: &Arc<dyn KeyProvider>, entropy: &Arc<dyn Entropy>,
) -> Result<Option<TrustSnapshotV1>> {
  let store = context.store();
  // A member holds a cluster pointer but no genesis record, so
  // `existing_cluster` reports the missing genesis as corruption; either
  // way only the cluster creator refreshes the snapshot.
  let genesis = match existing_cluster(context).await {
    Ok(Some(genesis)) => genesis,
    Ok(None) | Err(_) => return Ok(None),
  };
  if genesis.creator() != context.identity().node() {
    return Ok(None);
  }
  let bindings = trust_store::trusted_bindings(store).await?;
  let current: Vec<TrustBinding> = bindings
    .into_iter()
    .map(|(node, key)| TrustBinding::new(node, key))
    .collect();
  let latest = trust_store::latest_snapshot_ctx(
    store,
    genesis.cluster(),
    genesis.creator(),
    genesis.creator_key(),
  )
  .await?;
  if let Some(latest) = latest {
    if latest.bindings() == current.as_slice() {
      return Ok(Some(latest));
    }
    let revision = latest.revision().saturating_add(1);
    let snapshot = sign_snapshot(context, keys, &genesis, current, revision).await?;
    persist_snapshot_with_bindings(store, entropy, &snapshot).await?;
    return Ok(Some(snapshot));
  }
  let snapshot = sign_snapshot(context, keys, &genesis, current, 1).await?;
  persist_snapshot_with_bindings(store, entropy, &snapshot).await?;
  Ok(Some(snapshot))
}

/// Persists one verified snapshot plus its binding observations, so the
/// issuer's own trust page and every receiver's page expose the exact
/// binding set (SC-G05-P0-25).
async fn persist_snapshot_with_bindings(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>, snapshot: &TrustSnapshotV1,
) -> Result<()> {
  trust_store::persist_snapshot_ctx(store, entropy.as_ref(), snapshot).await?;
  for binding in snapshot.bindings() {
    trust_store::persist_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
      .await?;
  }
  Ok(())
}

async fn sign_snapshot(
  context: &Arc<LocalIdentityContext>, keys: &Arc<dyn KeyProvider>,
  genesis: &crate::identity::records::ClusterGenesisV1, bindings: Vec<TrustBinding>, revision: u64,
) -> Result<TrustSnapshotV1> {
  let mut snapshot = TrustSnapshotV1::new(
    genesis.cluster().clone(),
    revision,
    1,
    genesis.creator().clone(),
    genesis.creator_key().clone(),
    bindings,
    crate::Signature::from_bytes([0; 64]),
  );
  let handle = context.identity().handle().clone();
  let message = signature_message(
    crate::identity::trust::TRUST_SNAPSHOT_V1_DOMAIN,
    &snapshot.encode_signed_body()?,
  );
  let signature = keys.sign(&handle, &message).await?;
  snapshot.set_signature(signature);
  Ok(snapshot)
}

/// One anti-entropy tick: publish the local descriptor, refresh the issuer
/// snapshot when this node is the creator, and push a bounded page plus the
/// latest snapshot over every authenticated session. The work per tick is
/// bounded: one page and one snapshot per session, nothing paged to
/// exhaustion (SC-G05-P0-06).
/// The driver's per-node anti-entropy continuation state.
#[derive(Default)]
pub(crate) struct SyncCursor {
  /// The last snapshot revision sent, so unchanged grant sets are not
  /// re-sent every tick.
  pub(crate) snapshot_rev: u64,
  /// The last membership page cursor, so descriptor sync continues across
  /// ticks and converges beyond a single page.
  pub(crate) page: Option<Vec<u8>>,
}

pub(crate) async fn sync_tick(
  context: &Arc<LocalIdentityContext>, keys: &Arc<dyn KeyProvider>, entropy: &Arc<dyn Entropy>,
  sessions: &SessionTable, runtime: &RuntimeClient, local_endpoints: &[crate::Endpoint],
  cursor: &mut SyncCursor,
) -> Result<()> {
  let store = context.store();
  // Nothing to advertise at startup: the supervisor publishes the local
  // descriptor (with endpoints) when a query or listener first needs it,
  // so the anti-entropy loop never races a transient empty endpoint set
  // into a revision bump.
  if !local_endpoints.is_empty() {
    ensure_local_descriptor(context, keys, entropy, local_endpoints.to_vec()).await?;
  }
  // Before any member is admitted the node's store writes are quiescent
  // (the supervisor's lazy paths publish the local descriptor on the first
  // public query), keeping the admission commit sequence deterministic for
  // fault-injecting providers.
  let members = trust_store::trusted_bindings(store).await?;
  let has_members = members.len() > 1;
  if !has_members {
    let page = page_sync::emit_page_ctx(
      store,
      cursor.page.as_deref(),
      crate::membership::page::DEFAULT_PAGE_LIMIT,
    )
    .await?;
    cursor.page = page.cursor().map(|value| value.to_vec());
    let page_payload = SyncPayload::Page(ByteVec::from(page.encode()?));
    let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
    let peers: Vec<NodeId> = sessions
      .lock()
      .map_err(|_| Error::internal("session table"))?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    for peer in peers {
      let _ = send_payload(runtime, entropy, &peer, &protocol, &page_payload).await;
    }
    return Ok(());
  }
  let snapshot = match refresh_issuer_snapshot(context, keys, entropy).await? {
    Some(snapshot) => Some(snapshot),
    // A member relays the highest verified issuer snapshot it holds, so
    // the grant set propagates across the sparse topology even when the
    // issuer's direct sessions are not the whole mesh (SC-G05-P0-25).
    None => local_latest_snapshot(context).await?,
  };
  let page = page_sync::emit_page_ctx(
    store,
    cursor.page.as_deref(),
    crate::membership::page::DEFAULT_PAGE_LIMIT,
  )
  .await?;
  cursor.page = page.cursor().map(|value| value.to_vec());
  let page_payload = SyncPayload::Page(ByteVec::from(page.encode()?));
  // A snapshot is sent only when its revision advanced: the grant set is
  // unchanged most ticks, and re-sending the same revision to every
  // session every tick floods the store with idempotent commits.
  let snapshot_payload = match snapshot {
    Some(snapshot) if snapshot.revision() != cursor.snapshot_rev => {
      cursor.snapshot_rev = snapshot.revision();
      Some(SyncPayload::Snapshot(ByteVec::from(snapshot.encode()?)))
    }
    _ => None,
  };
  let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
  let peers: Vec<NodeId> = sessions
    .lock()
    .map_err(|_| Error::internal("session table"))?
    .iter()
    .filter(|(_, entry)| entry.alive())
    .map(|(peer, _)| peer.clone())
    .collect();
  for peer in peers {
    if let Some(payload) = &snapshot_payload {
      let _ = send_payload(runtime, entropy, &peer, &protocol, payload).await;
    }
    let _ = send_payload(runtime, entropy, &peer, &protocol, &page_payload).await;
  }
  Ok(())
}

/// Sends one sync payload to `peer` over its authenticated session with a
/// fire-and-forget admission: routing failures are dropped (the next tick
/// retries) and never stall the anti-entropy loop.
async fn send_payload(
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, peer: &NodeId, protocol: &ProtocolTag,
  payload: &SyncPayload,
) -> Result<()> {
  let trace_id = TraceId::generate(entropy.as_ref())?;
  let body = Box::new(crate::packet::StaticBody::new(Arc::from(payload.encode()?)));
  let (ack_notify, _ack) = tokio::sync::oneshot::channel();
  let request = crate::packet::OutboundRequest {
    trace_id,
    destination: peer.clone(),
    protocol: protocol.clone(),
    metadata: crate::packet::PacketMetadata::new(),
    body,
    ack_notify,
  };
  // Fire-and-forget: the admission ack (or its absence) is retried by the
  // next tick; a full routing queue drops the payload without blocking.
  runtime.try_send_packet(request)
}

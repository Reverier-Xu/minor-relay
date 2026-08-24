//! Session-carried membership sync (G5-05/06 wiring).
//!
//! An authenticated session carries two bounded sync payloads in one
//! direction: a [`MembershipPage`] of node descriptors and the issuer
//! [`TrustSnapshotV1`] grant set. Entries are trusted through the
//! authenticated session that delivered them (ADR-0008); decoding checks
//! only canonical wire rules and bounded capacities. The issuer refreshes
//! its snapshot when its admitted binding set changes, and every member
//! pages its local descriptors, so reciprocal trust, exact descriptors,
//! and topology converge over the same authenticated sessions the facade
//! observes.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  ClusterId, Error, IncomingPacket, NodeId, PacketBody, ProtocolTag, Result, TraceId,
  api::{BoxFuture, Entropy},
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::{
    genesis::existing_cluster,
    lifecycle::LocalIdentityContext,
    trust::{TrustBinding, TrustSnapshotV1, store as trust_store},
  },
  membership::page::{MembershipPage, sync as page_sync},
  protocol::{decode_canonical, encode_canonical},
  runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The canonical protocol tag of the membership sync stream.
pub(crate) const MEMBERSHIP_SYNC_PROTOCOL: &str = "relay.woooo.tech/protocols/membership-sync";

/// The wire schema of one sync payload.
const SYNC_PAYLOAD_SCHEMA: &str = "relay.woooo.tech/schemas/membership-sync-payload-v1";

/// Payload kinds: a membership page of descriptors, or an issuer trust
/// snapshot (grant set).
pub(crate) const SYNC_KIND_PAGE: u8 = 1;
pub(crate) const SYNC_KIND_SNAPSHOT: u8 = 2;

/// The receiver-side body cap: one page is at most
/// [`super::page::MAX_PAGE_DESCRIPTORS`] descriptors and one snapshot is
/// a bounded binding list, so a generous but finite byte budget bounds a
/// malicious stream (SC-G05-P0-09).
const MAX_SYNC_BYTES: usize = 256 * 1_024;
const MAX_SYNC_CHUNKS: usize = 4_096;

/// One sync payload: an encoded membership page or an encoded issuer
/// trust snapshot.
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
/// sessions. Entries are trusted through the session that delivered them
/// (ADR-0008); decoding enforces canonical wire rules and bounded
/// capacities before install.
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
      let page = MembershipPage::decode(encoded.as_ref())?;
      let _ = page_sync::apply_page_ctx(store, entropy.as_ref(), &page).await?;
    }
    SyncPayload::Snapshot(encoded) => {
      let snapshot = TrustSnapshotV1::decode(encoded.as_ref())?;
      // A snapshot for another cluster marking cannot apply here: one
      // node belongs to exactly one cluster, resolved from local state.
      let cluster = crate::identity::genesis::local_cluster(context)
        .await?
        .ok_or_else(|| Error::not_ready("local cluster"))?
        .cluster()
        .clone();
      if snapshot.cluster() != &cluster {
        return Err(Error::not_trusted("trust snapshot cluster"));
      }
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

/// Ensures the local descriptor exists (revision 1) with the given
/// endpoint candidates, so the anti-entropy tick can page it. Publishes a
/// revision bump when the endpoint set changes and the caller requests it.
pub(crate) async fn ensure_local_descriptor(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, endpoints: Vec<crate::Endpoint>,
) -> Result<()> {
  let store = context.store();
  let node = context.identity().node().clone();
  let public_key = context.identity().public_key().clone();
  let existing = crate::membership::store::read_descriptor_ctx(store, &node).await?;
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
    // revision (descriptor endpoint stability, SC-G05-P0-25).
    if endpoints.is_empty() {
      return Ok(());
    }
  }
  let revision = existing
    .as_ref()
    .map_or(1, |current| current.revision().saturating_add(1));
  let descriptor =
    crate::membership::NodeDescriptorV1::new(node, public_key, endpoints, revision, false, 1);
  crate::membership::store::store_descriptor_ctx(store, entropy.as_ref(), &descriptor).await?;
  Ok(())
}

/// The local latest issuer snapshot for this cluster. The issuer is
/// resolved through the trusted anchor (the cluster creator, or the
/// member's admission grant issuer).
pub(crate) async fn local_latest_snapshot(
  context: &Arc<LocalIdentityContext>,
) -> Result<Option<TrustSnapshotV1>> {
  let (_, issuer) = resolve_trusted_anchor(context).await?;
  trust_store::latest_snapshot_ctx(context.store(), &issuer).await
}

/// Resolves the trusted issuer anchor: the cluster creator when the full
/// genesis is present, otherwise the issuer of this node's own admission
/// grant. Cluster/pointer corruption surfaces as a typed error instead of
/// being mistaken for "not the creator".
async fn resolve_trusted_anchor(
  context: &Arc<LocalIdentityContext>,
) -> Result<(ClusterId, NodeId)> {
  let store = context.store();
  // A member holds a cluster pointer but no genesis record, so
  // `existing_cluster` reports the missing genesis as corruption; either
  // outcome falls through to the member's admission-grant anchor (the
  // authoritative trusted-issuer resolution for members). Only the
  // creator holds the full genesis.
  if let Ok(Some(genesis)) = existing_cluster(context).await {
    return Ok((genesis.cluster().clone(), genesis.creator().clone()));
  }
  let local = context.identity().node().clone();
  let (issuer, _key) = trust_store::trusted_issuer(store, &local)
    .await?
    .ok_or_else(|| Error::not_ready("local cluster"))?;
  let cluster = crate::identity::genesis::local_cluster(context)
    .await?
    .ok_or_else(|| Error::not_ready("local cluster"))?
    .cluster()
    .clone();
  Ok((cluster, issuer))
}

/// The issuer refreshes its trust snapshot when its admitted binding set
/// changed: enumerate the durable bindings at revision `latest + 1` and
/// persist. Non-creators are a no-op. Returns the latest snapshot.
pub(crate) async fn refresh_issuer_snapshot(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
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
  // Cheap short-circuit: bindings are append-only between admissions, so
  // an unchanged count means an unchanged grant set; the full enumeration
  // runs only when an admission may have added one.
  let latest = trust_store::latest_snapshot_ctx(store, genesis.creator()).await?;
  if let Some(latest) = &latest
    && !trust_store::has_more_than_bindings(store, latest.bindings().len()).await?
  {
    return Ok(Some(latest.clone()));
  }
  let bindings = trust_store::trusted_bindings(store).await?;
  let current: Vec<TrustBinding> = bindings
    .into_iter()
    .map(|(node, key)| TrustBinding::new(node, key))
    .collect();
  let revision = match &latest {
    Some(latest) if latest.bindings() != current.as_slice() => latest.revision().saturating_add(1),
    Some(latest) => return Ok(Some(latest.clone())),
    None => 1,
  };
  let snapshot = TrustSnapshotV1::new(
    genesis.cluster().clone(),
    revision,
    1,
    genesis.creator().clone(),
    genesis.creator_key().clone(),
    current,
  );
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
  /// Ticks since the last snapshot send: a lost delivery must be retried
  /// without waiting for the next grant-set change.
  pub(crate) ticks_since_snapshot_send: u32,
  /// Fingerprint of the last page sent, so an unchanged membership set
  /// costs no encode or per-peer delivery at all.
  pub(crate) page_fingerprint: u64,
  /// Fingerprint of the alive-peer set: a newly connected peer must
  /// receive the current pages immediately, changed set or not.
  pub(crate) peers_fingerprint: u64,
  /// Ticks since the last page send: a lost delivery must be retried on
  /// a slow cadence even when nothing changed.
  pub(crate) ticks_since_page_send: u32,
  /// The last membership page cursor, so descriptor sync continues across
  /// ticks and converges beyond a single page.
  pub(crate) page: Option<Vec<u8>>,
}

/// Snapshot deliveries are retried on this slow cadence even when the
/// grant set is unchanged, so a dropped payload heals instead of stalling
/// a peer forever (anti-entropy, SC-G05-P0-07).
const SNAPSHOT_RESEND_TICKS: u32 = 8;
/// Page deliveries are retried on this slower cadence for the same reason.
const PAGE_RESEND_TICKS: u32 = 32;

pub(crate) async fn sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, sessions: &SessionTable,
  runtime: &RuntimeClient, local_endpoints: &[crate::Endpoint], cursor: &mut SyncCursor,
) -> Result<()> {
  let store = context.store();
  // Nothing to advertise at startup: the supervisor publishes the local
  // descriptor (with endpoints) when a query or listener first needs it,
  // so the anti-entropy loop never races a transient empty endpoint set
  // into a revision bump.
  if !local_endpoints.is_empty() {
    ensure_local_descriptor(context, entropy, local_endpoints.to_vec()).await?;
  }
  // Before any member is admitted the node's store writes are quiescent
  // (the supervisor's lazy paths publish the local descriptor on the first
  // public query), keeping the admission commit sequence deterministic for
  // fault-injecting providers.
  // Cheap membership probe: an early-exit bounded read instead of a
  // whole-population map on every tick.
  let has_members = trust_store::has_more_than_bindings(store, 1).await?;
  if !has_members {
    // No membership yet: no descriptors exist to anti-entropize.
    return Ok(());
  }
  let snapshot = match refresh_issuer_snapshot(context, entropy).await? {
    Some(snapshot) => Some(snapshot),
    // A member relays the highest verified issuer snapshot it holds, so
    // the grant set propagates across the sparse topology even when the
    // issuer's direct sessions are not the whole mesh (SC-G05-P0-25).
    None => local_latest_snapshot(context).await?,
  };
  let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
  let peers = alive_peers(sessions)?;
  let peers_fp = peers_fingerprint(&peers);
  let page = page_sync::emit_page_ctx(
    store,
    cursor.page.as_deref(),
    crate::membership::page::DEFAULT_PAGE_LIMIT,
  )
  .await?;
  cursor.page = page.cursor().map(|value| value.to_vec());
  let page_payload = SyncPayload::Page(ByteVec::from(page.encode()?));
  // A page is sent when its content or the alive-peer set changed, and
  // retried on a slow cadence otherwise (lost-delivery healing,
  // SC-G05-P0-07); an unchanged steady state costs no sends at all.
  let page_fp = page.fingerprint();
  let page_due = page_fp != cursor.page_fingerprint
    || peers_fp != cursor.peers_fingerprint
    || cursor.ticks_since_page_send >= PAGE_RESEND_TICKS;
  cursor.page_fingerprint = page_fp;
  cursor.peers_fingerprint = peers_fp;
  // A snapshot is sent when its revision advanced, and retried on a slow
  // cadence even when unchanged: re-sending the same revision to every
  // session every tick floods the store with idempotent commits, but a
  // lost delivery must still heal (SC-G05-P0-07).
  let snapshot_payload = match &snapshot {
    Some(snapshot)
      if snapshot.revision() != cursor.snapshot_rev
        || cursor.ticks_since_snapshot_send >= SNAPSHOT_RESEND_TICKS =>
    {
      cursor.snapshot_rev = snapshot.revision();
      cursor.ticks_since_snapshot_send = 0;
      Some(SyncPayload::Snapshot(ByteVec::from(snapshot.encode()?)))
    }
    Some(_) => {
      cursor.ticks_since_snapshot_send = cursor.ticks_since_snapshot_send.saturating_add(1);
      None
    }
    None => None,
  };
  if page_due {
    cursor.ticks_since_page_send = 0;
    for peer in &peers {
      if let Some(payload) = &snapshot_payload {
        let _ = send_payload(runtime, entropy, peer, &protocol, payload).await;
      }
      let _ = send_payload(runtime, entropy, peer, &protocol, &page_payload).await;
    }
    return Ok(());
  }
  cursor.ticks_since_page_send = cursor.ticks_since_page_send.saturating_add(1);
  if let Some(payload) = &snapshot_payload {
    for peer in &peers {
      let _ = send_payload(runtime, entropy, peer, &protocol, payload).await;
    }
  }
  Ok(())
}

/// The alive-peer set of one node, in stable order.
fn alive_peers(sessions: &SessionTable) -> Result<Vec<NodeId>> {
  let guard = sessions
    .lock()
    .map_err(|_| Error::internal("session table"))?;
  Ok(
    guard
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect(),
  )
}

/// A stable order-independent fingerprint of the alive-peer set.
fn peers_fingerprint(peers: &[NodeId]) -> u64 {
  use std::hash::{Hash, Hasher};
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  peers.len().hash(&mut hasher);
  for peer in peers {
    peer.hash(&mut hasher);
  }
  hasher.finish()
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
    target: crate::PacketTarget::Exact(peer.clone()),
    load_balancer: None,
    max_hops: 1,
    protocol: protocol.clone(),
    metadata: crate::packet::PacketMetadata::new(),
    body,
    ack_notify,
  };
  // Fire-and-forget: the admission ack (or its absence) is retried by the
  // next tick; a full routing queue drops the payload without blocking.
  runtime.try_send_packet(request)
}

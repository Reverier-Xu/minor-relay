//! Session-carried resource sync (T-G07-04 wiring).
//!
//! An authenticated session carries one bounded [`ResourcePage`] per
//! anti-entropy tick over the dedicated resource-sync protocol. Records
//! are validated (digest at decode, writer signature against the locally
//! trusted member descriptors at application) before comparison, and the
//! ordinary metadata-synchronization driver pages them so loss, restart,
//! readdress, and digest disagreement repair through the normal tick —
//! never reconnect-only logic, future holding, or false convergence
//! acknowledgement.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::page::{ResourcePage, sync as page_sync};
use crate::{
  Error, IncomingPacket, NodeId, PacketBody, ProtocolTag, Result, TraceId,
  api::BoxFuture,
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::lifecycle::LocalIdentityContext,
  protocol::{decode_canonical_strict, encode_canonical},
  runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The canonical protocol tag of the resource sync stream.
pub(crate) const RESOURCE_SYNC_PROTOCOL: &str = "relay.woooo.tech/protocols/resource-sync";

/// The wire schema of one resource sync payload.
const RESOURCE_SYNC_PAYLOAD_SCHEMA: &str = "relay.woooo.tech/schemas/resource-sync-payload-v1";

/// The receiver-side body cap: one page is at most
/// [`super::page::MAX_PAGE_RECORDS`] whole records, so a generous but
/// finite byte budget bounds a malicious stream.
const MAX_SYNC_BYTES: usize = 256 * 1_024;
const MAX_SYNC_CHUNKS: usize = 4_096;

/// One resource sync payload: an encoded [`ResourcePage`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceSyncPayload(ByteVec);

#[derive(Encode, Decode)]
#[cbor(array)]
struct SyncPayloadWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  payload: ByteVec,
}

impl ResourceSyncPayload {
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &SyncPayloadWire {
        schema: RESOURCE_SYNC_PAYLOAD_SCHEMA.to_owned(),
        payload: self.0.clone(),
      },
      crate::protocol::offer::OFFER_CBOR_LIMITS,
    )
  }

  /// Decodes one payload, rejecting unknown schemas and any non-canonical
  /// encoding (fail closed). Record-level validation happens at page
  /// decode and application.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: SyncPayloadWire = decode_canonical_strict(
      bytes,
      crate::protocol::offer::OFFER_CBOR_LIMITS,
      "resource sync payload canonical form",
    )?;
    if wire.schema != RESOURCE_SYNC_PAYLOAD_SCHEMA {
      return Err(Error::invalid_input("resource sync payload schema"));
    }
    Ok(Self(wire.payload))
  }

  fn page(&self) -> Result<ResourcePage> {
    ResourcePage::decode(self.0.as_ref())
  }
}

/// The core receiver of resource sync streams over authenticated sessions.
#[derive(Debug)]
pub(crate) struct ResourceSyncConsumer {
  // Held weakly so the registry shared with a live node handle never pins
  // the node's metadata store after shutdown; a packet arriving after the
  // runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn crate::api::Entropy>,
}

impl ResourceSyncConsumer {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  ) -> Self {
    Self {
      context: Arc::downgrade(&context),
      entropy,
    }
  }
}

impl PacketConsumer for ResourceSyncConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingPacket) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let bytes = drain_body(packet.body()).await?;
      let payload = ResourceSyncPayload::decode(&bytes)?;
      let context = self
        .context
        .upgrade()
        .ok_or_else(|| Error::shutting_down("resource sync"))?;
      let page = payload.page()?;
      page_sync::apply_page_ctx(context.store(), self.entropy.as_ref(), &page).await?;
      Ok(())
    })
  }
}

/// Reads one complete bounded body from an admitted sync stream.
async fn drain_body(body: &mut dyn PacketBody) -> Result<Vec<u8>> {
  let mut bytes = Vec::new();
  let mut chunks: usize = 0;
  while let Some(chunk) = body.next_chunk().await? {
    chunks = chunks.saturating_add(1);
    if chunks > MAX_SYNC_CHUNKS || bytes.len().saturating_add(chunk.len()) > MAX_SYNC_BYTES {
      return Err(Error::resource_exhausted("resource sync body"));
    }
    bytes.extend_from_slice(&chunk);
  }
  Ok(bytes)
}

/// The protocol definition that gates the resource sync stream on
/// authenticated sessions.
pub(crate) fn resource_sync_protocol_definition() -> Result<ProtocolDefinition> {
  Ok(ProtocolDefinition::new(
    ProtocolTag::parse(RESOURCE_SYNC_PROTOCOL)?,
    crate::FeatureTag::parse(crate::protocol::feature::DATA_MESSAGES)?,
  ))
}

/// The resource-sync driver's per-node continuation state.
#[derive(Default)]
pub(crate) struct ResourceSyncCursor {
  /// Fingerprint of the last page sent, so an unchanged catalog costs no
  /// encode or per-peer delivery at all.
  pub(crate) page_fingerprint: u64,
  /// Fingerprint of the alive-peer set: a newly connected peer must
  /// receive the current page immediately, changed set or not.
  pub(crate) peers_fingerprint: u64,
  /// Ticks since the last page send: a lost delivery must be retried on a
  /// slow cadence even when nothing changed.
  pub(crate) ticks_since_page_send: u32,
  /// The last resource page cursor, so record sync continues across ticks
  /// and converges beyond a single page.
  pub(crate) page: Option<Vec<u8>>,
}

/// Page deliveries are retried on this slower cadence for lost-delivery
/// healing even when nothing changed.
const RESOURCE_PAGE_RESEND_TICKS: u32 = 32;

/// One resource anti-entropy step: page the local register from the
/// cursor and push the bounded page over every authenticated session.
/// The work per tick is bounded to one page per session, nothing paged to
/// exhaustion. A second completed pass transfers no authoritative changes:
/// unchanged fingerprints cost no sends at all.
pub(crate) async fn resource_sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
  sessions: &SessionTable, runtime: &RuntimeClient, cursor: &mut ResourceSyncCursor,
) -> Result<()> {
  let store = context.store();
  let peers = alive_peers(sessions)?;
  if peers.is_empty() {
    return Ok(());
  }
  let protocol = ProtocolTag::parse(RESOURCE_SYNC_PROTOCOL)?;
  let peers_fp = peers_fingerprint(&peers);
  let page = page_sync::emit_page_ctx(
    store,
    cursor.page.as_deref(),
    super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
  )
  .await?;
  cursor.page = page.cursor().map(|value| value.to_vec());
  let page_fp = page.fingerprint();
  // A page is sent when its content or the alive-peer set changed, and
  // retried on a slow cadence otherwise; an unchanged steady state costs
  // no sends at all (a second completed pass transfers no changes).
  let due = page_fp != cursor.page_fingerprint
    || peers_fp != cursor.peers_fingerprint
    || cursor.ticks_since_page_send >= RESOURCE_PAGE_RESEND_TICKS;
  cursor.page_fingerprint = page_fp;
  cursor.peers_fingerprint = peers_fp;
  if !due {
    cursor.ticks_since_page_send = cursor.ticks_since_page_send.saturating_add(1);
    return Ok(());
  }
  cursor.ticks_since_page_send = 0;
  let payload = ResourceSyncPayload(ByteVec::from(page.encode()?));
  for peer in &peers {
    let _ = send_payload(runtime, entropy, peer, &protocol, &payload).await;
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

/// Sends one sync payload to `peer` with fire-and-forget admission:
/// routing failures are dropped (the next tick retries) and never stall
/// the anti-entropy loop.
async fn send_payload(
  runtime: &RuntimeClient, entropy: &Arc<dyn crate::api::Entropy>, peer: &NodeId,
  protocol: &ProtocolTag, payload: &ResourceSyncPayload,
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
    internal: true,
    ack_notify,
  };
  runtime.try_send_packet(request)
}

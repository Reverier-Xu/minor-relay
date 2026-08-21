//! Established-session keep-alive and packet-stream multiplexing
//! (ADR-0002, ADR-0007).
//!
//! After the authentication exchange completes, the connection splits into
//! a writer half driven by a bounded frame channel (the session queue) and
//! a reader loop that demultiplexes the four packet kinds: opens are
//! validated and admitted into the bounded incoming stream table before
//! the current-process acknowledgement is returned; chunks flow in order
//! into the admitted stream's bounded body channel; ends terminate
//! streams; acks resolve pending outbound admissions.
//!
//! Interruption is explicit everywhere: a closed session fails pending
//! admissions and in-flight bodies with `StreamInterrupted`, and core
//! never persists or replays payload bytes.

use std::{
  collections::{BTreeMap, HashMap},
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use minicbor::bytes::ByteVec;
use tokio::{
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};

use super::driver::EstablishedSession;
use crate::{
  Error, ErrorKind, NodeId, Result, TraceId,
  extension_registry::ExtensionRegistry,
  packet::{
    AckOutcome, ChannelBody, IncomingPacket, MAX_CHUNK_BYTES, OutboundRequest, RouteRecord,
    RouteState, StreamItem,
    wire::{self, AckFrame, AckStatus, ChunkFrame, EndFrame, OpenFrame},
  },
  protocol::wire::PacketKind,
  transport::connection::{Connection, ConnectionReader, ConnectionWriter},
};

/// The number of body chunks buffered per admitted incoming stream before
/// backpressure stalls the session reader.
const INCOMING_STREAM_CHUNKS: usize = 8;

/// The shared node-local session table: authenticated peer to live (or
/// dead, pending replacement) session entry.
pub(crate) type SessionTable = Arc<Mutex<BTreeMap<NodeId, SessionEntry>>>;

/// The shared node-local route table: bounded in-memory trace metadata
/// (ADR-0007: identity, selected node, progress, terminal state — never
/// payload bytes, no durability claim).
pub(crate) type RouteTable = Arc<Mutex<BTreeMap<TraceId, RouteRecord>>>;

/// The packet-handling context shared by every session of one node.
pub(crate) struct SessionPacketContext {
  local: NodeId,
  registry: Arc<ExtensionRegistry>,
  queue_messages: usize,
}

impl SessionPacketContext {
  pub(crate) fn new(
    local: NodeId, registry: Arc<ExtensionRegistry>, queue_messages: usize,
  ) -> Self {
    Self {
      local,
      registry,
      queue_messages,
    }
  }

  pub(crate) const fn local(&self) -> &NodeId {
    &self.local
  }
}

/// One framed outbound session message.
pub(crate) struct SessionFrame {
  kind: PacketKind,
  body: Vec<u8>,
}

/// One established session's send-side handle in the session table.
#[derive(Clone)]
pub(crate) struct SessionEntry {
  frames: mpsc::Sender<SessionFrame>,
  pending_acks: Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
  alive: Arc<AtomicBool>,
}

impl SessionEntry {
  /// Whether the session's reader loop is still serving the connection.
  pub(crate) fn alive(&self) -> bool {
    self.alive.load(Ordering::SeqCst)
  }
}

/// Runs one established session until the connection closes or the node
/// shuts down: spawns the writer task, registers the session in the table
/// (retiring any previous session to the same peer), and serves incoming
/// packet frames.
pub(crate) async fn run_session(
  connection: Connection, session: EstablishedSession, context: Arc<SessionPacketContext>,
  table: SessionTable, shutdown: watch::Receiver<()>,
) {
  let peer = session.peer().clone();
  let (writer, mut reader) = connection.into_split();
  let (frames, frames_rx) = mpsc::channel(context.queue_messages);
  let pending_acks = Arc::new(Mutex::new(HashMap::new()));
  let alive = Arc::new(AtomicBool::new(true));
  let entry = SessionEntry {
    frames: frames.clone(),
    pending_acks: Arc::clone(&pending_acks),
    alive: Arc::clone(&alive),
  };
  {
    let replaced = table
      .lock()
      .map(|mut sessions| sessions.insert(peer, entry))
      .ok()
      .flatten();
    if let Some(previous) = replaced {
      retire(&previous);
    }
  }

  let writer_task = tokio::spawn(run_writer(writer, frames_rx));
  tokio::select! {
    () = read_loop(
      &mut reader,
      &session,
      &context,
      &frames,
      &pending_acks,
    ) => {}
    () = shutdown_observer(shutdown) => {}
  }

  alive.store(false, Ordering::SeqCst);
  writer_task.abort();
  // Pending admissions and in-flight incoming bodies observe the
  // interruption explicitly: pending acks fail with StreamInterrupted and
  // dropped body channels close without an end marker.
  if let Ok(mut pending) = pending_acks.lock() {
    for (_, notify) in pending.drain() {
      let _ = notify.send(Err(ErrorKind::StreamInterrupted));
    }
  }
}

/// Resolves when the runtime signals or drops the shutdown channel.
async fn shutdown_observer(mut signal: watch::Receiver<()>) {
  let _ = signal.changed().await;
}

/// Marks a replaced session dead and fails its pending admissions.
fn retire(entry: &SessionEntry) {
  entry.alive.store(false, Ordering::SeqCst);
  if let Ok(mut pending) = entry.pending_acks.lock() {
    for (_, notify) in pending.drain() {
      let _ = notify.send(Err(ErrorKind::StreamInterrupted));
    }
  }
}

/// Writes queued session frames in order until the queue closes or the
/// connection fails.
async fn run_writer(mut writer: ConnectionWriter, mut frames: mpsc::Receiver<SessionFrame>) {
  while let Some(frame) = frames.recv().await {
    if writer
      .send(frame.kind.kind_id(), &frame.body)
      .await
      .is_err()
    {
      return;
    }
  }
}

/// Serves incoming packet frames until the connection closes or a frame
/// violates the wire contract (fail closed).
async fn read_loop(
  reader: &mut ConnectionReader, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &mpsc::Sender<SessionFrame>,
  pending_acks: &Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
) {
  let mut incoming: HashMap<TraceId, (mpsc::Sender<StreamItem>, u64)> = HashMap::new();
  let mut consumers = JoinSet::new();
  loop {
    let message = match reader.receive().await {
      Ok(Some(message)) => message,
      Ok(None) | Err(_) => break,
    };
    let Some(kind) = crate::protocol::wire::lookup_packet(message.schema_id, message.kind_id)
    else {
      // An established session carries packet kinds only.
      break;
    };
    match kind {
      PacketKind::Open => match wire::decode_open(&message.body) {
        Ok(open) => {
          if admit_open(
            open,
            session,
            context,
            frames,
            &mut incoming,
            &mut consumers,
          )
          .await
          .is_err()
          {
            break;
          }
        }
        Err(_) => break,
      },
      PacketKind::Chunk => match wire::decode_chunk(&message.body) {
        Ok(chunk) => {
          if !forward_chunk(chunk, &mut incoming).await {
            break;
          }
        }
        Err(_) => break,
      },
      PacketKind::End => match wire::decode_end(&message.body) {
        Ok(end) => {
          if let Some((stream, _)) = incoming.remove(&end.trace_id) {
            let _ = stream.send(StreamItem::End).await;
          }
        }
        Err(_) => break,
      },
      PacketKind::Ack => match wire::decode_ack(&message.body) {
        Ok(ack) => resolve_ack(ack, pending_acks),
        Err(_) => break,
      },
    }
  }
}

/// Validates one open frame against the authenticated session and the
/// local registry, admits it into the bounded incoming stream table, and
/// acknowledges current-process admission (or the typed rejection).
async fn admit_open(
  open: OpenFrame, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &mpsc::Sender<SessionFrame>,
  incoming: &mut HashMap<TraceId, (mpsc::Sender<StreamItem>, u64)>, consumers: &mut JoinSet<()>,
) -> Result<()> {
  let trace_id = open.trace_id.clone();
  let status = if open.source != *session.peer() || open.destination != *context.local() {
    // Endpoints must match the session-authenticated identities exactly.
    AckStatus::Unsupported
  } else if incoming.contains_key(&open.trace_id) {
    AckStatus::Unsupported
  } else {
    match context.registry.protocol(&open.protocol) {
      Some(registration)
        if session
          .selected_features()
          .contains(registration.definition.owning_feature()) =>
      {
        if incoming.len() >= context.queue_messages {
          AckStatus::Overloaded
        } else {
          let (stream, body) = mpsc::channel(INCOMING_STREAM_CHUNKS);
          incoming.insert(open.trace_id.clone(), (stream, 0));
          let packet = IncomingPacket::new(
            open.source,
            open.destination,
            open.trace_id,
            open.protocol,
            open.metadata,
            ChannelBody::new(body),
          );
          let consumer = Arc::clone(&registration.consumer);
          consumers.spawn(async move {
            let _ = consumer.accept(packet).await;
          });
          AckStatus::Admitted
        }
      }
      // Unknown protocol tag or owning feature not selected on this
      // session: rejected before admission, never reaching a consumer.
      _ => AckStatus::Unsupported,
    }
  };
  let ack = AckFrame {
    trace_id,
    status,
    admitted_at_millis: now_millis(),
  };
  let body = wire::encode_ack(&ack)?;
  frames
    .send(SessionFrame {
      kind: PacketKind::Ack,
      body,
    })
    .await
    .map_err(|_| Error::stream_interrupted("packet session"))
}

/// Forwards one chunk to its admitted stream in strict sequence order.
/// Returns `false` on a sequence violation (fail closed).
async fn forward_chunk(
  chunk: ChunkFrame, incoming: &mut HashMap<TraceId, (mpsc::Sender<StreamItem>, u64)>,
) -> bool {
  let Some((stream, expected)) = incoming.get_mut(&chunk.trace_id) else {
    // Unknown or already-terminated stream: drop the chunk.
    return true;
  };
  if *expected != chunk.sequence {
    return false;
  }
  *expected = expected.saturating_add(1);
  let bytes: Arc<[u8]> = Arc::from(chunk.bytes.as_slice());
  if stream.send(StreamItem::Chunk(bytes)).await.is_err() {
    // The consumer is gone; terminate the incoming stream.
    incoming.remove(&chunk.trace_id);
  }
  true
}

/// Resolves one pending outbound admission.
fn resolve_ack(
  ack: AckFrame, pending_acks: &Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
) {
  let notify = pending_acks
    .lock()
    .map(|mut pending| pending.remove(&ack.trace_id))
    .ok()
    .flatten();
  if let Some(notify) = notify {
    let outcome = match ack.status {
      AckStatus::Admitted => Ok(UNIX_EPOCH + Duration::from_millis(ack.admitted_at_millis)),
      AckStatus::Unsupported => Err(ErrorKind::Unsupported),
      AckStatus::Overloaded => Err(ErrorKind::Overloaded),
    };
    let _ = notify.send(outcome);
  }
}

/// Pumps one outbound packet over its session: open, admission wait,
/// ordered chunks, end. Updates the in-memory route record and notifies
/// the synchronous waiter of the admission outcome (ADR-0007: the ack
/// proves current-process admission only).
pub(crate) async fn run_outbound(
  entry: SessionEntry, local: NodeId, request: OutboundRequest, routes: RouteTable,
) {
  let trace_id = request.trace_id.clone();
  let (ack_tx, ack_rx) = oneshot::channel();
  if !entry.alive() {
    request.reject(ErrorKind::StreamInterrupted);
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    });
    return;
  }
  {
    let registered = entry
      .pending_acks
      .lock()
      .map(|mut pending| pending.insert(trace_id.clone(), ack_tx));
    if registered.is_err() {
      request.reject(ErrorKind::Internal);
      update_route(&routes, &trace_id, |record| {
        record.update(RouteState::Failed(ErrorKind::Internal));
      });
      return;
    }
  }

  let open = OpenFrame {
    trace_id: trace_id.clone(),
    source: local,
    destination: request.destination.clone(),
    protocol: request.protocol.clone(),
    metadata: request.metadata.clone(),
  };
  let body = match wire::encode_open(&open) {
    Ok(body) => body,
    Err(error) => {
      withdraw_pending(&entry, &trace_id);
      request.reject(error.kind());
      update_route(&routes, &trace_id, |record| {
        record.update(RouteState::Failed(error.kind()));
      });
      return;
    }
  };
  if entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::Open,
      body,
    })
    .await
    .is_err()
  {
    withdraw_pending(&entry, &trace_id);
    request.reject(ErrorKind::StreamInterrupted);
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    });
    return;
  }

  // Wait for the destination's current-process admission before streaming
  // body chunks; a dead session resolves the wait with StreamInterrupted.
  let outcome = ack_rx.await.unwrap_or(Err(ErrorKind::StreamInterrupted));
  let _ = request.ack_notify.send(outcome);
  if let Err(kind) = outcome {
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Failed(kind));
    });
    return;
  }
  update_route(&routes, &trace_id, |record| {
    record.update(RouteState::Streaming);
  });

  let mut sequence = 0_u64;
  let mut body = request.body;
  loop {
    match body.next_chunk().await {
      Ok(Some(bytes)) => {
        if bytes.len() > MAX_CHUNK_BYTES {
          update_route(&routes, &trace_id, |record| {
            record.update(RouteState::Failed(ErrorKind::InvalidInput));
          });
          return;
        }
        let forwarded = bytes.len() as u64;
        let chunk = ChunkFrame {
          trace_id: trace_id.clone(),
          sequence,
          bytes: ByteVec::from(bytes.to_vec()),
        };
        sequence = sequence.saturating_add(1);
        let encoded = match wire::encode_chunk(&chunk) {
          Ok(encoded) => encoded,
          Err(error) => {
            update_route(&routes, &trace_id, |record| {
              record.update(RouteState::Failed(error.kind()));
            });
            return;
          }
        };
        if entry
          .frames
          .send(SessionFrame {
            kind: PacketKind::Chunk,
            body: encoded,
          })
          .await
          .is_err()
        {
          update_route(&routes, &trace_id, |record| {
            record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
          });
          return;
        }
        update_route(&routes, &trace_id, |record| {
          record.forward(forwarded);
        });
      }
      Ok(None) => break,
      Err(error) => {
        update_route(&routes, &trace_id, |record| {
          record.update(RouteState::Failed(error.kind()));
        });
        return;
      }
    }
  }

  let end = match wire::encode_end(&EndFrame {
    trace_id: trace_id.clone(),
  }) {
    Ok(end) => end,
    Err(error) => {
      update_route(&routes, &trace_id, |record| {
        record.update(RouteState::Failed(error.kind()));
      });
      return;
    }
  };
  let interrupted = entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::End,
      body: end,
    })
    .await
    .is_err();
  update_route(&routes, &trace_id, |record| {
    if interrupted {
      record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
    } else {
      record.update(RouteState::Delivered);
    }
  });
}

/// Inserts one route record under the configured capacity, evicting the
/// oldest terminal record when full. Active records are never evicted.
pub(crate) fn insert_route(
  routes: &RouteTable, capacity: usize, record: RouteRecord,
) -> Result<()> {
  let mut table = routes
    .lock()
    .map_err(|_| Error::internal("route records"))?;
  if !table.contains_key(&record.trace_id) && table.len() >= capacity {
    let oldest = table
      .iter()
      .filter(|(_, entry)| matches!(entry.state, RouteState::Delivered | RouteState::Failed(_)))
      .min_by_key(|(_, entry)| entry.updated_at)
      .map(|(trace_id, _)| trace_id.clone());
    match oldest {
      Some(trace_id) => {
        table.remove(&trace_id);
      }
      None => return Err(Error::resource_exhausted("route records")),
    }
  }
  table.insert(record.trace_id.clone(), record);
  Ok(())
}

/// Applies one update to a route record, when present.
fn update_route(routes: &RouteTable, trace_id: &TraceId, update: impl FnOnce(&mut RouteRecord)) {
  if let Ok(mut table) = routes.lock()
    && let Some(record) = table.get_mut(trace_id)
  {
    update(record);
  }
}

/// Removes a pending admission that never reached the wire.
fn withdraw_pending(entry: &SessionEntry, trace_id: &TraceId) {
  if let Ok(mut pending) = entry.pending_acks.lock() {
    pending.remove(trace_id);
  }
}

/// The current wall-clock time as milliseconds since the Unix epoch,
/// saturating at zero for pre-epoch clocks.
fn now_millis() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .ok()
    .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
    .unwrap_or(0)
}

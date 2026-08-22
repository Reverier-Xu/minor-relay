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
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use minicbor::bytes::ByteVec;
use tokio::{
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};
use tracing::{debug, instrument, trace, warn};

use super::driver::EstablishedSession;
use crate::{
  Error, ErrorKind, NodeId, Result, TraceId,
  api::BoxFuture,
  extension_registry::ExtensionRegistry,
  packet::{
    AckOutcome, ChannelBody, IncomingPacket, MAX_CHUNK_BYTES, OutboundRequest, PacketReplyContext,
    RouteRecord, RouteState, StreamItem,
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
// TODO(M6): these route records and the forwarding paths below are
// routing-domain code (roadmap: "Packet targets, load balancing, routes,
// stream forwarding, trace status"). They move to a dedicated `routing`
// module when M6 lands; keep session framing and route state separate
// until then.
pub(crate) type RouteTable = Arc<Mutex<BTreeMap<TraceId, RouteRecord>>>;

/// The packet-handling context shared by every session of one node.
/// The caller-selected session bounds (G4-04): outbound queue count and
/// encoded-byte budgets, plus the wall-clock liveness deadlines.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionPolicy {
  pub(crate) queue_messages: usize,
  pub(crate) queue_bytes: usize,
  pub(crate) idle_timeout: Duration,
  pub(crate) keepalive_interval: Duration,
  pub(crate) keepalive_timeout: Duration,
}

impl SessionPolicy {
  pub(crate) fn new(
    queue_messages: usize, queue_bytes: usize, idle_timeout: Duration,
    keepalive_interval: Duration, keepalive_timeout: Duration,
  ) -> Self {
    Self {
      queue_messages,
      queue_bytes,
      idle_timeout,
      keepalive_interval,
      keepalive_timeout,
    }
  }

  /// Builds the session bounds from the node configuration, so a session
  /// knob is declared once in `NodeConfig` and not copied field-by-field.
  pub(crate) fn from_config(config: &crate::NodeConfig) -> Self {
    Self::new(
      config.session_queue_messages(),
      config.session_queue_bytes(),
      config.session_idle_timeout(),
      config.keepalive_interval(),
      config.keepalive_timeout(),
    )
  }
}

pub(crate) struct SessionPacketContext {
  local: NodeId,
  registry: Arc<ExtensionRegistry>,
  policy: SessionPolicy,
  runtime: crate::runtime::RuntimeClient,
  clock: Arc<dyn crate::storage::receipt::WallClock>,
}

impl SessionPacketContext {
  pub(crate) fn new(
    local: NodeId, registry: Arc<ExtensionRegistry>, policy: SessionPolicy,
    runtime: crate::runtime::RuntimeClient, clock: Arc<dyn crate::storage::receipt::WallClock>,
  ) -> Self {
    Self {
      local,
      registry,
      policy,
      runtime,
      clock,
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

/// Which side initiated an established session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialDirection {
  /// This node dialed the peer.
  Outgoing,
  /// The peer dialed this node.
  Incoming,
}

/// The deterministic crossed-dial ownership rule (SC-G04-P0-09): the
/// connection initiated by the smaller node id wins, so both sides of a
/// simultaneous dial converge to the same authenticated session. Each side
/// keeps the entry whose direction matches the rule and drops the other.
pub(crate) fn keep_connection(local: &NodeId, peer: &NodeId, direction: DialDirection) -> bool {
  match direction {
    DialDirection::Outgoing => local < peer,
    DialDirection::Incoming => local > peer,
  }
}

/// The shared admission state of one outbound session queue: the count of
/// queued frames and their summed encoded bytes. Both bounds are checked
/// atomically (under `admit`) before enqueue, and a rejected frame is never
/// partially enqueued (SC-G04-P0-12).
#[derive(Debug, Default)]
struct QueueState {
  count: AtomicUsize,
  bytes: AtomicUsize,
  admit: std::sync::Mutex<()>,
}

/// The admission overhead of one queued frame beyond its body bytes.
const FRAME_OVERHEAD: usize = 16;

/// A bounded outbound frame sender. `send` atomically checks message count
/// and summed encoded bytes against the caller-selected limits and returns
/// a typed overload error at either boundary without partial enqueue.
#[derive(Clone)]
pub(crate) struct BoundedSender {
  inner: mpsc::Sender<SessionFrame>,
  state: Arc<QueueState>,
  max_count: usize,
  max_bytes: usize,
}

impl BoundedSender {
  pub(crate) fn send(&self, frame: SessionFrame) -> BoxFuture<'_, Result<()>> {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    // The admission check and reservation are one atomic critical section:
    // concurrent senders cannot both pass the count/byte check and exceed
    // the budget (the check-then-act is synchronous, no await inside).
    let reserved = match self.state.admit.lock() {
      Ok(_guard) => {
        let count = self.state.count.load(Ordering::Relaxed);
        let queued_bytes = self.state.bytes.load(Ordering::Relaxed);
        if count >= self.max_count || queued_bytes.saturating_add(bytes) > self.max_bytes {
          None
        } else {
          self.state.count.fetch_add(1, Ordering::Relaxed);
          self.state.bytes.fetch_add(bytes, Ordering::Relaxed);
          Some(bytes)
        }
      }
      Err(_) => return Box::pin(async move { Err(Error::internal("session queue")) }),
    };
    let Some(bytes) = reserved else {
      return Box::pin(async move { Err(Error::overloaded("session queue")) });
    };
    let inner = self.inner.clone();
    let state = Arc::clone(&self.state);
    Box::pin(async move {
      if inner.send(frame).await.is_err() {
        // The queue closed after admission; release the reservation.
        state.count.fetch_sub(1, Ordering::Relaxed);
        state.bytes.fetch_sub(bytes, Ordering::Relaxed);
        return Err(Error::shutting_down("session queue"));
      }
      Ok(())
    })
  }
}

/// The receiving half that releases queue reservations as frames drain.
pub(crate) struct BoundedReceiver {
  inner: mpsc::Receiver<SessionFrame>,
  state: Arc<QueueState>,
}

impl BoundedReceiver {
  pub(crate) async fn recv(&mut self) -> Option<SessionFrame> {
    let frame = self.inner.recv().await?;
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    self.state.count.fetch_sub(1, Ordering::Relaxed);
    self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
    Some(frame)
  }
}

/// One established session's send-side handle in the session table.
#[derive(Clone)]
pub(crate) struct SessionEntry {
  frames: BoundedSender,
  pending_acks: Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
  alive: Arc<AtomicBool>,
  direction: DialDirection,
  retire: watch::Sender<()>,
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
#[instrument(name = "session", skip_all, fields(peer = %session.peer()))]
pub(crate) async fn run_session(
  connection: Connection, session: EstablishedSession, context: Arc<SessionPacketContext>,
  table: SessionTable, shutdown: watch::Receiver<()>, direction: DialDirection,
) {
  let peer = session.peer().clone();
  let (writer, mut reader) = connection.into_split();
  let (frames_tx, frames_rx) = mpsc::channel(context.policy.queue_messages);
  let queue_state = Arc::new(QueueState::default());
  let frames = BoundedSender {
    inner: frames_tx,
    state: Arc::clone(&queue_state),
    max_count: context.policy.queue_messages,
    max_bytes: context.policy.queue_bytes,
  };
  let frames_rx = BoundedReceiver {
    inner: frames_rx,
    state: Arc::clone(&queue_state),
  };
  let pending_acks = Arc::new(Mutex::new(HashMap::new()));
  let alive = Arc::new(AtomicBool::new(true));
  let (retire_tx, retire_rx) = watch::channel(());
  let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(clock_seconds(
    context.clock.as_ref(),
  )));
  let (ping_tx, ping_rx) = watch::channel(());
  let entry = SessionEntry {
    frames: frames.clone(),
    pending_acks: Arc::clone(&pending_acks),
    alive: Arc::clone(&alive),
    direction,
    retire: retire_tx,
  };
  {
    let local = context.local().clone();
    let mut guard = match table.lock() {
      Ok(guard) => guard,
      Err(_) => {
        alive.store(false, Ordering::SeqCst);
        return;
      }
    };
    let replace = match guard.get(&peer) {
      None => true,
      Some(previous) => {
        // A dead entry must never block reconnection: only a live previous
        // session competes under the crossed-dial ownership rule.
        if !previous.alive() {
          true
        } else {
          let keep_existing = keep_connection(&local, &peer, previous.direction);
          let keep_new = keep_connection(&local, &peer, direction);
          // Crossed dial: the deterministic rule prefers exactly one of the
          // two directions; keep that one and drop the other. Same
          // direction (reconnect, restart) always replaces with the newest
          // entry.
          if keep_existing != keep_new {
            keep_new
          } else {
            true
          }
        }
      }
    };
    if replace {
      let previous = guard.insert(peer.clone(), entry);
      if let Some(previous) = previous {
        debug!("session replaced; draining the previous connection");
        retire(&previous);
      }
    } else {
      debug!("crossed dial: keeping the deterministic owner, closing this connection");
      alive.store(false, Ordering::SeqCst);
      return;
    }
  }

  debug!("session established; serving packet streams");
  let mut writer_task = tokio::spawn(run_writer(writer, frames_rx, ping_rx));
  tokio::select! {
    () = read_loop(
      &mut reader,
      &session,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
    ) => {
      trace!("session reader ended");
    }
    () = shutdown_observer(shutdown) => {
      trace!("session ended by shutdown signal");
    }
    () = retire_observer(retire_rx) => {
      trace!("session ended by deterministic replacement");
    }
    () = liveness_observer(
      &last_activity,
      &pending_acks,
      context.clock.clone(),
      context.policy.idle_timeout,
      context.policy.keepalive_interval,
      context.policy.keepalive_timeout,
      &ping_tx,
    ) => {
      debug!("session closed by the liveness policy");
    }
    _ = &mut writer_task => {
      // A writer that ends (send/ping failure) must tear the session down;
      // otherwise a half-open connection would keep its table entry and
      // every outbound packet would fail forever.
      trace!("session writer ended");
    }
  }

  alive.store(false, Ordering::SeqCst);
  // Remove this session's entry when it is still the registered one, so a
  // dead entry cannot block a later reconnection from either direction.
  if let Ok(mut sessions) = table.lock()
    && let Some(current) = sessions.get(&peer)
    && !current.alive()
  {
    sessions.remove(&peer);
  }
  writer_task.abort();
  // Pending admissions and in-flight incoming bodies observe the
  // interruption explicitly: pending acks fail with StreamInterrupted and
  // dropped body channels close without an end marker.
  if let Ok(mut pending) = pending_acks.lock() {
    let interrupted = pending.len();
    for (_, notify) in pending.drain() {
      let _ = notify.send(Err(ErrorKind::StreamInterrupted));
    }
    if interrupted > 0 {
      debug!(interrupted, "session closed pending admissions");
    }
  }
}

/// Resolves when the runtime signals or drops the shutdown channel.
async fn shutdown_observer(mut signal: watch::Receiver<()>) {
  let _ = signal.changed().await;
}

/// Resolves when this session is deterministically replaced (crossed dial
/// or a newer same-direction connection).
async fn retire_observer(mut signal: watch::Receiver<()>) {
  let _ = signal.changed().await;
}

/// UNIX-seconds from the injected wall clock.
fn clock_seconds(clock: &dyn crate::storage::receipt::WallClock) -> u64 {
  clock
    .now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or(0)
}

/// Enforces the session liveness policy on host wall time (SC-G04-P0-13/14):
/// a session with no authenticated traffic or owned in-flight work for the
/// idle deadline closes; a peer missing a keepalive result for the
/// keepalive deadline closes. Wall-clock rollback or freeze delays both
/// deadlines and a forward jump makes them immediately due.
async fn liveness_observer(
  last_activity: &Arc<std::sync::atomic::AtomicU64>,
  pending_acks: &Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
  clock: Arc<dyn crate::storage::receipt::WallClock>, idle_timeout: Duration,
  keepalive_interval: Duration, keepalive_timeout: Duration, ping_tx: &watch::Sender<()>,
) {
  if idle_timeout.is_zero() && keepalive_interval.is_zero() {
    // No liveness policy configured; never resolves.
    std::future::pending::<()>().await;
    return;
  }
  let tick = std::cmp::min(
    if idle_timeout.is_zero() {
      Duration::MAX
    } else {
      idle_timeout
    },
    if keepalive_interval.is_zero() {
      Duration::MAX
    } else {
      keepalive_interval
    },
  )
  .min(Duration::from_secs(1))
  .max(Duration::from_millis(10));
  let mut last_ping = 0_u64;
  loop {
    tokio::time::sleep(tick).await;
    let now = clock_seconds(clock.as_ref());
    let last = last_activity.load(Ordering::Relaxed);
    let has_work = pending_acks
      .lock()
      .map(|pending| !pending.is_empty())
      .unwrap_or(false);
    // Idle close only when no owned in-flight work remains.
    if !idle_timeout.is_zero() && !has_work && now.saturating_sub(last) >= idle_timeout.as_secs() {
      return;
    }
    if !keepalive_interval.is_zero()
      && last_ping != 0
      && now.saturating_sub(last_ping) >= keepalive_timeout.as_secs()
      && now.saturating_sub(last) >= keepalive_timeout.as_secs()
    {
      // The peer missed the keepalive result (no pong or traffic since the
      // ping was sent); close.
      return;
    }
    if !keepalive_interval.is_zero()
      && now.saturating_sub(last_ping) >= keepalive_interval.as_secs()
    {
      last_ping = now;
      let _ = ping_tx.send(());
    }
  }
}

/// Drains a replaced session: it stops accepting new work, its pending
/// admissions fail exactly once with `StreamInterrupted`, and the retire
/// signal closes its reader so the connection tears down after the winner
/// is registered.
fn retire(entry: &SessionEntry) {
  entry.alive.store(false, Ordering::SeqCst);
  if let Ok(mut pending) = entry.pending_acks.lock() {
    for (_, notify) in pending.drain() {
      let _ = notify.send(Err(ErrorKind::StreamInterrupted));
    }
  }
  let _ = entry.retire.send(());
}

/// Writes queued session frames in order until the queue closes or the
/// connection fails.
async fn run_writer(
  mut writer: ConnectionWriter, mut frames: BoundedReceiver, mut ping: watch::Receiver<()>,
) {
  loop {
    tokio::select! {
      frame = frames.recv() => {
        let Some(frame) = frame else {
          trace!("session writer channel closed");
          return;
        };
        if writer
          .send(frame.kind.kind_id(), &frame.body)
          .await
          .is_err()
        {
          warn!(kind = ?frame.kind, "session writer send failed");
          return;
        }
        trace!(kind = ?frame.kind, "session frame sent");
      }
      () = async { let _ = ping.changed().await; } => {
        if writer.ping().await.is_err() {
          warn!("session keepalive ping failed");
          return;
        }
      }
    }
  }
}

/// Serves incoming packet frames until the connection closes or a frame
/// violates the wire contract (fail closed).
async fn read_loop(
  reader: &mut ConnectionReader, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &BoundedSender, pending_acks: &Arc<Mutex<HashMap<TraceId, oneshot::Sender<AckOutcome>>>>,
  last_activity: &Arc<std::sync::atomic::AtomicU64>,
) {
  let mut incoming: HashMap<TraceId, (mpsc::Sender<StreamItem>, u64)> = HashMap::new();
  let mut consumers = JoinSet::new();
  let mut last_pong_seen = reader.pong_last_seen();
  loop {
    // A peer pong is a keepalive response: reflect it into the injected
    // clock's activity mark so the liveness observer sees one time source.
    let pong = reader.pong_last_seen();
    if pong != last_pong_seen {
      last_pong_seen = pong;
      last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
    }
    let message = match reader.receive().await {
      Ok(Some(message)) => message,
      Ok(None) => {
        trace!("session read ended orderly");
        break;
      }
      Err(error) => {
        warn!(kind = ?error.kind(), "session receive failed");
        break;
      }
    };
    last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
    let Some(kind) = crate::protocol::wire::lookup_packet(message.schema_id, message.kind_id)
    else {
      // An established session carries packet kinds only.
      warn!(
        schema_id = message.schema_id,
        kind_id = message.kind_id,
        "unknown packet kind on session"
      );
      break;
    };
    trace!(kind = ?kind, "session frame received");
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
        Err(_) => {
          warn!("malformed packet open frame");
          break;
        }
      },
      PacketKind::Chunk => match wire::decode_chunk(&message.body) {
        Ok(chunk) => {
          if !forward_chunk(chunk, &mut incoming).await {
            warn!("incoming chunk sequence violation; closing session");
            break;
          }
        }
        Err(_) => {
          warn!("malformed packet chunk frame");
          break;
        }
      },
      PacketKind::End => match wire::decode_end(&message.body) {
        Ok(end) => {
          trace!(trace_id = %end.trace_id, "incoming stream ended");
          if let Some((stream, _)) = incoming.remove(&end.trace_id) {
            let _ = stream.send(StreamItem::End).await;
          }
        }
        Err(_) => {
          warn!("malformed packet end frame");
          break;
        }
      },
      PacketKind::Ack => match wire::decode_ack(&message.body) {
        Ok(ack) => resolve_ack(ack, pending_acks),
        Err(_) => {
          warn!("malformed packet ack frame");
          break;
        }
      },
    }
  }
}

/// Validates one open frame against the authenticated session and the
/// local registry, admits it into the bounded incoming stream table, and
/// acknowledges current-process admission (or the typed rejection).
async fn admit_open(
  open: OpenFrame, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &BoundedSender, incoming: &mut HashMap<TraceId, (mpsc::Sender<StreamItem>, u64)>,
  consumers: &mut JoinSet<()>,
) -> Result<()> {
  let trace_id = open.trace_id.clone();
  let ack_protocol = open.protocol.clone();
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
        if incoming.len() >= context.policy.queue_messages {
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
            PacketReplyContext::new(context.registry.clone(), context.runtime.clone()),
          );
          let consumer = Arc::clone(&registration.consumer);
          let consumer_trace = trace_id.clone();
          consumers.spawn(async move {
            let result = consumer.accept(packet).await;
            debug!(
              trace_id = %consumer_trace,
              ok = result.is_ok(),
              "packet consumer finished"
            );
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
    trace_id: trace_id.clone(),
    status,
    admitted_at_millis: now_millis(),
  };
  debug!(
    trace_id = %ack.trace_id,
    protocol = %ack_protocol,
    ?ack.status,
    "packet admission outcome"
  );
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
  trace!(
    trace_id = %chunk.trace_id,
    sequence = chunk.sequence,
    bytes = chunk.bytes.len(),
    "incoming chunk forwarded"
  );
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
    trace!(trace_id = %ack.trace_id, ?ack.status, "admission ack resolved");
    let _ = notify.send(outcome);
  }
}

/// Pumps one outbound packet over its session: open, admission wait,
/// ordered chunks, end. Updates the in-memory route record and notifies
/// the synchronous waiter of the admission outcome (ADR-0007: the ack
/// proves current-process admission only).
#[instrument(name = "packet", skip_all, fields(
  trace_id = %request.trace_id,
  destination = %request.destination,
  local = %local,
))]
pub(crate) async fn run_outbound(
  entry: SessionEntry, local: NodeId, request: OutboundRequest, routes: RouteTable,
) {
  let trace_id = request.trace_id.clone();
  let (ack_tx, ack_rx) = oneshot::channel();
  if !entry.alive() {
    debug!("packet rejected: session not alive");
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
  trace!("packet open queued");

  // Wait for the destination's current-process admission before streaming
  // body chunks; a dead session resolves the wait with StreamInterrupted.
  let outcome = ack_rx.await.unwrap_or(Err(ErrorKind::StreamInterrupted));
  let _ = request.ack_notify.send(outcome);
  debug!(admitted = outcome.is_ok(), "packet admission acknowledged");
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
        trace!(sequence, bytes = forwarded, "packet chunk queued");
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
  debug!(interrupted, "packet stream finished");
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

#[cfg(test)]
mod replacement_tests {
  use super::{DialDirection, keep_connection};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  /// SC-G04-P0-09: every completion ordering picks the same single session
  /// owner from durable identities.
  #[test]
  fn crossed_dial_converges_to_the_smaller_initiator_connection() {
    let smaller = node(1);
    let larger = node(2);

    // Smaller node keeps its outgoing dial; larger keeps its incoming one —
    // both sides converge to the smaller's connection.
    assert!(keep_connection(&smaller, &larger, DialDirection::Outgoing));
    assert!(!keep_connection(&smaller, &larger, DialDirection::Incoming));
    assert!(!keep_connection(&larger, &smaller, DialDirection::Outgoing));
    assert!(keep_connection(&larger, &smaller, DialDirection::Incoming));

    // The rule is total for every ordering: exactly one direction wins per
    // side, and the winning pair is the same connection.
    for (local, peer) in [
      (smaller.clone(), larger.clone()),
      (larger.clone(), smaller.clone()),
    ] {
      let keep_outgoing = keep_connection(&local, &peer, DialDirection::Outgoing);
      let keep_incoming = keep_connection(&local, &peer, DialDirection::Incoming);
      assert_ne!(keep_outgoing, keep_incoming);
    }
  }
}

#[cfg(test)]
mod queue_tests {
  use std::sync::Arc;

  use futures_util::FutureExt;
  use tokio::sync::mpsc;

  use super::{BoundedReceiver, BoundedSender, FRAME_OVERHEAD, QueueState, SessionFrame};
  use crate::{ErrorKind, protocol::wire::PacketKind};

  fn frame(bytes: usize) -> SessionFrame {
    SessionFrame {
      kind: PacketKind::Chunk,
      body: vec![0_u8; bytes],
    }
  }

  fn queue(max_count: usize, max_bytes: usize) -> (BoundedSender, BoundedReceiver) {
    let (tx, rx) = mpsc::channel(max_count);
    let state = Arc::new(QueueState::default());
    (
      BoundedSender {
        inner: tx,
        state: Arc::clone(&state),
        max_count,
        max_bytes,
      },
      BoundedReceiver { inner: rx, state },
    )
  }

  /// SC-G04-P0-12: count and byte bounds are checked atomically and a
  /// rejected frame is never partially enqueued.
  #[tokio::test]
  async fn bounded_queue_rejects_at_either_boundary_without_partial_enqueue() {
    let (sender, mut receiver) = queue(2, 1_000);

    // Two frames fit the count bound.
    sender.send(frame(10)).await.unwrap();
    sender.send(frame(20)).await.unwrap();
    // Third exceeds the count bound.
    let error = sender.send(frame(5)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    assert_eq!(error.context(), "session queue");

    // Drain one; the queue admits again at the count boundary.
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(5)).await.unwrap();

    // Byte bound: a single oversized frame is rejected outright.
    let (byte_sender, mut byte_receiver) = queue(16, FRAME_OVERHEAD + 32);
    let error = byte_sender.send(frame(64)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    // Nothing was enqueued by the rejected frame (a recv would hang).
    assert!(byte_receiver.recv().now_or_never().is_none());
  }

  #[tokio::test]
  async fn bounded_queue_recovers_after_drain() {
    let (sender, mut receiver) = queue(1, 1_000);
    sender.send(frame(10)).await.unwrap();
    assert_eq!(
      sender.send(frame(10)).await.unwrap_err().kind(),
      ErrorKind::Overloaded
    );
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(10)).await.unwrap();
    let _ = receiver.recv().await.unwrap();
  }
}

#[cfg(test)]
mod liveness_tests {
  use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::watch;

  use super::liveness_observer;
  use crate::{TraceId, packet::AckOutcome, storage::contract::helpers::ManualClock};

  fn no_pending() -> Arc<Mutex<HashMap<TraceId, tokio::sync::oneshot::Sender<AckOutcome>>>> {
    Arc::new(Mutex::new(HashMap::new()))
  }

  /// SC-G04-P0-14: while host wall time advances normally, only sessions
  /// without authenticated traffic or owned in-flight work close after the
  /// configured idle deadline.
  #[tokio::test(start_paused = true)]
  async fn idle_closes_at_the_deadline_only_without_owned_work() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let pending = no_pending();
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Before the deadline the observer stays alive.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Owned in-flight work holds the session past the deadline.
    let held = no_pending();
    let held_handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let held = Arc::clone(&held);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &held,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!held_handle.is_finished());

    // At the deadline with no work the observer resolves.
    clock.set(UNIX_EPOCH + Duration::from_secs(110));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// SC-G04-P0-14 continuation: rollback or freeze delays closure and a
  /// forward jump makes it immediately due.
  #[tokio::test(start_paused = true)]
  async fn idle_respects_clock_rollback_and_forward_jumps() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let (ping_tx, _) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Rollback keeps the session alive (deadline recedes).
    clock.set(UNIX_EPOCH + Duration::from_secs(50));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // A forward jump makes the deadline immediately due.
    clock.set(UNIX_EPOCH + Duration::from_secs(500));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// SC-G04-P0-13: a peer missing the keepalive result is closed after the
  /// keepalive deadline.
  #[tokio::test(start_paused = true)]
  async fn keepalive_closes_a_peer_missing_the_result() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          Duration::from_secs(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });

    // After the keepalive interval a ping fires.
    clock.set(UNIX_EPOCH + Duration::from_secs(1_005));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(ping_rx.changed().await.is_ok());

    // The peer never answers: after the keepalive timeout the observer
    // resolves (session closes).
    clock.set(UNIX_EPOCH + Duration::from_secs(1_015));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }
}

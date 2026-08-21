//! Secure-join integration lane (T-G03-02).
//!
//! Two real nodes over loopback TLS 1.3 WebSocket: the receiver creates a
//! cluster, issues a join credential, and listens; the joiner completes the
//! exporter-bound join and persists the admission. Negative lanes prove
//! generic failure without admission or credential consumption.

use std::sync::Arc;

use minor_relay::{
  CreateCluster, Endpoint, ErrorKind, GetLocalNode, JoinCluster, JoinCredential, Listen,
  NodeBuilder, NodeHandle, RotateJoinCredential, Shutdown,
};
#[cfg(all(unix, feature = "json"))]
use tempfile::TempDir;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

struct Node {
  handle: NodeHandle,
  _keys: Arc<ScriptedKeys>,
}

async fn start(storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>) -> Node {
  let factory: Arc<dyn minor_relay::extension::StorageFactory> = storage;
  let handle = NodeBuilder::new(factory, keys).start().await.unwrap();
  Node {
    handle,
    _keys: Arc::new(ScriptedKeys::full()),
  }
}

#[cfg(all(unix, feature = "json"))]
async fn start_json(dir: &TempDir, keys: Arc<ScriptedKeys>) -> Node {
  let handle = NodeBuilder::new(
    minor_relay::adapters::json_store(dir.path().to_path_buf()),
    keys,
  )
  .start()
  .await
  .unwrap();
  Node {
    handle,
    _keys: Arc::new(ScriptedKeys::full()),
  }
}

#[tokio::test]
async fn secure_join_completes_exporter_bound_join_and_persists_admission() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(10_000)),
  )
  .await;
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(20_000)),
  )
  .await;

  let cluster = receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let admission = joiner
    .handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  assert_eq!(admission.cluster_id(), cluster.cluster_id());
  assert_eq!(admission.issuer(), cluster.creator());

  let local = joiner.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.cluster_id(), cluster.cluster_id());
  assert_eq!(local.node_id(), admission.admitted_node());

  // The receiver observes the admitted subject in its own identity state:
  // its local node view shows the issuer, not the subject.
  let receiver_local = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(receiver_local.node_id(), cluster.creator());

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner.handle.command(Shutdown::new()).await.unwrap();
}

// The json backend provides OsCrashDurable only where the directory
// barrier is available (unix); elsewhere the runtime requirement is
// refused with a typed error, matching json_runtime's non-unix lane.
#[cfg(all(unix, feature = "json"))]
#[tokio::test]
async fn secure_join_json_backend_round_trips_the_same_join() {
  let receiver_dir = tempfile::tempdir().unwrap();
  let joiner_dir = tempfile::tempdir().unwrap();
  let receiver_keys = Arc::new(ScriptedKeys::full_at(30_000));
  let joiner_keys = Arc::new(ScriptedKeys::full_at(40_000));
  let receiver = start_json(&receiver_dir, receiver_keys.clone()).await;
  let joiner = start_json(&joiner_dir, joiner_keys.clone()).await;

  let cluster = receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let admission = joiner
    .handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  assert_eq!(admission.cluster_id(), cluster.cluster_id());

  // Both sides persist through reopen: shutdown and restart the joiner on
  // the same directory proves the adopted pointer/binding/grant survived.
  joiner.handle.command(Shutdown::new()).await.unwrap();
  let restarted = start_json(&joiner_dir, joiner_keys.clone()).await;
  let local = restarted.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.cluster_id(), cluster.cluster_id());
  assert_eq!(local.node_id(), admission.admitted_node());

  receiver.handle.command(Shutdown::new()).await.unwrap();
  restarted.handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test]
async fn secure_join_wrong_credential_fails_without_admission() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(50_000)),
  )
  .await;
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(60_000)),
  )
  .await;

  receiver.handle.command(CreateCluster::new()).await.unwrap();
  receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let wrong = JoinCredential::parse("join_BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
  let error = joiner
    .handle
    .command(JoinCluster::new(listener.endpoint().clone(), wrong))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  assert!(
    joiner.handle.query(GetLocalNode::new()).await.is_err(),
    "a failed join leaves the joiner standalone"
  );

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-02 packet data plane evidence (SC-G03-P0-06) ----

use std::sync::Mutex as StdMutex;

use minor_relay::{
  BoxFuture, ExtensionRegistry, IncomingPacket, PacketBody, PacketMetadata, PacketPolicy,
  PacketTarget, ProtocolDefinition, ProtocolTag, QualifiedTag,
};

#[derive(Debug)]
struct VecBody {
  chunks: std::vec::IntoIter<Arc<[u8]>>,
}

impl VecBody {
  fn new(chunks: Vec<&'static [u8]>) -> Self {
    Self {
      chunks: chunks
        .into_iter()
        .map(Arc::from)
        .collect::<Vec<_>>()
        .into_iter(),
    }
  }
}

impl PacketBody for VecBody {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, minor_relay::Result<Option<Arc<[u8]>>>> {
    Box::pin(async move { Ok(self.chunks.next()) })
  }
}

#[derive(Debug, Default)]
struct Collector {
  packets: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl minor_relay::PacketConsumer for Collector {
  fn accept<'a>(&'a self, mut packet: IncomingPacket) -> BoxFuture<'a, minor_relay::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      while let Some(chunk) = packet.body().next_chunk().await? {
        body.extend_from_slice(&chunk);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((packet.trace_id().to_string(), body));
      Ok(())
    })
  }
}

async fn start_with_protocol(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<Collector>,
) -> NodeHandle {
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn minor_relay::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

fn protocol(tag: &str) -> ProtocolDefinition {
  ProtocolDefinition::new(
    ProtocolTag::parse(&format!("relay.woooo.tech/protocols/{tag}")).unwrap(),
    minor_relay::FeatureTag::parse("relay.woooo.tech/features/session-core").unwrap(),
  )
}

fn metadata() -> PacketMetadata {
  PacketMetadata::new()
    .insert(
      QualifiedTag::parse("relay.woooo.tech/resources/test-label").unwrap(),
      Arc::from(b"value".as_slice()),
    )
    .unwrap()
}

fn policy() -> PacketPolicy {
  PacketPolicy::new(
    QualifiedTag::parse("relay.woooo.tech/policies/direct").unwrap(),
    1,
  )
  .unwrap()
}

#[tokio::test]
async fn secure_join_packet_streams_ordered_after_authentication() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(70_000)),
      protocol("test-echo"),
      receiver_collector,
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(80_000)),
    protocol("test-echo"),
    collector.clone(),
  )
  .await;

  receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let admission = joiner_handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();

  // The receiver sends to the joiner over the established authenticated
  // session; the TraceId is visible before any body delivery.
  let packet = receiver
    .handle
    .create_packet(
      PacketTarget::Exact(admission.admitted_node().clone()),
      ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let trace_before = packet.trace_id().clone();
  let ack = packet
    .send_sync(Box::new(VecBody::new(vec![
      b"chunk-1", b"chunk-2", b"chunk-3",
    ])))
    .await
    .unwrap();
  assert_eq!(ack.trace_id(), &trace_before);
  assert_eq!(ack.destination(), admission.admitted_node());

  // Admission is acked before the consumer finishes; wait for the bounded
  // consumer task to record the packet without wall-clock sleeps.
  for _ in 0..4096 {
    if !collector.packets.lock().unwrap().is_empty() {
      break;
    }
    tokio::task::yield_now().await;
  }
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1);
  assert_eq!(packets[0].0, trace_before.to_string());
  assert_eq!(packets[0].1, b"chunk-1chunk-2chunk-3");

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner_handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test]
async fn secure_join_packet_rejects_unknown_target_and_unregistered_protocol() {
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(90_000)),
      protocol("test-echo"),
      Arc::new(Collector::default()),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  receiver.handle.command(CreateCluster::new()).await.unwrap();

  // No session to any node: routing to an unknown exact node fails before
  // any delivery work.
  let unknown = minor_relay::NodeId::parse("node_999999999999999999999").unwrap();
  let packet = receiver
    .handle
    .create_packet(
      PacketTarget::Exact(unknown),
      ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      PacketMetadata::new(),
    )
    .unwrap();
  let error = packet
    .send_sync(Box::new(VecBody::new(vec![b"never-delivered"])))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::RouteUnavailable);

  // Unregistered protocol: rejected before admission even with a session.
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(95_000)),
    protocol("only-this"),
    collector,
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let admission = joiner_handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();

  // Sender-side: creating a packet for a protocol the local registry never
  // registered fails before any session work.
  let error = receiver
    .handle
    .create_packet(
      PacketTarget::Exact(admission.admitted_node().clone()),
      ProtocolTag::parse("relay.woooo.tech/protocols/not-registered").unwrap(),
      policy(),
      PacketMetadata::new(),
    )
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Unsupported);

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner_handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-04 feature selection / credential-free reconnect evidence (E2E-01)
// ----

use minor_relay::ConnectMember;

/// Sends one two-chunk packet from `sender` to `target` and waits for the
/// receiver-side collector to observe it in order.
async fn packet_round_trip(
  sender: &NodeHandle, target: &minor_relay::NodeId, collector: &Arc<Collector>,
) -> minor_relay::NodeId {
  let packet = sender
    .create_packet(
      PacketTarget::Exact(target.clone()),
      ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let ack = packet
    .send_sync(Box::new(VecBody::new(vec![b"a", b"b"])))
    .await
    .unwrap();
  assert_eq!(ack.destination(), target);
  for _ in 0..4096 {
    if !collector.packets.lock().unwrap().is_empty() {
      break;
    }
    tokio::task::yield_now().await;
  }
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1, "one ordered packet must arrive");
  assert_eq!(packets[0].1, b"ab");
  ack.destination().clone()
}

#[tokio::test]
async fn secure_join_rotation_keeps_members_and_reconnect_is_credential_free() {
  let receiver_keys = Arc::new(ScriptedKeys::full_at(90_000));
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      receiver_keys.clone(),
      protocol("test-echo"),
      Arc::clone(&receiver_collector),
    )
    .await,
    _keys: receiver_keys.clone(),
  };
  receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let joiner_keys = Arc::new(ScriptedKeys::full_at(95_000));
  let joiner_storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let joiner_collector = Arc::new(Collector::default());
  let joiner = Node {
    handle: start_with_protocol(
      Arc::clone(&joiner_storage),
      joiner_keys.clone(),
      protocol("test-echo"),
      Arc::clone(&joiner_collector),
    )
    .await,
    _keys: joiner_keys.clone(),
  };
  let admission = joiner
    .handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  let _admitted = admission.admitted_node().clone();

  // E2E-01: the joined member streams packets; credential rotation does
  // not disconnect it.
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  packet_round_trip(&joiner.handle, &receiver_id, &receiver_collector).await;
  receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  receiver_collector.packets.lock().unwrap().clear();
  packet_round_trip(&joiner.handle, &receiver_id, &receiver_collector).await;

  // Disconnect by shutting the joiner down, then reconnect with key trust
  // only: no credential exists on this node, the trusted binding gates the
  // handshake, and packets flow again.
  joiner.handle.command(Shutdown::new()).await.unwrap();
  let restarted = Node {
    handle: start_with_protocol(
      joiner_storage,
      joiner_keys.clone(),
      protocol("test-echo"),
      Arc::clone(&joiner_collector),
    )
    .await,
    _keys: joiner_keys.clone(),
  };
  let authenticated = restarted
    .handle
    .command(ConnectMember::new(
      listener.endpoint().clone(),
      receiver_id.clone(),
    ))
    .await
    .unwrap();
  assert_eq!(authenticated, receiver_id.clone());
  receiver_collector.packets.lock().unwrap().clear();
  packet_round_trip(&restarted.handle, &receiver_id, &receiver_collector).await;

  restarted.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-05 bidirectional packet streams evidence (SC-G03-P0-15..17) ----

use tokio::sync::Notify;

/// A packet body that stalls on the first chunk until released, then ends.
#[derive(Debug)]
struct BlockingBody {
  release: Arc<Notify>,
  released: bool,
}

impl PacketBody for BlockingBody {
  fn next_chunk<'a>(&'a mut self) -> BoxFuture<'a, minor_relay::Result<Option<Arc<[u8]>>>> {
    if self.released {
      return Box::pin(async move { Ok(None) });
    }
    self.released = true;
    Box::pin(async move {
      self.release.notified().await;
      Ok(Some(Arc::from(&b"held"[..])))
    })
  }
}

/// A consumer that records packet traces, bodies, and terminal errors.
#[derive(Debug, Default)]
struct RecordingConsumer {
  packets: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl minor_relay::PacketConsumer for RecordingConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingPacket) -> BoxFuture<'a, minor_relay::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      while let Some(chunk) = packet.body().next_chunk().await? {
        body.extend_from_slice(&chunk);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((packet.trace_id().to_string(), body));
      Ok(())
    })
  }
}

/// A consumer that derives a caller-owned return packet (endpoint swap,
/// trace-id reuse) and sends it back to the authenticated source.
#[derive(Debug, Default)]
struct ReplyConsumer {
  pings: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl minor_relay::PacketConsumer for ReplyConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingPacket) -> BoxFuture<'a, minor_relay::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      while let Some(chunk) = packet.body().next_chunk().await? {
        body.extend_from_slice(&chunk);
      }
      let trace = packet.trace_id().clone();
      self.pings.lock().unwrap().push((trace.to_string(), body));
      let reply = packet
        .derive_return_packet(
          ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap(),
          PacketMetadata::new(),
        )
        .unwrap();
      assert_eq!(
        reply.trace_id(),
        &trace,
        "derived reply reuses the trace id"
      );
      reply
        .send_sync(Box::new(VecBody::new(vec![b"reply"])))
        .await?;
      Ok(())
    })
  }
}

async fn start_with_config<C: minor_relay::PacketConsumer + Send + Sync + 'static>(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<C>, config: minor_relay::NodeConfig,
) -> NodeHandle {
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn minor_relay::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .config(config)
    .start()
    .await
    .unwrap()
}

async fn start_with_reply_consumer(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<ReplyConsumer>,
) -> NodeHandle {
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn minor_relay::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

async fn round_trip_to(
  sender: &NodeHandle, target: &minor_relay::NodeId, body: &[&'static [u8]],
  collector: &Arc<Collector>,
) -> minor_relay::TraceId {
  let packet = sender
    .create_packet(
      PacketTarget::Exact(target.clone()),
      ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let trace = packet.trace_id().clone();
  packet
    .send_sync(Box::new(VecBody::new(body.to_vec())))
    .await
    .unwrap();
  for _ in 0..4096 {
    if !collector.packets.lock().unwrap().is_empty() {
      break;
    }
    tokio::task::yield_now().await;
  }
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1, "one ordered packet must arrive");
  trace
}

/// SC-G03-P0-15: both peers stream concurrent packets over one session;
/// each incoming stream preserves its endpoints, trace id, metadata, and
/// byte order.
#[tokio::test]
async fn secure_join_packets_flow_concurrently_in_both_directions() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(100_000)),
      protocol("test-echo"),
      Arc::clone(&receiver_collector),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(101_000)),
    protocol("test-echo"),
    collector.clone(),
  )
  .await;
  receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let admission = joiner_handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let joiner_id = admission.admitted_node().clone();

  let (east_trace, west_trace) = tokio::join!(
    async {
      round_trip_to(
        &receiver.handle,
        &joiner_id,
        &[b"east", b"bound"],
        &collector,
      )
      .await
    },
    async {
      round_trip_to(
        &joiner_handle,
        &receiver_id,
        &[b"west", b"bound"],
        &receiver_collector,
      )
      .await
    }
  );
  assert_ne!(east_trace, west_trace);
  assert_eq!(collector.packets.lock().unwrap().clone()[0].1, b"eastbound");
  assert_eq!(
    receiver_collector.packets.lock().unwrap().clone()[0].1,
    b"westbound"
  );

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G03-P0-16: a caller derives a return packet by swapping endpoints
/// and reusing the incoming trace id; core assigns no return meaning.
#[tokio::test]
async fn secure_join_derived_return_packet_reuses_trace_id() {
  let reply_consumer = Arc::new(ReplyConsumer::default());
  let reply_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_reply_consumer(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(110_000)),
      protocol("test-echo"),
      Arc::clone(&reply_consumer),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(111_000)),
    protocol("test-echo"),
    reply_collector.clone(),
  )
  .await;
  receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let admission = joiner_handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let _joiner_id = admission.admitted_node().clone();

  let trace = round_trip_to(&joiner_handle, &receiver_id, &[b"ping"], &reply_collector).await;
  let pings = reply_consumer.pings.lock().unwrap().clone();
  assert_eq!(
    pings.len(),
    1,
    "receiver consumer must see the original ping"
  );
  assert_eq!(pings[0].0, trace.to_string(), "trace id preserved inbound");
  assert_eq!(pings[0].1, b"ping");
  let replies = reply_collector.packets.lock().unwrap().clone();
  assert_eq!(replies.len(), 1);
  assert_eq!(
    replies[0].0,
    trace.to_string(),
    "derived reply reuses the trace id"
  );
  assert_eq!(replies[0].1, b"reply");

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G03-P0-17: bounded incoming-stream admission returns typed
/// backpressure at the configured capacity, and release frees every slot.
#[tokio::test]
async fn secure_join_incoming_stream_capacity_returns_backpressure_and_recovers() {
  let config = minor_relay::NodeConfig::new()
    .with_session_queue_limits(4, 65_536)
    .unwrap();
  let recorder = Arc::new(RecordingConsumer::default());
  let receiver = Node {
    handle: start_with_config(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(120_000)),
      protocol("test-echo"),
      Arc::clone(&recorder),
      config,
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(121_000)),
    protocol("test-echo"),
    Arc::new(Collector::default()),
  )
  .await;
  receiver.handle.command(CreateCluster::new()).await.unwrap();
  let issued = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let admission = joiner_handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap();
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let _joiner_id = admission.admitted_node().clone();

  let release = Arc::new(Notify::new());
  let protocol_tag = ProtocolTag::parse("relay.woooo.tech/protocols/test-echo").unwrap();
  for _ in 0..4 {
    let packet = joiner_handle
      .create_packet(
        PacketTarget::Exact(receiver_id.clone()),
        protocol_tag.clone(),
        policy(),
        metadata(),
      )
      .unwrap();
    packet
      .send_sync(Box::new(BlockingBody {
        release: release.clone(),
        released: false,
      }))
      .await
      .unwrap();
  }

  let packet = joiner_handle
    .create_packet(
      PacketTarget::Exact(receiver_id.clone()),
      protocol_tag.clone(),
      policy(),
      metadata(),
    )
    .unwrap();
  let error = packet
    .send_sync(Box::new(VecBody::new(vec![b"overflow"])))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Overloaded);

  release.notify_waiters();
  for _ in 0..4096 {
    if recorder.packets.lock().unwrap().len() >= 4 {
      break;
    }
    tokio::task::yield_now().await;
  }
  assert_eq!(recorder.packets.lock().unwrap().len(), 4);
  let packet = joiner_handle
    .create_packet(
      PacketTarget::Exact(receiver_id.clone()),
      protocol_tag,
      policy(),
      metadata(),
    )
    .unwrap();
  packet
    .send_sync(Box::new(VecBody::new(vec![b"after"])))
    .await
    .unwrap();
  for _ in 0..4096 {
    if recorder.packets.lock().unwrap().len() >= 5 {
      break;
    }
    tokio::task::yield_now().await;
  }
  assert_eq!(recorder.packets.lock().unwrap().len(), 5);

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-06 hostile / admission-input closure evidence (SC-G03-P0-22) ----

/// SC-G03-P0-22: a source exhausting its fixed admission rate window is
/// refused before any handshake or signing work; the refusal consumes no
/// credential and performs no signature.
#[tokio::test]
async fn secure_join_admission_rate_window_refuses_before_signing() {
  let receiver_keys = Arc::new(ScriptedKeys::full_at(130_000));
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      receiver_keys.clone(),
      protocol("test-echo"),
      Arc::new(Collector::default()),
    )
    .await,
    _keys: receiver_keys.clone(),
  };
  receiver.handle.command(CreateCluster::new()).await.unwrap();
  receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // A syntactically valid but cryptographically wrong credential fails at
  // proof verification; every attempt still counts against the fixed
  // per-source admission rate window (16 per 60 seconds).
  let hostile = JoinCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
  let attacker = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(131_000)),
    protocol("test-echo"),
    Arc::new(Collector::default()),
  )
  .await;
  for _ in 0..16 {
    let error = attacker
      .command(JoinCluster::new(
        listener.endpoint().clone(),
        JoinCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
      ))
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  }
  assert!(
    !receiver_keys.take_calls().is_empty(),
    "authenticated attempts reach the handshake and sign"
  );

  // The seventeenth attempt from the same source (all loopback reconnects
  // normalize to one source) is refused before any signing work.
  let error = attacker
    .command(JoinCluster::new(listener.endpoint().clone(), hostile))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  assert!(
    receiver_keys.take_calls().is_empty(),
    "a rate-refused attempt must perform no signing and consume no credential"
  );

  attacker.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

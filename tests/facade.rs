//! External core-only facade proof and E2E-08 (T-G09-07,
//! SC-G09-P0-22..26).
//!
//! This test crate is an external consumer: it exercises the entire
//! core-only public surface — packet streams over label-selected
//! destinations, paged member/trust/topology/resource/listener/session
//! views, resource mutations, revocation, leave, and events — without any
//! business or deployment type ever entering core.

use std::{sync::Arc, time::Duration};

use minor_relay::{
  BoxFuture, CreateCluster, Endpoint, ErrorKind, EventOptions, EventReceive, GetResource,
  JoinCluster, Listen, LoadBalancingPolicy, NodeBuilder, NodeConfig, NodeHandle, NodeId,
  PacketMetadata, PacketPolicy, PacketTarget, PageListeners, PageMembers, PageResources,
  PageSessions, PageSpec, PageTopology, PageTrust, ProtocolDefinition, ProtocolTag, PutResource,
  RemoveResource, ResourceChanged, ResourceLabels, ResourceName, ResourceUri, ResourceWrite,
  Result, RevokeNode, RoutingPolicy, SelectResources, Selector, SessionChanged, Shutdown,
  ShutdownReason, UpdateNodeMetadata, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);
const ECHO_PROTOCOL: &str = "relay.woooo.tech/protocols/facade-echo";
const LOAD_BALANCER: &str = "example.org/balancers/first-match";

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
}

/// Counts fully drained echo packets.
#[derive(Debug, Default)]
struct EchoCollector {
  packets: std::sync::Mutex<usize>,
}

impl minor_relay::PacketConsumer for EchoCollector {
  fn accept<'a>(
    &'a self, mut packet: minor_relay::IncomingPacket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
      while packet.body().next_chunk().await?.is_some() {}
      *self.packets.lock().unwrap() += 1;
      Ok(())
    })
  }
}

/// Selects the first matching candidate in canonical order.
#[derive(Debug)]
struct FirstMatch;

impl LoadBalancingPolicy for FirstMatch {
  fn select<'a>(
    &'a self, _selector: &'a Selector, candidates: &'a dyn minor_relay::CandidateNodeReader,
  ) -> BoxFuture<'a, Result<NodeId>> {
    Box::pin(async move {
      let page = candidates.next_matching_nodes(_selector, None, 1).await?;
      page
        .items()
        .first()
        .map(|member| member.node_id().clone())
        .ok_or_else(|| {
          minor_relay::Error::provider(
            minor_relay::ProviderErrorKind::Unsupported,
            minor_relay::ProviderErrorContext::LoadBalancingPolicy,
          )
        })
    })
  }
}

/// A small opaque body for the echo packet.
#[derive(Debug)]
struct EchoBody {
  chunk: Option<Arc<[u8]>>,
}

impl minor_relay::PacketBody for EchoBody {
  fn next_chunk<'a>(
    &'a mut self,
  ) -> minor_relay::BoxFuture<'a, minor_relay::Result<Option<Arc<[u8]>>>> {
    Box::pin(async move { Ok(self.chunk.take()) })
  }
}

async fn start_node(seed: u64, echo: bool) -> Node {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(1_100_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let mut builder = NodeBuilder::new(storage, keys).config(config);
  if echo {
    let mut extensions = minor_relay::ExtensionRegistry::new();
    extensions
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
          minor_relay::FeatureTag::parse("relay.woooo.tech/features/session-core").unwrap(),
        ),
        Arc::new(EchoCollector::default()),
      )
      .unwrap();
    extensions
      .register_load_balancer(
        minor_relay::QualifiedTag::parse(LOAD_BALANCER).unwrap(),
        Arc::new(FirstMatch),
      )
      .unwrap();
    builder = builder.extensions(extensions);
  }
  let handle = builder.start().await.unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  }
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .command(Listen::new(node.endpoint.clone()))
    .await
    .unwrap();
  listener.endpoint().clone()
}

async fn join_with_retry(node: &NodeHandle, issuer: &NodeHandle, endpoint: Endpoint) {
  let issued = issuer
    .command(minor_relay::RotateJoinCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let credential = minor_relay::JoinCredential::parse(&secret).unwrap();
    match node
      .command(JoinCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => return,
      Err(error) => {
        assert!(
          deadline.elapsed() < Duration::from_secs(60),
          "join never succeeded: {error:?}"
        );
        tokio::time::sleep(Duration::from_millis(100 * (1_u64 << attempts.min(4)))).await;
      }
    }
  }
}

/// A deterministic key provider with working deletion: the leave's
/// custody lane needs a provider whose delete actually applies.
#[derive(Debug, Default)]
struct LeaveCapableKeys {
  records: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
  next: std::sync::Mutex<u64>,
}

impl LeaveCapableKeys {
  fn seed_for(base: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&base.to_le_bytes().repeat(4)[..32].try_into().unwrap())
  }

  fn create_at(&self, operation: &minor_relay::KeyOperationId) -> minor_relay::KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()) {
      let signing = self.records.lock().unwrap().get(handle).cloned();
      if let Some(signing) = signing {
        return minor_relay::KeyCreateState::Present(minor_relay::CreatedKey::new(
          minor_relay::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
          minor_relay::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
        ));
      }
    }
    let mut next = self.next.lock().unwrap();
    let index = *next;
    *next += 1;
    let signing = Self::seed_for(index + 1);
    let handle = format!("facade-handle-{index}").into_bytes();
    let created = minor_relay::CreatedKey::new(
      minor_relay::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      minor_relay::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    minor_relay::KeyCreateState::Present(created)
  }

  fn lookup(&self, operation: &minor_relay::KeyOperationId) -> Option<minor_relay::KeyCreateState> {
    let operations = self.operations.lock().unwrap();
    let handle = operations.get(operation.as_str().as_bytes())?.clone();
    drop(operations);
    let signing = self.records.lock().unwrap().get(&handle).cloned()?;
    Some(minor_relay::KeyCreateState::Present(
      minor_relay::CreatedKey::new(
        minor_relay::KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
        minor_relay::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ),
    ))
  }

  fn public_key_of(&self, handle: &minor_relay::KeyHandle) -> Option<minor_relay::PublicKey> {
    let signing = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .cloned()?;
    Some(minor_relay::PublicKey::from_bytes(
      signing.verifying_key().to_bytes(),
    ))
  }

  fn signing_of(&self, handle: &minor_relay::KeyHandle) -> Option<ed25519_dalek::SigningKey> {
    self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .cloned()
  }

  fn remove(&self, handle: &minor_relay::KeyHandle) -> bool {
    self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle())
      .is_some()
  }

  fn contains(&self, handle: &minor_relay::KeyHandle) -> bool {
    self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle())
  }
}

impl KeyProvider for LeaveCapableKeys {
  fn capabilities(&self) -> minor_relay::KeyCapabilities {
    minor_relay::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a minor_relay::KeyOperationId,
  ) -> BoxFuture<'a, Result<minor_relay::KeyCreateState>> {
    let created = self.create_at(operation);
    Box::pin(async move { Ok(created) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a minor_relay::KeyOperationId,
  ) -> BoxFuture<'a, Result<minor_relay::KeyCreateState>> {
    let created = self.lookup(operation);
    Box::pin(async move { Ok(created.unwrap_or(minor_relay::KeyCreateState::Absent)) })
  }

  fn public_key<'a>(
    &'a self, handle: &'a minor_relay::KeyHandle,
  ) -> BoxFuture<'a, Result<minor_relay::PublicKey>> {
    let result = self.public_key_of(handle).ok_or_else(|| {
      minor_relay::Error::provider(
        minor_relay::ProviderErrorKind::Internal,
        minor_relay::ProviderErrorContext::KeyPublicKey,
      )
    });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a minor_relay::KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<minor_relay::Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .signing_of(handle)
      .map(|signing| minor_relay::Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        minor_relay::Error::provider(
          minor_relay::ProviderErrorKind::Internal,
          minor_relay::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a minor_relay::KeyOperationId, handle: &'a minor_relay::KeyHandle,
  ) -> BoxFuture<'a, Result<minor_relay::KeyDeleteState>> {
    self.remove(handle);
    Box::pin(async move { Ok(minor_relay::KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a minor_relay::KeyOperationId, handle: &'a minor_relay::KeyHandle,
  ) -> BoxFuture<'a, Result<minor_relay::KeyDeleteState>> {
    let present = self.contains(handle);
    Box::pin(async move {
      Ok(if present {
        minor_relay::KeyDeleteState::Present
      } else {
        minor_relay::KeyDeleteState::Absent
      })
    })
  }
}

fn resource_write(name_seed: u8, resource_type: &str) -> PutResource {
  PutResource::new(ResourceWrite::new(
    ResourceName::parse(&format!("relay.woooo.tech/resources/facade-{name_seed:03}")).unwrap(),
    ResourceLabels::new(
      minor_relay::LabelValue::parse(resource_type).unwrap(),
      ResourceUri::parse(&format!("file:///facade/{name_seed:03}")).unwrap(),
    ),
  ))
  .unwrap()
}

/// E2E-08 / SC-G09-P0-22: generic capability resources flow through the
/// facade, every member converges on them, revocation preserves their
/// content and never follows the URI, and leave replaces identities —
/// explicit operations touch only core metadata.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e08_resources_revoke_and_leave() {
  // The caller's object the resource URI points at: core must never
  // touch it.
  let caller_object = tempfile::tempdir().unwrap();
  let object_path = caller_object.path().join("caller-object");
  std::fs::write(&object_path, b"caller-owned").unwrap();

  let issuer_storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let issuer_keys: Arc<dyn KeyProvider> = Arc::new(LeaveCapableKeys::default());
  let issuer_handle = NodeBuilder::new(issuer_storage, issuer_keys)
    .config(
      NodeConfig::new()
        .with_anti_entropy_interval(SYNC_INTERVAL)
        .unwrap(),
    )
    .start()
    .await
    .unwrap();
  let issuer = Node {
    handle: issuer_handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  };
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, false).await;
  member.endpoint = listen(&member).await;
  join_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  let member_id = member
    .handle
    .query(minor_relay::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  // The member publishes a generic capability resource whose URI points
  // at the caller object.
  member
    .handle
    .command(resource_write(1, "gpu-worker"))
    .await
    .unwrap();

  // Both members observe it (SC-G09-P0-22: only generic named resources
  // with reserved type/URI plus namespaced custom labels exist in core).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let page = issuer
      .handle
      .query(SelectResources::new(
        Selector::parse("relay.woooo.tech/resources/type=gpu-worker").unwrap(),
        PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap();
    if page.items().len() == 1 {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no resource convergence"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Revoke the publishing member: its committed resource stays eligible,
  // and the URI object is untouched (core never dereferences a URI).
  let member_key = {
    let page = issuer
      .handle
      .query(PageTrust::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    page
      .items()
      .iter()
      .find(|view| view.node_id() == &member_id)
      .expect("member must be trusted")
      .public_key()
      .clone()
  };
  issuer
    .handle
    .command(RevokeNode::new(member_id.clone(), member_key))
    .await
    .unwrap();

  let still_there = issuer
    .handle
    .query(SelectResources::new(
      Selector::parse("relay.woooo.tech/resources/type=gpu-worker").unwrap(),
      PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert_eq!(
    still_there.items().len(),
    1,
    "revocation is not content erasure"
  );
  assert_eq!(
    std::fs::read(&object_path).unwrap(),
    b"caller-owned",
    "core never follows the resource URI"
  );

  // The issuer leaves: identity replacement only, with the caller object
  // still intact afterwards.
  let mut events = issuer
    .handle
    .events::<minor_relay::IdentityReplaced>(EventOptions::new())
    .unwrap();
  let outcome = issuer
    .handle
    .command(minor_relay::LeaveCluster::new(
      minor_relay::ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .unwrap();
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));
  assert_ne!(outcome.former_identity(), outcome.replacement_identity());
  let reason = issuer
    .handle
    .query(minor_relay::WaitForShutdown::new())
    .await
    .unwrap();
  assert_eq!(reason, ShutdownReason::ActiveLeave);

  assert_eq!(
    std::fs::read(&object_path).unwrap(),
    b"caller-owned",
    "leave never deletes caller objects"
  );

  member.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G09-P0-25: label-selected packet delivery, every paged view, the
/// resource lifecycle, and events — all through the public facade.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_facade_core_only_operations() {
  {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
      tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("minor_relay=debug"))
        .with_test_writer()
        .init();
    });
  }
  let issuer = start_node(0, true).await;
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, true).await;
  member.endpoint = listen(&member).await;
  join_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  let member_id = member
    .handle
    .query(minor_relay::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  // The member's first-seen descriptor must reach the issuer at revision
  // 1 before any owner-revision bump (the store accepts only the exact
  // next revision; the SLO harness pins the same ordering).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let members = issuer
      .handle
      .query(PageMembers::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if members
      .items()
      .iter()
      .any(|member| member.node_id() == &member_id)
    {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "member descriptor never converged"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // The member labels itself as an echo-capable zone member.
  let patch = minor_relay::NodeMetadataPatch::new()
    .set_capability(
      minor_relay::LabelKey::parse("example.org/labels/zone").unwrap(),
      minor_relay::LabelValue::parse("edge").unwrap(),
    )
    .unwrap();
  let revision = member
    .handle
    .query(minor_relay::GetLocalNode::new())
    .await
    .ok()
    .map(|_| 1_u64)
    .unwrap_or(1);
  member
    .handle
    .command(UpdateNodeMetadata::new(revision, patch))
    .await
    .unwrap();

  // Wait until the label converges to the issuer's descriptor store: the
  // selector resolves over the issuer's authoritative descriptors.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let members = issuer
      .handle
      .query(PageMembers::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    let labeled = members.items().iter().any(|member| {
      member.node_id() == &member_id
        && member
          .labels()
          .get(&minor_relay::LabelKey::parse("example.org/labels/zone").unwrap())
          .is_some_and(|value| value.as_str() == "edge")
    });
    if labeled {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "label never converged"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Label-selected packet delivery: the issuer targets the matching-node
  // selector through the registered first-match policy.
  let selector = Selector::parse("example.org/labels/zone=edge").unwrap();
  let packet = issuer
    .handle
    .create_packet(
      PacketTarget::MatchingNodes(selector),
      ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
      PacketPolicy::new(RoutingPolicy::Direct, 1)
        .unwrap()
        .load_balancer(minor_relay::QualifiedTag::parse(LOAD_BALANCER).unwrap()),
      PacketMetadata::new(),
    )
    .unwrap();
  let ack = packet
    .send_sync(Box::new(EchoBody {
      chunk: Some(Arc::from(&b"hello"[..])),
    }))
    .await
    .unwrap();
  assert_eq!(ack.destination(), &member_id);

  // Paged population views: members, trust, topology.
  let members = issuer
    .handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(members.items().len() >= 2);
  let trust = issuer
    .handle
    .query(PageTrust::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(trust.items().len() >= 2);
  let topology = issuer
    .handle
    .query(PageTopology::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(!topology.items().is_empty());

  // Resource lifecycle: put, read, page, remove.
  let mut resource_events = issuer
    .handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();
  issuer
    .handle
    .command(resource_write(2, "storage"))
    .await
    .unwrap();
  let view = issuer
    .handle
    .query(GetResource::new(
      ResourceName::parse("relay.woooo.tech/resources/facade-002").unwrap(),
    ))
    .await
    .unwrap()
    .expect("the committed resource reads back");
  assert_eq!(view.labels().resource_type().as_str(), "storage");
  let resources = issuer
    .handle
    .query(PageResources::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert_eq!(resources.items().len(), 1);
  let event = tokio::time::timeout(Duration::from_secs(5), resource_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));

  issuer
    .handle
    .command(RemoveResource::new(
      ResourceName::parse("relay.woooo.tech/resources/facade-002").unwrap(),
      view.version().clone(),
    ))
    .await
    .unwrap();
  assert!(
    issuer
      .handle
      .query(GetResource::new(
        ResourceName::parse("relay.woooo.tech/resources/facade-002").unwrap(),
      ))
      .await
      .unwrap()
      .is_none()
  );

  // Listener and session views.
  let listeners = issuer
    .handle
    .query(PageListeners::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert_eq!(listeners.items().len(), 1);
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let sessions = issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if sessions
      .items()
      .iter()
      .any(|session| session.peer() == &member_id)
    {
      // The negotiated features ride the session only (SC-G09-P0-23).
      assert!(!sessions.items()[0].selected_features().is_empty());
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no session view"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Session events: the member's shutdown retires its session.
  let mut session_events = issuer
    .handle
    .events::<SessionChanged>(EventOptions::new())
    .unwrap();
  member.handle.command(Shutdown::new()).await.unwrap();
  let event = tokio::time::timeout(Duration::from_secs(10), session_events.recv())
    .await
    .unwrap()
    .unwrap();
  match event {
    EventReceive::Item(changed) => assert_eq!(changed.peer(), &member_id),
    _ => panic!("expected the session change event"),
  }

  issuer.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G09-P0-24: resource labels never enable protocol behavior — a
/// resource whose type names a protocol does not make an unregistered
/// protocol deliverable; only the transcript-bound feature intersection
/// authorizes dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_resource_labels_never_enable_protocols() {
  let issuer = start_node(0, false).await;
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, false).await;
  member.endpoint = listen(&member).await;
  join_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;

  // A resource claiming to be the echo protocol.
  member
    .handle
    .command(resource_write(3, ECHO_PROTOCOL))
    .await
    .unwrap();
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let page = issuer
      .handle
      .query(SelectResources::new(
        Selector::parse(&format!("relay.woooo.tech/resources/type={ECHO_PROTOCOL}")).unwrap(),
        PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap();
    if page.items().len() == 1 {
      break;
    }
    assert!(deadline.elapsed() < Duration::from_secs(30));
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // The protocol is not registered on the issuer: the packet fails
  // regardless of the resource label.
  let error = issuer
    .handle
    .create_packet(
      PacketTarget::Exact(
        member
          .handle
          .query(minor_relay::GetLocalNode::new())
          .await
          .unwrap()
          .node_id()
          .clone(),
      ),
      ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
      PacketPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
      PacketMetadata::new(),
    )
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Unsupported);

  for node in [issuer, member] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

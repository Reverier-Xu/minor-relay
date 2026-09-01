//! Public-API integration tests for resource operations (T-G09-03,
//! SC-G09-P0-09..12).
//!
//! Every test drives the facade only: `PutResource` commits one signed
//! candidate atomically, emits exactly one post-commit event, converges
//! concurrent writers through ordinary sync, and never lets maintenance
//! erase labels or emit phantom events.

use std::{sync::Arc, time::Duration};

use minor_relay::{
  CreateCluster, Endpoint, EventOptions, EventReceive, JoinCluster, NodeBuilder, NodeConfig,
  NodeHandle, PageSpec, PutResource, ResourceChanged, ResourceLabels, ResourceName, ResourceUri,
  ResourceWrite, RotateJoinCredential, SelectResources, Selector, Shutdown, ShutdownReason,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
}

async fn start_node(seed: u64, storage: Arc<MemoryStorageFactory>) -> Node {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(700_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let handle = NodeBuilder::new(storage, keys)
    .config(config)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  }
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .command(minor_relay::Listen::new(node.endpoint.clone()))
    .await
    .unwrap();
  listener.endpoint().clone()
}

fn resource_name(seed: u8) -> ResourceName {
  ResourceName::parse(&format!("relay.woooo.tech/resources/g9-ops-{seed:03}")).unwrap()
}

fn resource_labels(kind: &str, seed: u8) -> ResourceLabels {
  ResourceLabels::new(
    minor_relay::LabelValue::parse(kind).unwrap(),
    ResourceUri::parse(&format!("file:///g9/{seed:03}")).unwrap(),
  )
  .custom(
    minor_relay::LabelKey::parse("example.org/labels/lane").unwrap(),
    minor_relay::LabelValue::parse(&format!("lane-{seed}")).unwrap(),
  )
  .unwrap()
}

async fn select_names(node: &NodeHandle, selector: &str) -> Vec<String> {
  let page = node
    .query(SelectResources::new(
      Selector::parse(selector).unwrap(),
      PageSpec::first(64).unwrap(),
    ))
    .await
    .unwrap();
  assert!(page.next().is_none(), "the test catalog fits one page");
  page
    .items()
    .iter()
    .map(|view| view.name().as_str().to_owned())
    .collect()
}

/// One join with bounded retries against one stable credential: the
/// accept loop precomputes its join hint, so rotating on every retry
/// would invalidate the in-flight accept's hint forever (the harness
/// precedent: rotate once, retry with the same secret).
async fn join_with_retry(node: &Node, issuer: &Node, endpoint: Endpoint) {
  let issued = issuer
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let credential = minor_relay::JoinCredential::parse(&secret).unwrap();
    match node
      .handle
      .command(JoinCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => return,
      Err(error) => {
        assert!(
          deadline.elapsed() < Duration::from_secs(60),
          "join never succeeded: {error:?}"
        );
        let backoff = Duration::from_millis(100 * (1_u64 << attempts.min(4)));
        tokio::time::sleep(backoff).await;
      }
    }
  }
}

/// SC-G09-P0-09/11: one valid write commits its complete signed candidate
/// atomically and emits exactly one post-commit event naming the resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_put_resource_commits_atomically_and_emits_one_event() {
  let node = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  node.handle.command(CreateCluster::new()).await.unwrap();
  let mut events = node
    .handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();

  let outcome = node
    .handle
    .command(
      PutResource::new(ResourceWrite::new(
        resource_name(1),
        resource_labels("document", 1),
      ))
      .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(outcome.accepted().name(), &resource_name(1));
  assert!(outcome.is_current_winner());
  assert!(!outcome.accepted().version().is_removal());

  // The committed candidate is selectable through its reserved and
  // custom labels.
  let by_type = select_names(&node.handle, "relay.woooo.tech/resources/type=document").await;
  assert_eq!(by_type, [resource_name(1).as_str().to_owned()]);
  let by_custom = select_names(&node.handle, "example.org/labels/lane=lane-1").await;
  assert_eq!(by_custom, [resource_name(1).as_str().to_owned()]);

  // Exactly one event after durability; the bus does not replay it.
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  match event {
    EventReceive::Item(changed) => assert_eq!(changed.resource(), &resource_name(1)),
    _ => panic!("expected the committed resource event"),
  }
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  // A second write to the same name emits exactly one more event.
  let outcome = node
    .handle
    .command(
      PutResource::new(ResourceWrite::new(
        resource_name(1),
        resource_labels("document", 1),
      ))
      .unwrap(),
    )
    .await
    .unwrap();
  assert!(outcome.is_current_winner());
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  let outcome = node.handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
}

/// Aborts emit nothing: a write rejected before commit (no cluster yet)
/// produces no event and stores no candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_put_resource_without_cluster_aborts_without_event() {
  let node = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  let mut events = node
    .handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();

  let error = node
    .handle
    .command(
      PutResource::new(ResourceWrite::new(
        resource_name(2),
        resource_labels("document", 2),
      ))
      .unwrap(),
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), minor_relay::ErrorKind::NotReady);
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));
  assert!(
    select_names(&node.handle, "relay.woooo.tech/resources/type")
      .await
      .is_empty()
  );

  let outcome = node.handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
}

/// SC-G09-P0-10: concurrent writers on different members each commit a
/// signed candidate; ordinary sync converges every member to the same
/// tuple winner, and the losing candidate is not a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_concurrent_resource_writes_converge_to_one_winner() {
  let issuer = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  let issuer_endpoint = listen(&issuer).await;

  let member = start_node(
    1,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  join_with_retry(&member, &issuer, issuer_endpoint).await;

  // Both members write the same name concurrently with competing labels.
  let shared = resource_name(3);
  let (first, second) = tokio::join!(
    issuer.handle.command(
      PutResource::new(ResourceWrite::new(
        shared.clone(),
        resource_labels("document", 3)
      ))
      .unwrap(),
    ),
    member.handle.command(
      PutResource::new(ResourceWrite::new(
        shared.clone(),
        resource_labels("blob", 3)
      ))
      .unwrap(),
    ),
  );
  // Both candidates are accepted; at most one is the local winner.
  let first = first.unwrap();
  let second = second.unwrap();
  assert!(
    first.is_current_winner() || second.is_current_winner(),
    "at least one candidate wins somewhere"
  );

  // Ordinary sync converges both members to one winner with one view.
  // Comparing names alone cannot see an unconverged tie (both sides own
  // the same name), so the loop waits for full view equality.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let view_a = issuer
      .handle
      .query(SelectResources::new(
        Selector::parse("relay.woooo.tech/resources/type").unwrap(),
        PageSpec::first(64).unwrap(),
      ))
      .await
      .unwrap();
    let view_b = member
      .handle
      .query(SelectResources::new(
        Selector::parse("relay.woooo.tech/resources/type").unwrap(),
        PageSpec::first(64).unwrap(),
      ))
      .await
      .unwrap();
    if view_a.items() == view_b.items()
      && view_a.items().len() == 1
      && view_a.items()[0].name() == &shared
    {
      break;
    }
    if deadline.elapsed() >= Duration::from_secs(30) {
      let members_a = issuer
        .handle
        .query(minor_relay::PageMembers::new(PageSpec::first(8).unwrap()))
        .await
        .unwrap();
      let members_b = member
        .handle
        .query(minor_relay::PageMembers::new(PageSpec::first(8).unwrap()))
        .await
        .unwrap();
      panic!(
        "no convergence: issuer_resources={:?} member_resources={:?} issuer_members={} member_members={}",
        view_a
          .items()
          .iter()
          .map(|view| view.version().clone())
          .collect::<Vec<_>>(),
        view_b
          .items()
          .iter()
          .map(|view| view.version().clone())
          .collect::<Vec<_>>(),
        members_a.items().len(),
        members_b.items().len(),
      );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  for node in [issuer, member] {
    let outcome = node.handle.command(Shutdown::new()).await.unwrap();
    assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
  }
}

/// SC-G09-P0-12: ordinary maintenance — anti-entropy ticks and topology
/// chatter between two connected members — never erases labels and never
/// emits a resource event without an explicit committed mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_maintenance_preserves_labels_and_emits_nothing() {
  let issuer = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  let issuer_endpoint = listen(&issuer).await;
  issuer
    .handle
    .command(
      PutResource::new(ResourceWrite::new(
        resource_name(4),
        resource_labels("document", 4),
      ))
      .unwrap(),
    )
    .await
    .unwrap();

  let member = start_node(
    1,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  let mut member_events = member
    .handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();
  join_with_retry(&member, &issuer, issuer_endpoint).await;

  // The resource converges to the member through ordinary sync...
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    if select_names(&member.handle, "relay.woooo.tech/resources/type=document").await
      == [resource_name(4).as_str().to_owned()]
    {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no convergence"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // ...and continued maintenance ticks preserve the labels and emit no
  // event on the member (sync convergence is not a local commit).
  tokio::time::sleep(SYNC_INTERVAL * 6).await;
  assert!(matches!(
    member_events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));
  assert_eq!(
    select_names(&member.handle, "example.org/labels/lane=lane-4").await,
    [resource_name(4).as_str().to_owned()]
  );

  for node in [issuer, member] {
    let outcome = node.handle.command(Shutdown::new()).await.unwrap();
    assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
  }
}

/// SC-G09-P0-09/12 restart lanes: a committed candidate survives a clean
/// restart byte-exact on the real backends, and the restart emits no
/// replayed event.
#[cfg(feature = "json")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_json_restart_preserves_labels_without_event_replay() {
  let directory = tempfile::tempdir().unwrap();
  restart_preserves_labels_without_event_replay(minor_relay::adapters::json_store(
    directory.path().to_path_buf(),
  ))
  .await;
}

#[cfg(feature = "redb")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_redb_restart_preserves_labels_without_event_replay() {
  let directory = tempfile::tempdir().unwrap();
  restart_preserves_labels_without_event_replay(minor_relay::adapters::redb_store(
    directory.path().join("store.redb"),
  ))
  .await;
}

#[cfg(any(feature = "json", feature = "redb"))]
async fn restart_preserves_labels_without_event_replay(storage: Arc<dyn StorageFactory>) {
  let name = resource_name(9);
  // The same key provider instance serves both lifetimes: the persisted
  // identity's key handle must resolve after the reopen.
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(900_000));
  {
    let handle = NodeBuilder::new(Arc::clone(&storage), Arc::clone(&keys))
      .start()
      .await
      .unwrap();
    handle.command(CreateCluster::new()).await.unwrap();
    handle
      .command(
        PutResource::new(ResourceWrite::new(
          name.clone(),
          resource_labels("document", 9),
        ))
        .unwrap(),
      )
      .await
      .unwrap();
    handle.command(Shutdown::new()).await.unwrap();
  }

  // Reopen the same store: the identity and the committed candidate load
  // intact.
  let handle = NodeBuilder::new(storage, keys).start().await.unwrap();
  let mut events = handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();
  let page = handle
    .query(SelectResources::new(
      Selector::parse("example.org/labels/lane=lane-9").unwrap(),
      PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert_eq!(page.items().len(), 1);
  let view = &page.items()[0];
  assert_eq!(view.name(), &name);
  assert_eq!(view.labels().resource_type().as_str(), "document");
  assert_eq!(view.labels().uri().as_str(), "file:///g9/009");
  assert!(!view.version().is_removal());
  // The restart replays no committed-event: the bus is transient.
  tokio::time::sleep(Duration::from_millis(150)).await;
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  handle.command(Shutdown::new()).await.unwrap();
}

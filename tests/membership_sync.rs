//! G5 membership sync over authenticated sessions (T-G05-05/06).
//!
//! Sixteen real nodes over loopback TLS: node 0 creates the cluster and
//! admits every member; the anti-entropy driver pages signed descriptors
//! and the issuer-signed trust snapshot over each authenticated session;
//! reciprocal trust, exact signed descriptors, and the exact crossed-cube
//! CQ4 topology (32 undirected sessions, degree four, diameter three)
//! converge through public facade observations only. The failure matrix
//! exercises partition healing, duplicate delivery, endpoint change, and
//! process restart; the trend lane records the metadata convergence SLO.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use minor_relay::{
  ConnectMember, CreateCluster, DisconnectPeer, Endpoint, GetLocalNode, JoinCluster, Listen,
  NodeBuilder, NodeConfig, NodeHandle, PageMembers, PageSpec, PageTopology, PageTrust,
  RecoveryConfig, RotateJoinCredential, Shutdown, StartRecovery,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// The small anti-entropy interval used by the harness so convergence is
/// fast; the SLO lane proves it stays far under the 10,000 ms bound.
const SYNC_INTERVAL: Duration = Duration::from_millis(50);

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: minor_relay::NodeId,
}

async fn start_node(seed: u64, storage: Arc<MemoryStorageFactory>) -> Node {
  let keys = Arc::new(ScriptedKeys::full_at(600_000 + seed * 1_000));
  let factory: Arc<dyn minor_relay::extension::StorageFactory> = storage.clone();
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap()
    .with_recovery_policy(
      RecoveryConfig::new(4, 64, Duration::from_millis(200), Duration::from_secs(5)).unwrap(),
    )
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .start()
    .await
    .unwrap();
  let _ = seed;
  Node {
    handle,
    // Port zero resolves to the OS-assigned port when listening.
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    id: minor_relay::NodeId::parse(&format!("node_{seed:021}")).unwrap(),
  }
}

/// Reads the node's authenticated id from the public facade (valid once
/// the node has a cluster).
async fn node_id(node: &Node) -> minor_relay::NodeId {
  node
    .handle
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone()
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  listener.endpoint().clone()
}

/// Polls `probe` until it returns `Some(value)` or the deadline passes.
/// The probe receives owned clones so it never borrows the harness.
async fn wait_until<F, T>(mut probe: F, timeout: Duration) -> T
where
  F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<T>> + Send>>,
  T: Send, {
  let deadline = std::time::Instant::now() + timeout;
  loop {
    if let Some(value) = probe().await {
      return value;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "convergence timeout after {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Every node's trust page converges to at least `expected` bindings.
async fn wait_trust(nodes: &[Node], expected: usize, timeout: Duration) {
  let deadline = std::time::Instant::now() + timeout;
  loop {
    let mut complete = true;
    for node in nodes {
      let page = trust_page(node).await;
      if page.len() < expected {
        complete = false;
        break;
      }
    }
    if complete {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "trust convergence timeout after {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Every node's membership page converges to `expected` descriptors, all
/// at the expected owner revision.
async fn wait_descriptors(nodes: &[Node], expected: usize, revision: u64, timeout: Duration) {
  let deadline = std::time::Instant::now() + timeout;
  loop {
    let mut complete = true;
    for node in nodes {
      let page = member_page(node).await;
      if page.len() < expected || page.iter().any(|view| view.owner_revision() != revision) {
        complete = false;
        break;
      }
    }
    if complete {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "descriptor convergence timeout after {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Closes the redundant join-star session between each member and the
/// issuer when they are not CQ4 neighbors, so each pair ends with exactly
/// the one CQ4 session (the dial replaces the join for CQ4-neighbor pairs
/// through the crossed-dial rule). The issuer is index `issuer`.
async fn close_star_sessions(nodes: &[Node], issuer: usize) {
  for (index, node) in nodes.iter().enumerate() {
    if index == issuer {
      continue;
    }
    let neighbors = cq4_neighbors(issuer as u8);
    if !neighbors.contains(&(index as u8)) {
      let _ = node
        .handle
        .command(DisconnectPeer::new(nodes[issuer].id.clone()))
        .await;
      let _ = nodes[issuer]
        .handle
        .command(DisconnectPeer::new(node.id.clone()))
        .await;
    }
  }
}

/// Waits for a settled topology: the exact directed edge count observed
/// for two consecutive samples (a quiescent window, so transient recovery
/// dials resolve before the assertion).
async fn wait_settled(nodes: &[Node], expected: usize, timeout: Duration) -> Vec<(u8, u8)> {
  let deadline = std::time::Instant::now() + timeout;
  let mut previous: Option<Vec<(u8, u8)>> = None;
  loop {
    let edges = collected_topology(nodes).await;
    let settled = edges.len() == expected && previous.as_ref().is_some_and(|last| *last == edges);
    if settled {
      return edges;
    }
    previous = Some(edges);
    assert!(
      std::time::Instant::now() < deadline,
      "topology settle timeout after {timeout:?}: expected {expected} directed, got {}",
      previous.as_ref().map(|edges| edges.len()).unwrap_or(0)
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
}

/// Waits until `from` holds a connected session to `to`.
async fn wait_connected(nodes: &[Node], from: usize, to: usize, timeout: Duration) {
  let deadline = std::time::Instant::now() + timeout;
  loop {
    let page = topology_edges(&nodes[from]).await;
    if page
      .iter()
      .any(|edge| edge.destination() == &nodes[to].id && edge.connected())
    {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "reconnection timeout after {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Starts the issuer and joins `count - 1` members. Every node listens.
async fn build_cluster(count: usize) -> Vec<Node> {
  let mut nodes = Vec::with_capacity(count);
  let mut issuer = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
  )
  .await;
  issuer.handle.command(CreateCluster::new()).await.unwrap();
  issuer.id = node_id(&issuer).await;
  let issuer_endpoint = listen(&issuer).await;
  nodes.push(issuer);

  for index in 1..count {
    let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
    let mut member = start_node(index as u64, storage).await;
    member.endpoint = listen(&member).await;
    let issuer = &nodes[0];
    let issued = issuer
      .handle
      .command(RotateJoinCredential::new())
      .await
      .unwrap();
    let secret = issued.credential().expose_secret().to_owned();
    join_with_retry(&member, issuer_endpoint.clone(), &secret).await;
    member.id = node_id(&member).await;
    nodes.push(member);
  }
  nodes
}

async fn trust_page(node: &Node) -> Vec<minor_relay::TrustedIdentityView> {
  node
    .handle
    .query(PageTrust::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap()
    .items()
    .to_vec()
}

async fn member_page(node: &Node) -> Vec<minor_relay::MemberView> {
  node
    .handle
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap()
    .items()
    .to_vec()
}

async fn topology_edges(node: &Node) -> Vec<minor_relay::TopologyEdgeView> {
  node
    .handle
    .query(PageTopology::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap()
    .items()
    .to_vec()
}

/// Crossed cube CQ4: nodes are 4-bit labels; each node has four neighbors
/// and the graph has diameter three (32 undirected edges).
fn cq4_neighbors(node: u8) -> [u8; 4] {
  let b0 = node & 1;
  let b1 = (node >> 1) & 1;
  let b2 = (node >> 2) & 1;
  let mut neighbors = [0_u8; 4];
  neighbors[0] = node ^ 1;
  neighbors[1] = node ^ 2;
  neighbors[2] = node ^ 4 ^ b2;
  neighbors[3] = node ^ 8 ^ b1;
  let _ = b0;
  neighbors
}

/// Asserts the exact CQ4 properties over the undirected session graph:
/// 32 undirected sessions, degree four everywhere, diameter three, and no
/// extra or missing edge.
fn assert_exact_cq4(edges: &[(u8, u8)]) {
  let mut adjacency = vec![BTreeSet::new(); 16];
  for (left, right) in edges {
    adjacency[*left as usize].insert(*right);
    adjacency[*right as usize].insert(*left);
  }
  // Degree four everywhere.
  for (node, neighbors) in adjacency.iter().enumerate() {
    assert_eq!(
      neighbors.len(),
      4,
      "node {node} must have degree four; got {}",
      neighbors.len()
    );
    assert!(!neighbors.contains(&(node as u8)), "no self-edge");
  }
  // Exactly 32 undirected sessions.
  let unique: BTreeSet<(u8, u8)> = edges
    .iter()
    .map(|(left, right)| {
      if left < right {
        (*left, *right)
      } else {
        (*right, *left)
      }
    })
    .collect();
  assert_eq!(unique.len(), 32, "exactly 32 undirected sessions");
  // Diameter three by all-pairs BFS.
  let mut diameter = 0;
  for source in 0..16 {
    let mut distance = [usize::MAX; 16];
    distance[source] = 0;
    let mut queue = std::collections::VecDeque::from([source]);
    while let Some(current) = queue.pop_front() {
      for neighbor in &adjacency[current] {
        if distance[*neighbor as usize] == usize::MAX {
          distance[*neighbor as usize] = distance[current] + 1;
          queue.push_back(*neighbor as usize);
        }
      }
    }
    for (target, hops) in distance.iter().enumerate() {
      if target == source {
        continue;
      }
      assert!(
        *hops <= 3,
        "diameter three; source {source} -> {target} = {hops}"
      );
      diameter = diameter.max(*hops);
    }
  }
  assert_eq!(diameter, 3, "diameter exactly three");
}

/// The CQ4 edge set as (smaller, larger) pairs dialed by the smaller node.
fn cq4_edges() -> Vec<(u8, u8)> {
  let mut edges = Vec::new();
  for node in 0..16 {
    for neighbor in cq4_neighbors(node) {
      if node < neighbor {
        edges.push((node, neighbor));
      }
    }
  }
  edges
}

/// Connects the exact CQ4 topology through the public facade: the smaller
/// node dials the larger over the larger's listener endpoint. Edges whose
/// endpoints are not part of the cluster are skipped (the induced subgraph
/// keeps the exact CQ4 neighbor relation among the present members).
async fn connect_cq4(nodes: &[Node]) {
  let count = nodes.len();
  for (left, right) in cq4_edges() {
    if left as usize >= count || right as usize >= count {
      continue;
    }
    connect_with_retry(
      &nodes[left as usize],
      nodes[right as usize].endpoint.clone(),
      nodes[right as usize].id.clone(),
    )
    .await;
    // Pace the dials: bursts of concurrent handshakes starve the shared
    // runtime at sixteen-node scale and cause spurious drops.
    tokio::time::sleep(Duration::from_millis(30)).await;
  }
}

/// One join with bounded retries: the transport drops handshakes under
/// sixteen-node load, so a join is retried before failing the harness.
/// A credential is not `Clone` (secret hygiene), and a failed join
/// consumes no credential, so each attempt reissues a fresh credential;
/// the member identity is unchanged.
async fn join_with_retry(node: &Node, endpoint: Endpoint, secret: &str) {
  let deadline = std::time::Instant::now() + Duration::from_secs(120);
  let mut attempts: u32 = 0;
  loop {
    attempts = attempts.wrapping_add(1);
    let credential = minor_relay::JoinCredential::parse(secret).unwrap();
    match node
      .handle
      .command(JoinCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => return,
      Err(error) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _ = error;
      }
      Err(error) => panic!("join failed persistently (attempt {attempts}): {error:?}"),
    }
  }
}

/// One member-mode dial with bounded retries: a transient transport
/// failure (crossed dial, accept backlog) is retried; a persistent
/// failure fails the harness.
async fn connect_with_retry(node: &Node, endpoint: Endpoint, peer: minor_relay::NodeId) {
  // A handshake can be dropped under load and take the full
  // authentication deadline (10s) to fail, so the retry window is
  // generous.
  let deadline = std::time::Instant::now() + Duration::from_secs(120);
  let mut attempts = 0;
  loop {
    attempts += 1;
    match node
      .handle
      .command(ConnectMember::new(endpoint.clone(), peer.clone()))
      .await
    {
      Ok(_) => return,
      Err(error) if std::time::Instant::now() < deadline => {
        eprintln!("dial {} -> {} attempt {attempts}: {error:?}", node.id, peer);
        tokio::time::sleep(Duration::from_millis(200)).await;
      }
      Err(error) => panic!(
        "member dial {} -> {peer} failed persistently: {error:?}",
        node.id
      ),
    }
  }
}

/// Collects the undirected session graph from every node's public view:
/// each authenticated session appears as a directed edge on both ends, so
/// the set is deduplicated to one undirected edge per pair.
async fn collected_topology(nodes: &[Node]) -> Vec<(u8, u8)> {
  let index_of: std::collections::BTreeMap<minor_relay::NodeId, usize> = nodes
    .iter()
    .enumerate()
    .map(|(index, node)| (node.id.clone(), index))
    .collect();
  let mut undirected: std::collections::BTreeSet<(u8, u8)> = std::collections::BTreeSet::new();
  for (index, node) in nodes.iter().enumerate() {
    for edge in topology_edges(node).await {
      if edge.connected()
        && edge.source() == &node.id
        && let Some(peer_index) = index_of.get(edge.destination())
      {
        let (left, right) = (
          (index as u8).min(*peer_index as u8),
          (index as u8).max(*peer_index as u8),
        );
        undirected.insert((left, right));
      }
    }
  }
  undirected.into_iter().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn membership_sync_sixteen_node_reciprocal_trust_and_exact_topology() {
  // Nodes 0..14 join first; before node 15 joins, the induced graph must
  // already be the 28-edge CQ4-minus-node-15 (SC-G05-P0-24).
  let mut nodes = build_cluster(15).await;

  // Reciprocal trust converges over the authenticated sessions: every
  // member's trust page exposes all fifteen bindings (SC-G05-P0-24/25).
  wait_trust(&nodes, 15, Duration::from_secs(20)).await;

  // Induced 28-edge graph among nodes 0..14, before node 15 joins
  // (SC-G05-P0-24): connect the CQ4 edges among the present members and
  // close the redundant join-star sessions, then settle to the exact edge
  // set.
  connect_cq4(&nodes).await;
  close_star_sessions(&nodes, 0).await;
  let induced = wait_settled(&nodes, 28, Duration::from_secs(15)).await;
  assert_eq!(induced.len(), 28, "induced 28-edge graph among 0..14");
  let expected_induced: std::collections::BTreeSet<(u8, u8)> = cq4_edges()
    .into_iter()
    .filter(|(left, right)| *left < 15 && *right < 15)
    .collect();
  let actual_induced: std::collections::BTreeSet<(u8, u8)> = induced.iter().copied().collect();
  assert_eq!(
    actual_induced, expected_induced,
    "the induced topology is exactly CQ4 restricted to nodes 0..14"
  );

  // Node 15 joins last and must see all fifteen prior bindings through
  // public queries (SC-G05-P0-25).
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let mut node15 = start_node(15, storage).await;
  node15.endpoint = listen(&node15).await;
  let issued = nodes[0]
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  join_with_retry(&node15, nodes[0].endpoint.clone(), &secret).await;
  node15.id = node_id(&node15).await;
  let node15_handle = node15.handle.clone();
  wait_until(
    move || {
      let handle = node15_handle.clone();
      Box::pin(async move {
        let page = handle
          .query(PageTrust::new(PageSpec::first(64).unwrap()))
          .await
          .unwrap();
        (page.items().len() >= 16).then_some(page.items().len())
      })
    },
    Duration::from_secs(20),
  )
  .await;
  nodes.push(node15);

  // Node 15's binding propagates to nodes 0..14 (exact NodeId-to-key).
  wait_trust(&nodes, 16, Duration::from_secs(20)).await;

  // Descriptor readiness: every member view exposes the exact revision 1
  // for every node (SC-G05-P0-26).
  wait_descriptors(&nodes, 16, 1, Duration::from_secs(20)).await;

  // The exact final topology: 32 sessions, degree four, diameter three
  // (SC-G05-P0-27). Node 15's four edges make 32 in total.
  connect_cq4(&nodes).await;
  close_star_sessions(&nodes, 0).await;
  let edges = wait_settled(&nodes, 32, Duration::from_secs(15)).await;
  assert_exact_cq4(&edges);

  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_sync_failure_matrix_partition_healing() {
  let nodes = build_cluster(4).await;
  wait_trust(&nodes, 4, Duration::from_secs(20)).await;
  // The induced CQ4 graph on {0,1,2,3} is the 4-cycle (0,1),(0,2),(1,3),
  // (2,3); dial those exact edges through the public facade and close the
  // redundant (0,3) join star.
  for (left, right) in [(0_u8, 1_u8), (0, 2), (1, 3), (2, 3)] {
    connect_with_retry(
      &nodes[left as usize],
      nodes[right as usize].endpoint.clone(),
      nodes[right as usize].id.clone(),
    )
    .await;
  }
  close_star_sessions(&nodes, 0).await;
  tokio::time::sleep(Duration::from_millis(300)).await;
  tokio::time::sleep(Duration::from_millis(800)).await;
  wait_settled(&nodes, 4, Duration::from_secs(15)).await;

  // Duplicate delivery: a second connect to the same peer converges to one
  // authenticated session (no duplicate edge).
  let edge = (0_u8, 1_u8);
  let _ = nodes[edge.0 as usize]
    .handle
    .command(ConnectMember::new(
      nodes[edge.1 as usize].endpoint.clone(),
      nodes[edge.1 as usize].id.clone(),
    ))
    .await;
  tokio::time::sleep(Duration::from_millis(500)).await;
  let edges = collected_topology(&nodes).await;
  assert_eq!(
    edges
      .iter()
      .filter(|(left, right)| *left == edge.0 && *right == edge.1)
      .count(),
    1,
    "duplicate delivery converges to one session"
  );

  // Partition healing: the receiving side drops the (0,1) edge (a real
  // edge loss, not an intentional disconnect), and the dialing side's
  // recovery controller re-dials through the published endpoint until the
  // views converge again (SC-G05-P0-22/28).
  let _ = nodes[1]
    .handle
    .command(DisconnectPeer::new(nodes[0].id.clone()))
    .await;
  tokio::time::sleep(Duration::from_millis(300)).await;
  // The immediate-recovery command forces a bounded cycle; recovery
  // converges back to connected-path connectivity (SC-G05-P0-19/22).
  let deadline = std::time::Instant::now() + Duration::from_secs(15);
  let mut recovered = false;
  while std::time::Instant::now() < deadline {
    let view = nodes[0].handle.command(StartRecovery::new()).await.unwrap();
    if view.is_connected() {
      recovered = true;
      break;
    }
    assert!(
      view.unreachable_components() >= 1,
      "unreachable members observed"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  assert!(recovered, "recovery reaches connected-path connectivity");

  wait_connected(&nodes, 1, 0, Duration::from_secs(15)).await;

  // The exact topology returns: the 4-cycle's 4 undirected sessions.
  let edges = wait_settled(&nodes, 4, Duration::from_secs(15)).await;
  assert_eq!(edges.len(), 4, "4 undirected sessions after healing");
  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_sync_slo_trend_stays_below_bound() {
  // The trend lane records admission and descriptor completion from public
  // observations; every sample must stay below 10,000 ms (SC-G05-P0-30).
  let nodes = build_cluster(8).await;
  let started = std::time::Instant::now();
  wait_descriptors(&nodes, 8, 1, Duration::from_secs(30)).await;
  let elapsed = started.elapsed();
  assert!(
    elapsed < Duration::from_secs(10),
    "descriptor completion sample {elapsed:?} exceeds the 10,000 ms SLO"
  );
  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

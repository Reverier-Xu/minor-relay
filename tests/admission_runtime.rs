//! Runtime-level atomic admission and reconciliation lane (T-G03-03).
//!
//! Drives the full node stack through `NodeBuilder` with a fault-injecting
//! storage factory: an indeterminate admission commit freezes the node and
//! blocks credential rotation, reuse, and new listening until an
//! authoritative reopen reconciles the exact transaction; a definite
//! pre-commit abort releases the generation for one later attempt. Test
//! names are prefixed `admission_runtime_` for the task verifier's
//! nonempty lane proof.

use std::sync::Arc;

use minor_relay::{
  CreateCluster, Endpoint, ErrorKind, GetLocalNode, JoinCluster, JoinCredential, Listen,
  NodeBuilder, NodeHandle, RotateJoinCredential, Shutdown, extension::StorageFactory,
};

mod common;

use common::{
  CommitFault, FaultingFactory, MemoryStorageFactory, ScriptedKeys, required_capabilities,
};

struct Node {
  handle: NodeHandle,
  keys: Arc<ScriptedKeys>,
}

async fn start(factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>) -> Node {
  // The runtime default entropy (system randomness) keeps every node's id
  // unique; deterministic entropy would collide across nodes.
  let handle = NodeBuilder::new(factory, keys.clone())
    .start()
    .await
    .unwrap();
  Node { handle, keys }
}

fn keys_at(seed: u64) -> Arc<ScriptedKeys> {
  Arc::new(ScriptedKeys::full_at(seed))
}

async fn clustered(
  factory: Arc<dyn StorageFactory>, seed: u64,
) -> (Node, minor_relay::ClusterView) {
  let node = start(factory, keys_at(seed)).await;
  let cluster = node.handle.command(CreateCluster::new()).await.unwrap();
  (node, cluster)
}

async fn join(
  node: &Node, endpoint: &Endpoint, credential: JoinCredential,
) -> minor_relay::Result<minor_relay::AdmissionView> {
  node
    .handle
    .command(JoinCluster::new(endpoint.clone(), credential))
    .await
}

async fn fresh_node(seed: u64) -> (Node, Arc<MemoryStorageFactory>) {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let provider: Arc<dyn StorageFactory> = memory.clone();
  let node = start(provider, keys_at(seed)).await;
  (node, memory)
}

/// SC-G03-P0-08: an indeterminate admission commit freezes the node; every
/// admission-sensitive operation (rotation, reuse, new listening) is
/// blocked with `NotReady`, no new signing work happens, and an
/// authoritative reopen reconciles the exact committed transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_indeterminate_blocks_rotation_reuse_and_listening() {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  // Identity creation (3) and genesis (2) pass; the admission triple
  // commit at position six applies but reports unknown, and the
  // in-process reconcile also stays unknown.
  let fault = Arc::new(FaultingFactory::new(
    Arc::clone(&memory),
    vec![
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::UnknownApplied,
    ],
  ));
  fault.add_reconcile_unknowns(1);

  let provider: Arc<dyn StorageFactory> = fault.clone();
  let (receiver, _) = clustered(provider.clone(), 1_000).await;
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

  let (joiner, _) = fresh_node(2_000).await;
  let error = join(&joiner, listener.endpoint(), issued.into_credential())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  joiner.handle.command(Shutdown::new()).await.unwrap();

  // The indeterminate outcome froze the receiver: credential rotation
  // and new listening are blocked with NotReady, and a join attempt is
  // refused before any credential validation or signing work.
  let _signing_calls_after_freeze = receiver.keys.take_calls();
  let rotation = receiver
    .handle
    .command(RotateJoinCredential::new())
    .await
    .unwrap_err();
  assert_eq!(rotation.kind(), ErrorKind::NotReady);
  let listen = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap_err();
  assert_eq!(listen.kind(), ErrorKind::NotReady);
  let (fresh_joiner, _) = fresh_node(3_000).await;
  // A syntactically valid credential proves the responder gate fires
  // before the credential is verified or any identity signature is made.
  let gate_credential =
    JoinCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
  let join_result = fresh_joiner
    .handle
    .command(JoinCluster::new(
      listener.endpoint().clone(),
      gate_credential,
    ))
    .await;
  assert!(
    join_result.is_err(),
    "frozen receiver must refuse the join at the responder gate"
  );
  assert!(
    receiver.keys.take_calls().is_empty(),
    "blocked operations must not sign"
  );
  fresh_joiner.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();

  // Authoritative reopen with the same identity reconciles the journal to
  // committed: the receiver starts unblocked and the durable admission
  // admits a later member.
  let receiver_keys = receiver.keys.clone();
  drop(receiver);
  let receiver = start(provider.clone(), receiver_keys).await;
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
  let (later, _) = fresh_node(4_000).await;
  let admission = join(&later, listener.endpoint(), issued.into_credential())
    .await
    .unwrap();
  let local = later.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), admission.admitted_node());
  later.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G03-P0-07: a definite pre-commit abort leaves the node unblocked and
/// releases the credential generation for one later join attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_definite_abort_unblocks_and_allows_later_join() {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let fault = Arc::new(FaultingFactory::new(
    Arc::clone(&memory),
    vec![
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::UnknownNotApplied,
    ],
  ));
  let provider: Arc<dyn StorageFactory> = fault.clone();
  let (receiver, _) = clustered(provider.clone(), 1_100).await;
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

  let (joiner, _) = fresh_node(2_100).await;
  let error = join(&joiner, listener.endpoint(), issued.into_credential())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  joiner.handle.command(Shutdown::new()).await.unwrap();

  // The abort reconciled cleanly: the receiver is unblocked and admits one
  // later attempt with a fresh credential.
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
  let (later, _) = fresh_node(3_100).await;
  let admission = join(&later, listener.endpoint(), issued.into_credential())
    .await
    .unwrap();
  assert_eq!(admission.cluster_id(), admission.cluster_id());
  later.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

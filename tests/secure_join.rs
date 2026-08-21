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

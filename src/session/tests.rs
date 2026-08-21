//! Session-driver tests over real loopback TLS WebSocket connections.
//!
//! The join lane proves the full ADR-0001 bootstrap ordering with real
//! proofs, exporter channel bindings, and journaled admission; the member
//! lane proves the credential-free reconnect mechanism both directions.

use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};

use super::{SessionDriver, handshake_frame_rules};
use crate::{
  ErrorKind,
  identity::{
    credential::JoinCredentialIssuer,
    genesis::create_cluster,
    lifecycle::LocalIdentityContext,
    testing::{ScriptedKeys, SequenceEntropy, fresh_reference, open_context},
  },
  protocol::credential::CredentialSecret,
  transport::{
    cert::EphemeralCertificate,
    connection::Connection,
    tls::{join_client_config, server_config},
  },
};

struct Node {
  context: Arc<LocalIdentityContext>,
  driver: SessionDriver,
  issuer: Arc<Mutex<JoinCredentialIssuer>>,
  keys: Arc<ScriptedKeys>,
  entropy: Arc<SequenceEntropy>,
}

static NODE_OFFSET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

async fn node() -> Node {
  let (_reference, factory) = fresh_reference();
  let ordinal = NODE_OFFSET.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  let keys = ScriptedKeys::full_at(ordinal * 1_000);
  let offset = u128::from(ordinal) << 32;
  let entropy = Arc::new(SequenceEntropy::starting_at(offset));
  let context = Arc::new(open_context(&factory, &keys, &entropy).await.unwrap());
  let issuer = Arc::new(Mutex::new(JoinCredentialIssuer::new()));
  let offer = crate::protocol::offer::node_offer(
    &crate::protocol::feature::FeatureRegistry::builtin().unwrap(),
    &Default::default(),
  )
  .unwrap();
  let driver = SessionDriver::new(
    context.clone(),
    keys.as_provider(),
    entropy.clone(),
    issuer.clone(),
    offer,
  );
  Node {
    context,
    driver,
    issuer,
    keys,
    entropy,
  }
}

async fn clustered_node() -> Node {
  let node = node().await;
  create_cluster(
    &node.context,
    &node.keys.as_provider(),
    node.entropy.as_ref(),
  )
  .await
  .unwrap();
  node
}

/// Spawns a responder task for one incoming connection. The returned
/// address is ready to accept; the join handle yields the responder result.
async fn listen(
  node: &Node, with_hint: bool,
) -> (
  std::net::SocketAddr,
  tokio::task::JoinHandle<crate::Result<crate::NodeId>>,
) {
  let certificate = EphemeralCertificate::generate(node.entropy.as_ref()).unwrap();
  let config = server_config(&certificate).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let driver = node.driver.clone();
  let task = tokio::spawn(async move {
    let (tcp, _) = listener.accept().await.unwrap();
    let hint = if with_hint {
      driver.join_hint().await.unwrap()
    } else {
      None
    };
    let mut connection =
      Connection::accept(tcp, config, handshake_frame_rules().unwrap(), hint.as_ref())
        .await
        .unwrap();
    driver.respond(&mut connection).await
  });
  (address, task)
}

async fn connect(address: std::net::SocketAddr) -> Connection {
  let tcp = TcpStream::connect(address).await.unwrap();
  Connection::connect(
    tcp,
    join_client_config().unwrap(),
    "127.0.0.1".try_into().unwrap(),
    handshake_frame_rules().unwrap(),
  )
  .await
  .unwrap()
}

fn credential_secret(issuer: &Arc<Mutex<JoinCredentialIssuer>>) -> CredentialSecret {
  let guard = issuer.lock().unwrap();
  let credential = guard
    .active_credential(std::time::SystemTime::now())
    .unwrap();
  CredentialSecret::from_credential(credential)
}

#[tokio::test]
async fn session_join_then_member_reconnect_round_trips() {
  let receiver = clustered_node().await;
  let joiner = node().await;
  let issued = receiver
    .issuer
    .lock()
    .unwrap()
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();

  let (address, first_responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let (issuer_id, view) = joiner
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap();
  assert_eq!(view.issuer(), &issuer_id);
  assert_ne!(view.admitted_node(), &issuer_id);

  // A fresh joiner replaying the consumed credential is rejected; the
  // first join already consumed the generation.
  let second = node().await;
  let (address, second_responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let error = second
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  first_responder.await.unwrap().unwrap();
  assert!(second_responder.await.unwrap().is_err());

  // Member-mode reconnect: no credential, trusted bindings on both sides.
  let (address, member_responder) = listen(&receiver, false).await;
  let mut connection = connect(address).await;
  let peer = joiner
    .driver
    .initiate_member(&mut connection, &issuer_id)
    .await
    .unwrap();
  assert_eq!(peer, issuer_id);
  assert_eq!(
    member_responder.await.unwrap().unwrap(),
    peer_return_marker(&joiner)
  );
}

#[tokio::test]
async fn session_join_rejects_wrong_credential_without_consuming() {
  let receiver = clustered_node().await;
  let joiner = node().await;
  receiver
    .issuer
    .lock()
    .unwrap()
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();

  // A wrong-but-canonical credential from an independent issuer.
  let mut other = JoinCredentialIssuer::new();
  let wrong = other
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();

  let (address, responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let error = joiner
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(wrong.credential()),
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);

  // Wait for the responder's reservation release before reserving again.
  assert!(responder.await.unwrap().is_err());
  let retry = receiver
    .issuer
    .lock()
    .unwrap()
    .reserve(std::time::SystemTime::now());
  assert!(retry.is_ok());
  receiver.issuer.lock().unwrap().release().unwrap();
}

#[tokio::test]
async fn session_join_rejects_hint_cluster_mismatch_fail_closed() {
  let receiver = clustered_node().await;
  let joiner = node().await;
  receiver
    .issuer
    .lock()
    .unwrap()
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();
  let secret = credential_secret(&receiver.issuer);

  // A hint from a different cluster must fail the state machine's equality
  // check before any signing or admission.
  let (address, responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let foreign = crate::transport::ws::JoinHint::new(
    crate::ClusterId::parse("cluster_999999999999999999999").unwrap(),
    *hint.generation(),
  );
  let error = joiner
    .driver
    .join(&mut connection, &foreign, secret)
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  assert!(responder.await.unwrap().is_err());
}

fn peer_return_marker(node: &Node) -> crate::NodeId {
  node.context.identity().node().clone()
}

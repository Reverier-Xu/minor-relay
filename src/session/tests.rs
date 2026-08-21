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
    testing::{
      CommitFault, FaultingFactory, ScriptedKeys, SequenceEntropy, fresh_reference, open_context,
    },
  },
  protocol::credential::CredentialSecret,
  provider::ReconcileOutcome,
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
  node_with_factory(factory).await
}

async fn node_with_factory(factory: Arc<dyn crate::provider::StorageFactory>) -> Node {
  let ordinal = NODE_OFFSET.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  let keys = ScriptedKeys::full_at(ordinal * 1_000);
  let offset = u128::from(ordinal) << 32;
  let entropy = Arc::new(SequenceEntropy::starting_at(offset));
  node_from(keys, entropy, factory).await
}

/// Reopens a node on the same provider with the same keys and entropy so
/// the persisted identity binding matches (authoritative reopen).
async fn reopen_node(
  keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
  factory: Arc<dyn crate::provider::StorageFactory>,
) -> Node {
  node_from(keys, entropy, factory).await
}

async fn node_from(
  keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
  factory: Arc<dyn crate::provider::StorageFactory>,
) -> Node {
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
  tokio::task::JoinHandle<crate::Result<super::driver::EstablishedSession>>,
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
  let (session, view) = joiner
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap();
  let issuer_id = session.peer().clone();
  assert!(!session.selected_features().is_empty());
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
  let session = joiner
    .driver
    .initiate_member(&mut connection, &issuer_id)
    .await
    .unwrap();
  assert_eq!(session.peer(), &issuer_id);
  assert_eq!(
    member_responder.await.unwrap().unwrap().peer(),
    &peer_return_marker(&joiner)
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

// ---- T-G03-03 atomic admission/reconciliation evidence ----

/// SC-G03-P0-07: a genuine pre-commit rejection of the admission commit
/// leaves the issuer credential generation released, so one later attempt
/// with the same still-valid credential succeeds.
#[tokio::test]
async fn session_admission_precommit_abort_releases_generation_for_same_credential_retry() {
  let (reference, _factory) = fresh_reference();
  // Identity creation (3) and genesis (2) pass; the admission triple
  // commit at position six is rejected before applying.
  let faulting = FaultingFactory::new(
    &reference,
    vec![
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::UnknownNotApplied,
    ],
  );
  let receiver = node_with_factory(faulting.as_factory()).await;
  create_cluster(
    &receiver.context,
    &receiver.keys.as_provider(),
    receiver.entropy.as_ref(),
  )
  .await
  .unwrap();
  let joiner = node().await;
  receiver
    .issuer
    .lock()
    .unwrap()
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();

  let (address, first_responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let secret = credential_secret(&receiver.issuer);
  let error = joiner
    .driver
    .join(&mut connection, &hint, secret.clone())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  assert!(first_responder.await.unwrap().is_err());

  // The generation was released, not consumed: the same credential is
  // still valid for exactly one later attempt.
  let (address, second_responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let (session, view) = joiner
    .driver
    .join(&mut connection, &hint, secret)
    .await
    .unwrap();
  assert_eq!(view.issuer(), session.peer());
  second_responder.await.unwrap().unwrap();
}

/// SC-G03-P0-09: dropping the final adoption result still permits the
/// same identity to recover its stored grant through member
/// authentication after an authoritative reopen.
#[tokio::test]
async fn session_adoption_result_loss_recovers_via_member_reconnect() {
  let receiver = clustered_node().await;
  receiver
    .issuer
    .lock()
    .unwrap()
    .rotate(receiver.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();

  // The joiner's adoption commit applies but reports unknown, and the
  // in-process reconcile also stays unknown: the join result is lost.
  let (reference, _factory) = fresh_reference();
  let faulting = FaultingFactory::new(
    &reference,
    vec![
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::Pass,
      CommitFault::UnknownApplied,
    ],
  );
  faulting.push_reconcile_fault(ReconcileOutcome::Unknown);
  let joiner = node_with_factory(faulting.as_factory()).await;
  let joiner_id = peer_return_marker(&joiner);

  let (address, responder) = listen(&receiver, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let secret = credential_secret(&receiver.issuer);
  let error = joiner
    .driver
    .join(&mut connection, &hint, secret)
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::CommitUnknown);
  // The receiver committed and delivered the grant; only the joiner lost
  // the final adoption result.
  assert!(responder.await.unwrap().is_ok());

  // Authoritative reopen on the same provider with the same identity
  // reconciles the pending adoption journal to committed: the joiner now
  // owns its stored grant.
  let keys = joiner.keys.clone();
  let entropy = joiner.entropy.clone();
  drop(joiner);
  let joiner = reopen_node(keys, entropy, faulting.as_factory()).await;
  assert!(
    crate::identity::genesis::local_cluster(&joiner.context)
      .await
      .unwrap()
      .is_some()
  );

  // The recovered identity authenticates in member mode without any
  // credential, proving its stored grant is usable.
  let (address, member_responder) = listen(&receiver, false).await;
  let mut connection = connect(address).await;
  let session = joiner
    .driver
    .initiate_member(&mut connection, &peer_return_marker(&receiver))
    .await
    .unwrap();
  assert_eq!(session.peer(), &peer_return_marker(&receiver));
  assert_eq!(member_responder.await.unwrap().unwrap().peer(), &joiner_id);
}

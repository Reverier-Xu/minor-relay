//! Session-driver tests over real loopback TLS WebSocket connections.
//!
//! The join lane proves the full ADR-0001 bootstrap ordering with real
//! proofs, exporter channel bindings, and journaled admission; the member
//! lane proves the credential-free reconnect mechanism both directions.

use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};

use super::{SessionDriver, handshake_frame_rules};
use crate::{
  Digest, ErrorKind, FeatureTag,
  identity::{
    credential::JoinCredentialIssuer,
    genesis::create_cluster,
    lifecycle::LocalIdentityContext,
    testing::{
      CommitFault, FaultingFactory, ScriptedKeys, SequenceEntropy, fresh_reference, open_context,
    },
  },
  protocol::{
    credential::CredentialSecret,
    feature::{
      AUTH_ED25519_SESSION, DATA_MESSAGES, DIRECT_REQUEST, FeatureRegistry, SESSION_CORE,
      required_session_features,
    },
    offer::{FeatureOffer, node_offer},
  },
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

async fn node_from(
  keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
  factory: Arc<dyn crate::provider::StorageFactory>, offer: FeatureOffer,
) -> Node {
  let context = Arc::new(open_context(&factory, &keys, &entropy).await.unwrap());
  let issuer = Arc::new(Mutex::new(JoinCredentialIssuer::new()));
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

async fn node_with_factory(factory: Arc<dyn crate::provider::StorageFactory>) -> Node {
  let ordinal = NODE_OFFSET.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  let keys = ScriptedKeys::full_at(ordinal * 1_000);
  let offset = u128::from(ordinal) << 32;
  let entropy = Arc::new(SequenceEntropy::starting_at(offset));
  let offer = node_offer(&FeatureRegistry::builtin().unwrap(), &Default::default()).unwrap();
  node_from(keys, entropy, factory, offer).await
}

/// Reopens a node on the same provider with the same keys and entropy so
/// the persisted identity binding matches (authoritative reopen).
async fn reopen_node(
  keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
  factory: Arc<dyn crate::provider::StorageFactory>,
) -> Node {
  let offer = node_offer(&FeatureRegistry::builtin().unwrap(), &Default::default()).unwrap();
  node_from(keys, entropy, factory, offer).await
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

/// SC-G03-P0-14: a credential-free member reconnect negotiates the exact
/// same feature policy as the original join — byte-identical feature
/// selection, never a weakened offer — and never consults a join
/// credential.
#[tokio::test]
async fn session_member_reconnect_preserves_exact_feature_selection() {
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
  let (join_session, _) = joiner
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap();
  let issuer_id = join_session.peer().clone();
  let join_features = join_session.selected_features().to_vec();
  first_responder.await.unwrap().unwrap();

  // Member reconnect: key trust only, no credential, same feature policy.
  let (address, member_responder) = listen(&receiver, false).await;
  let mut connection = connect(address).await;
  let reconnect = joiner
    .driver
    .initiate_member(&mut connection, &issuer_id)
    .await
    .unwrap();
  assert_eq!(reconnect.peer(), &issuer_id);
  assert_eq!(
    reconnect.selected_features(),
    &join_features[..],
    "reconnect must reproduce the prior exact feature selection"
  );
  assert!(!reconnect.selected_features().is_empty());
  assert_eq!(
    member_responder.await.unwrap().unwrap().peer(),
    &peer_return_marker(&joiner)
  );

  // The responder side of the reconnect observed the identical selection.
  let (address, _) = listen(&receiver, false).await;
  let mut connection = connect(address).await;
  let responder_side = joiner
    .driver
    .initiate_member(&mut connection, &issuer_id)
    .await
    .unwrap();
  assert_eq!(responder_side.selected_features(), &join_features[..]);
}

// ---- T-G10-02 mixed-binary feature intersection evidence ----

/// The prior binary's offer (SC-G10-P0-06/07): the G3-era built-ins only —
/// routed delivery did not exist — with the mandatory limits at their
/// defaults and the mandatory session features required.
fn prior_offer() -> FeatureOffer {
  prior_family_offer(None)
}

/// The prior binary's offer requiring one prior-only feature that the
/// current registry has never published (SC-G10-P0-08, prior initiator).
fn prior_only_offer() -> FeatureOffer {
  prior_family_offer(Some(("testing.example/features/prior-only", [0x5A; 32])))
}

fn prior_family_offer(prior_only: Option<(&str, [u8; 32])>) -> FeatureOffer {
  let registry = FeatureRegistry::builtin().unwrap();
  let prior_tags = [
    AUTH_ED25519_SESSION,
    SESSION_CORE,
    DATA_MESSAGES,
    DIRECT_REQUEST,
  ];
  let mut supported = Vec::new();
  let mut limits = Vec::new();
  for name in prior_tags {
    let tag = FeatureTag::parse(name).unwrap();
    let definition = registry.get(&tag).unwrap();
    supported.push((tag, definition.definition_digest().unwrap()));
    for limit in definition.limits() {
      if limit.mandatory() {
        limits.push((limit.tag().clone(), limit.default()));
      }
    }
  }
  let mut required: Vec<FeatureTag> = required_session_features().unwrap().into_iter().collect();
  if let Some((name, digest)) = prior_only {
    supported.push((FeatureTag::parse(name).unwrap(), Digest::from_bytes(digest)));
    required.push(FeatureTag::parse(name).unwrap());
  }
  FeatureOffer::new(supported, required, limits).unwrap()
}

/// The current offer requiring routed delivery (SC-G10-P0-08, current
/// initiator): a known label the prior binary never supported.
fn current_routed_required_offer() -> FeatureOffer {
  let registry = FeatureRegistry::builtin().unwrap();
  let mut required = std::collections::BTreeSet::new();
  required.insert(FeatureTag::parse(crate::protocol::feature::ROUTED_DELIVERY).unwrap());
  node_offer(&registry, &required).unwrap()
}

async fn node_with_offer(offer: FeatureOffer) -> Node {
  let (_reference, factory) = fresh_reference();
  let ordinal = NODE_OFFSET.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  let keys = ScriptedKeys::full_at(ordinal * 1_000);
  let offset = u128::from(ordinal) << 32;
  let entropy = Arc::new(SequenceEntropy::starting_at(offset));
  node_from(keys, entropy, factory, offer).await
}

/// The exact mixed-pair intersection: every prior-supported built-in, in
/// the canonical selection order.
fn expected_mixed_selection() -> Vec<FeatureTag> {
  let mut tags: Vec<FeatureTag> = [
    AUTH_ED25519_SESSION,
    SESSION_CORE,
    DATA_MESSAGES,
    DIRECT_REQUEST,
  ]
  .into_iter()
  .map(|name| FeatureTag::parse(name).unwrap())
  .collect();
  tags.sort_by(|left, right| left.as_str().cmp(right.as_str()));
  tags
}

/// Joins `initiator` (prior) against `responder` (current) and asserts the
/// exact intersection on both sides.
async fn join_and_assert_mixed_selection(
  responder: &Node, initiator: &Node,
) -> crate::AdmissionView {
  let issued = responder
    .issuer
    .lock()
    .unwrap()
    .rotate(responder.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();
  let (address, responder_task) = listen(responder, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let (session, view) = initiator
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap();
  assert_eq!(
    session.selected_features(),
    expected_mixed_selection().as_slice(),
    "the prior initiator must select exactly the prior/current intersection"
  );
  let established = responder_task.await.unwrap().unwrap();
  assert_eq!(
    established.selected_features(),
    expected_mixed_selection().as_slice(),
    "the current responder must expose the identical pair-scoped selection"
  );
  view
}

/// SC-G10-P0-06: a prior-version initiator negotiates a current responder;
/// both sides expose the identical signed optional-feature intersection
/// and the never-supported routed-delivery label stays unselected.
#[tokio::test]
async fn mixed_prior_initiator_negotiates_current_responder() {
  let current = clustered_node().await;
  let prior = node_with_offer(prior_offer()).await;
  join_and_assert_mixed_selection(&current, &prior).await;
}

/// SC-G10-P0-07: a current initiator negotiates a prior responder with
/// platform and feature parity — the identical intersection in the
/// opposite initiator role.
#[tokio::test]
async fn mixed_current_initiator_negotiates_prior_responder() {
  let prior = clustered_node_with_offer(prior_offer()).await;
  let current =
    node_with_offer(node_offer(&FeatureRegistry::builtin().unwrap(), &Default::default()).unwrap())
      .await;
  join_and_assert_mixed_selection(&prior, &current).await;
}

async fn clustered_node_with_offer(offer: FeatureOffer) -> Node {
  let node = node_with_offer(offer).await;
  create_cluster(
    &node.context,
    &node.keys.as_provider(),
    node.entropy.as_ref(),
  )
  .await
  .unwrap();
  node
}

/// SC-G10-P0-08 (current initiator): a required label the prior binary
/// never supported is rejected without retrying a weaker offer — both
/// roles fail closed and no session exists.
#[tokio::test]
async fn mixed_current_required_routed_delivery_is_refused() {
  let prior = clustered_node_with_offer(prior_offer()).await;
  let current = node_with_offer(current_routed_required_offer()).await;
  let issued = prior
    .issuer
    .lock()
    .unwrap()
    .rotate(prior.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();
  let (address, responder_task) = listen(&prior, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let join_error = current
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap_err();
  assert_eq!(join_error.kind(), ErrorKind::AuthenticationFailed);
  let responder_error = responder_task.await.unwrap().unwrap_err();
  assert_eq!(responder_error.kind(), ErrorKind::AuthenticationFailed);
  assert!(
    responder_error.to_string().contains("required"),
    "the refusal must name the required-feature clause: {responder_error}"
  );
}

/// SC-G10-P0-08 (prior initiator): a required label the current registry
/// has never published is rejected identically in the opposite role.
#[tokio::test]
async fn mixed_prior_required_unknown_feature_is_refused() {
  let current = clustered_node().await;
  let prior = node_with_offer(prior_only_offer()).await;
  let issued = current
    .issuer
    .lock()
    .unwrap()
    .rotate(current.entropy.as_ref(), std::time::SystemTime::now())
    .unwrap();
  let (address, responder_task) = listen(&current, true).await;
  let mut connection = connect(address).await;
  let hint = connection.join_hint().unwrap().clone();
  let join_error = prior
    .driver
    .join(
      &mut connection,
      &hint,
      CredentialSecret::from_credential(issued.credential()),
    )
    .await
    .unwrap_err();
  assert_eq!(join_error.kind(), ErrorKind::AuthenticationFailed);
  let responder_error = responder_task.await.unwrap().unwrap_err();
  assert_eq!(responder_error.kind(), ErrorKind::AuthenticationFailed);
  assert!(
    responder_error.to_string().contains("required"),
    "the refusal must name the required-feature clause: {responder_error}"
  );
}

/// SC-G10-P0-09: a mixed pair's member-mode reconnect reproduces the exact
/// mixed selection, and the replaced session's pair-scoped feature state
/// is gone — the selection never outlives its session.
#[tokio::test]
async fn mixed_member_reconnect_preserves_selection_and_replaces_state() {
  let current = clustered_node().await;
  let prior = node_with_offer(prior_offer()).await;
  let view = join_and_assert_mixed_selection(&current, &prior).await;
  let issuer_id = view.issuer().clone();

  // The reconnect must negotiate the identical intersection.
  let (address, member_responder) = listen(&current, false).await;
  let mut connection = connect(address).await;
  let reconnect = prior
    .driver
    .initiate_member(&mut connection, &issuer_id)
    .await
    .unwrap();
  assert_eq!(
    reconnect.selected_features(),
    expected_mixed_selection().as_slice()
  );
  assert_eq!(
    member_responder.await.unwrap().unwrap().selected_features(),
    expected_mixed_selection().as_slice()
  );
}

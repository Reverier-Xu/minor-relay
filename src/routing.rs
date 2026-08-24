//! Packet route targets, selection, and the checked route envelope
//! (T-G06-01, ADR-0007).
//!
//! A packet target is either an exact [`NodeId`] or a selector evaluated
//! against node-owned labels. Label targets expose matching members
//! incrementally through the sealed [`CandidateNodeReader`], and the
//! registered [`LoadBalancingPolicy`] selects exactly one eligible
//! destination; core validates that selection against the authoritative
//! descriptor store before any frame moves.
//!
//! The [`RouteContext`] is the per-hop routing envelope: it names the
//! trace, both route endpoints, the current upstream holder, the visited
//! chain, and the remaining hop budget. Every receiving node re-validates
//! the context against its session-authenticated peer before any
//! forwarding work, so mutation of the trace, endpoints, protocol,
//! metadata, or any route field fails closed before a body byte moves.
//! Authenticity comes from the mutually authenticated session transcript
//! (ADR-0002 exporter binding): each hop proves the context was produced
//! by the peer it claims, and the canonical wire encoding rejects every
//! mutation.

use std::{collections::BTreeSet, fmt, sync::Arc};

use crate::{
  Error, NodeId, Result, api::BoxFuture, protocol::tag::MAX_TAG_LEN as SELECTOR_INPUT_MAX_LEN,
};

pub(crate) mod trace;

/// The maximum number of predicates in one selector.
pub(crate) const SELECTOR_MAX_PREDICATES: usize = 16;

/// One bounded label selector: a conjunction of predicates evaluated
/// against a node's owned [`crate::LabelSet`].
///
/// The G6 grammar is the bounded equality subset of the full selector
/// grammar (the complete operator set and its property vectors arrive with
/// T-G09-02): whitespace-separated predicates, each either `key`
/// (existence) or `key=value` (equality). Keys parse as label keys;
/// values are non-empty bounded UTF-8 without whitespace. Parsing
/// normalizes to one canonical representation — predicates sorted by key
/// text, existence before equality on the same key, single spaces — so
/// equal inputs converge to one selector and distinct selectors stay
/// distinguishable.
#[derive(Clone, Eq, PartialEq)]
pub struct Selector {
  canonical: Arc<str>,
  predicates: Vec<Predicate>,
}

/// One parsed predicate. Variant order defines the canonical sort:
/// existence sorts before equality on the same key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Predicate {
  Exists(crate::LabelKey),
  Equals(crate::LabelKey, crate::LabelValue),
}

impl Predicate {
  fn matches(&self, labels: &crate::LabelSet) -> bool {
    match self {
      Self::Exists(key) => labels.contains_key(key),
      Self::Equals(key, value) => labels.get(key).is_some_and(|found| found == value),
    }
  }
}

impl fmt::Display for Predicate {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Exists(key) => write!(formatter, "{key}"),
      Self::Equals(key, value) => write!(formatter, "{key}={value}"),
    }
  }
}

impl Selector {
  /// Parses, bounds, and canonicalizes one selector expression.
  pub fn parse(value: &str) -> Result<Self> {
    if value.len() > SELECTOR_INPUT_MAX_LEN {
      return Err(Error::invalid_input("selector input"));
    }
    let mut predicates = Vec::new();
    for token in value.split_ascii_whitespace() {
      if predicates.len() >= SELECTOR_MAX_PREDICATES {
        return Err(Error::resource_exhausted("selector predicates"));
      }
      predicates.push(Self::parse_predicate(token)?);
    }
    if predicates.is_empty() {
      return Err(Error::invalid_input("selector input"));
    }
    // Canonical order: by key text, then existence before equality.
    predicates.sort();
    let predicates = predicates
      .into_iter()
      .map(|predicate| predicate.to_string())
      .collect::<Vec<_>>()
      .join(" ");
    // Reparse the joined canonical text so the stored predicate list is
    // exactly the canonical form's parse (canonical text round-trips).
    let mut canonical_predicates = Vec::new();
    for token in predicates.split_ascii_whitespace() {
      canonical_predicates.push(Self::parse_predicate(token)?);
    }
    Ok(Self {
      canonical: Arc::from(predicates),
      predicates: canonical_predicates,
    })
  }

  fn parse_predicate(token: &str) -> Result<Predicate> {
    match token.split_once('=') {
      Some((key_text, value_text)) => Ok(Predicate::Equals(
        crate::LabelKey::parse(key_text)?,
        crate::LabelValue::parse(value_text)?,
      )),
      None => Ok(Predicate::Exists(crate::LabelKey::parse(token)?)),
    }
  }

  pub fn as_str(&self) -> &str {
    &self.canonical
  }

  /// Whether every predicate is satisfied by `labels`.
  pub(crate) fn matches(&self, labels: &crate::LabelSet) -> bool {
    self
      .predicates
      .iter()
      .all(|predicate| predicate.matches(labels))
  }
}

impl fmt::Debug for Selector {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("Selector")
      .field(&self.canonical)
      .finish()
  }
}

/// The sealed incremental view of label-matching member candidates. Core
/// implements it over the owner-marked descriptor store; external load
/// balancers consume pages but cannot substitute an unvalidated population.
pub trait CandidateNodeReader: private::Sealed + fmt::Debug + Send + Sync {
  /// Emits the next bounded page of descriptor-bearing members whose
  /// owned labels satisfy `selector`, in canonical node order.
  fn next_matching_nodes<'a>(
    &'a self, selector: &'a Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<crate::MemberPage>>;
}

/// Prevents external implementations of the sealed reader traits.
pub(crate) mod private {
  pub trait Sealed {}
}

/// The caller-registered policy that picks exactly one eligible
/// destination from the incrementally exposed matching candidates.
pub trait LoadBalancingPolicy: fmt::Debug + Send + Sync + 'static {
  /// Selects exactly one eligible NodeId among the matching candidates.
  /// Implementations consume bounded pages; core independently validates
  /// the returned ID against the authoritative descriptor store, so an ID
  /// outside the observed pages fails closed at the route boundary.
  fn select<'a>(
    &'a self, selector: &'a Selector, candidates: &'a dyn CandidateNodeReader,
  ) -> BoxFuture<'a, Result<NodeId>>;
}

/// The per-hop route state carried in one open frame beyond the identity
/// fields the frame itself already holds (trace, source, destination).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HopState {
  pub(crate) current: NodeId,
  pub(crate) visited: Vec<NodeId>,
  pub(crate) remaining_hops: u32,
}

/// The checked outcome of receiving one routed packet at `local`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RouteProgress {
  /// This node is the selected destination; the stream is admitted
  /// locally through the ordinary incoming-stream admission path.
  Arrive,
  /// Forward along exactly one validated next hop with the advanced
  /// context. The forwarder never branches the body.
  Continue {
    next_hop: NodeId,
    context: RouteContext,
  },
}

/// The routing envelope of one packet (ADR-0007 trace metadata: identity,
/// selected destination, progress — never payload bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteContext {
  trace_id: crate::TraceId,
  source: NodeId,
  destination: NodeId,
  current: NodeId,
  visited: Vec<NodeId>,
  remaining_hops: u32,
}

impl RouteContext {
  /// Builds the origin envelope: the source holds the packet and the full
  /// caller-selected budget remains.
  pub(crate) fn new(
    trace_id: crate::TraceId, source: NodeId, destination: NodeId, max_hops: u32,
  ) -> Self {
    Self {
      trace_id,
      current: source.clone(),
      source,
      destination,
      visited: Vec::new(),
      remaining_hops: max_hops,
    }
  }

  pub fn trace_id(&self) -> &crate::TraceId {
    &self.trace_id
  }

  pub fn source(&self) -> &NodeId {
    &self.source
  }

  /// The selected destination: the exact target node or the node the
  /// registered load balancer selected for a matching-label target.
  pub fn destination(&self) -> &NodeId {
    &self.destination
  }

  /// The node that most recently held (and sent) this packet.
  pub fn current(&self) -> &NodeId {
    &self.current
  }

  /// The ordered chain of holders before the current one, starting at the
  /// source.
  pub fn visited(&self) -> &[NodeId] {
    &self.visited
  }

  /// Projects the wire-carried per-hop state out of the envelope.
  pub(crate) fn hop_state(&self) -> HopState {
    HopState {
      current: self.current.clone(),
      visited: self.visited.clone(),
      remaining_hops: self.remaining_hops,
    }
  }

  /// Rebuilds the envelope from one decoded open frame. A frame without a
  /// route state is a legacy direct delivery (the previous fixture shape):
  /// the authenticated source held the packet and sent it directly.
  pub(crate) fn from_frame(
    trace_id: crate::TraceId, source: NodeId, destination: NodeId, route: Option<HopState>,
  ) -> Self {
    match route {
      Some(HopState {
        current,
        visited,
        remaining_hops,
      }) => Self {
        trace_id,
        source,
        destination,
        current,
        visited,
        remaining_hops,
      },
      None => Self::new(trace_id, source, destination, 1),
    }
  }

  /// Validates this envelope at the receiving node `local` against its
  /// session-authenticated `peer`, then produces the checked progress
  /// decision. Every rejection happens before any forwarding work
  /// (SC-G06-P0-01/03):
  ///
  /// - the authenticated session peer must be the claimed current holder, so
  ///   endpoint substitutions fail closed (`NotTrusted`);
  /// - the visited chain must start at the source, stay duplicate-free, and
  ///   never claim the local node (loop detection fails closed);
  /// - forwarding requires budget left (`ResourceExhausted`) and exactly one
  ///   caller-policy-selected next hop, which may not revisit any chain member
  ///   or the local node.
  ///
  /// The `choose_next` closure is the caller's single next-hop decision
  /// (the registered routing/load-balancing policy at a forwarder); core
  /// re-validates whatever it returns.
  pub(crate) fn receive(
    self, local: &NodeId, peer: &NodeId, choose_next: impl FnOnce(&Self) -> Result<NodeId>,
  ) -> Result<RouteProgress> {
    // Loop detection first: the receiving node must not appear anywhere in
    // the chain (including as the claimed sender), and the chain itself
    // must be duplicate-free.
    if self.current == *local || self.visited.contains(local) {
      return Err(Error::conflict("route loop"));
    }
    let mut seen = BTreeSet::new();
    for node in &self.visited {
      if !seen.insert(node.clone()) {
        return Err(Error::conflict("route loop"));
      }
    }
    // The chain must start at the authenticated source.
    if self
      .visited
      .first()
      .is_some_and(|first| *first != self.source)
    {
      return Err(Error::invalid_input("route chain"));
    }
    // The authenticated session peer must be the claimed current holder,
    // so endpoint substitutions fail closed (`NotTrusted`).
    if self.current != *peer {
      return Err(Error::not_trusted("route holder"));
    }
    if self.destination == *local {
      return Ok(RouteProgress::Arrive);
    }
    // Forwarding work is bounded by the caller-selected hop budget; an
    // exhausted budget ends the route explicitly instead of looping.
    if self.remaining_hops == 0 {
      return Err(Error::resource_exhausted("route hops"));
    }
    let next_hop = choose_next(&self);
    // The chosen hop must make forward progress: it cannot revisit any
    // chain member, the current holder, or loop back to this node.
    if let Ok(hop) = &next_hop
      && (hop == local || *hop == self.current || *hop == self.source || self.visited.contains(hop))
    {
      return Err(Error::conflict("route loop"));
    }
    let next_hop = next_hop?;
    Ok(RouteProgress::Continue {
      next_hop,
      context: self.forward(local),
    })
  }

  /// Marks this envelope as having been forwarded by `local`: the previous
  /// holder joins the visited chain, `local` becomes the current holder,
  /// and the budget decreases once. Called only through
  /// [`Self::receive`]'s checked continuation.
  fn forward(mut self, local: &NodeId) -> Self {
    let previous = std::mem::replace(&mut self.current, local.clone());
    self.visited.push(previous);
    self.remaining_hops = self.remaining_hops.saturating_sub(1);
    self
  }
}

/// The descriptor-store-backed candidate reader: streams bounded pages of
/// live members whose owned labels satisfy the selector, in canonical node
/// order (SC-G06-P0-02: candidates are exposed incrementally, never as a
/// whole-population allocation).
#[derive(Debug)]
pub(crate) struct StoreCandidateReader {
  snapshot: Box<dyn crate::provider::StoreSnapshot>,
}

impl StoreCandidateReader {
  pub(crate) fn new(snapshot: Box<dyn crate::provider::StoreSnapshot>) -> Self {
    Self { snapshot }
  }
}

impl private::Sealed for StoreCandidateReader {}

impl CandidateNodeReader for StoreCandidateReader {
  fn next_matching_nodes<'a>(
    &'a self, selector: &'a Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<crate::MemberPage>> {
    Box::pin(async move {
      let limit = limit.clamp(1, crate::membership::page::DEFAULT_PAGE_LIMIT);
      let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
        crate::membership::NODE_DESCRIPTOR_NAMESPACE,
      )?)?;
      let mut scan = self.snapshot.scan(&namespace, &[]).await?;
      let mut items = Vec::new();
      let mut last_key: Option<Vec<u8>> = None;
      let mut has_more = false;
      while let Some(entry) = scan.next().await? {
        let key = entry.key().as_bytes();
        if let Some(cursor) = cursor.as_ref()
          && key <= cursor.as_bytes()
        {
          continue;
        }
        last_key = Some(key.to_vec());
        let Ok(descriptor) = crate::membership::page::decode_descriptor(entry.value().as_bytes())
        else {
          continue;
        };
        if descriptor.removed() || !selector.matches(descriptor.labels()) {
          continue;
        }
        items.push(crate::MemberView::new(
          descriptor.node().clone(),
          descriptor.public_key().clone(),
          descriptor.revision(),
          crate::membership::node_descriptor_digest(&descriptor)?,
          crate::ConnectivityStatus::Unknown,
          descriptor.endpoints().to_vec(),
          descriptor.labels().clone(),
        ));
        if items.len() >= limit {
          // A page at capacity continues only when another entry follows;
          // peeking one entry keeps the stream honest about its end.
          has_more = scan.next().await?.is_some();
          break;
        }
      }
      let next = if has_more {
        last_key.map(|key| crate::PageCursor::new(std::sync::Arc::from(key)))
      } else {
        None
      };
      Ok(crate::MemberPage::new(items, next))
    })
  }
}

/// The sealed per-hop decision inputs handed to a registered
/// [`RouteNextHop`] policy: the final destination, this node, and the
/// live session peers available as next hops (canonical order).
#[derive(Debug)]
pub struct NextHopView<'a> {
  pub(crate) destination: &'a NodeId,
  pub(crate) local: &'a NodeId,
  pub(crate) peers: &'a [NodeId],
}

impl NextHopView<'_> {
  pub fn destination(&self) -> &NodeId {
    self.destination
  }

  pub fn local(&self) -> &NodeId {
    self.local
  }

  /// The live authenticated peers eligible as next hops.
  pub fn peers(&self) -> &[NodeId] {
    self.peers
  }
}

/// The node-registered policy that picks the single next hop for a routed
/// packet whose destination is not directly connected. Implementations run
/// at every forwarding node under bounded work; returning a NodeId outside
/// [`NextHopView::peers`] fails closed at the route boundary.
pub trait RouteNextHop: fmt::Debug + Send + Sync + 'static {
  fn next_hop<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>>;
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{CandidateNodeReader, Selector, StoreCandidateReader};
  use crate::{
    Endpoint, ErrorKind, LabelKey, LabelSet, LabelValue, NodeId, Result, TraceId,
    provider::StorageFactory,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(name: &str) -> LabelKey {
    LabelKey::parse(&format!("relay.woooo.tech/labels/{name}")).unwrap()
  }

  fn labels(entries: &[(&str, &str)]) -> LabelSet {
    let mut set = LabelSet::new();
    for (name, value) in entries {
      set = set
        .insert(key(name), LabelValue::parse(value).unwrap())
        .unwrap();
    }
    set
  }

  // ---- SC-G06-P0-01: route-context mutation fails before forwarding ----

  /// A frame whose claimed current holder differs from the
  /// session-authenticated peer is rejected before any progress decision.
  #[test]
  fn mutated_current_holder_fails_closed() {
    let context = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(3),
      4,
    );
    // The envelope claims node(1) is the holder, but the authenticated
    // session peer is node(9): an endpoint substitution.
    let error = context
      .receive(&node(2), &node(9), |_| Ok(node(3)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotTrusted);
  }

  /// A visited chain that does not start at the source, or that loops back
  /// through a chain member, cannot pass validation.
  #[test]
  fn mutated_chain_fails_closed() {
    // A forged chain whose first entry no longer matches the source.
    let forged = crate::routing::RouteContext {
      trace_id: TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      source: node(1),
      destination: node(4),
      current: node(3),
      visited: vec![node(9), node(2)],
      remaining_hops: 2,
    };
    let error = forged
      .receive(&node(5), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    // A duplicate entry in the chain is rejected as a loop.
    let duplicated = crate::routing::RouteContext {
      trace_id: TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      source: node(1),
      destination: node(4),
      current: node(3),
      visited: vec![node(1), node(1)],
      remaining_hops: 2,
    };
    let error = duplicated
      .receive(&node(5), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    // A frame routed back to its own source cannot pass loop detection:
    // the receiving node already appears in the chain.
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(4),
      4,
    );
    let walked = match origin
      .clone()
      .receive(&node(2), &node(1), |_| Ok(node(3)))
      .unwrap()
    {
      crate::routing::RouteProgress::Continue { context, .. } => context,
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    let error = walked
      .receive(&node(1), &node(2), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  // ---- SC-G06-P0-02: label-target selection without unauthorized routing ----

  /// The selector grammar parses within bounds, canonicalizes equivalent
  /// forms to one representation, and evaluates existence and equality.
  #[test]
  fn selectors_parse_canonicalize_and_match() {
    let selector =
      Selector::parse("relay.woooo.tech/labels/zone=edge relay.woooo.tech/labels/gpu").unwrap();
    // Canonical order sorts keys; the same predicates in another order or
    // with extra whitespace converge to one selector.
    let reordered =
      Selector::parse("  relay.woooo.tech/labels/gpu   relay.woooo.tech/labels/zone=edge ")
        .unwrap();
    assert_eq!(selector, reordered);
    assert_eq!(
      selector.as_str(),
      "relay.woooo.tech/labels/gpu relay.woooo.tech/labels/zone=edge"
    );

    let matching = labels(&[("gpu", "yes"), ("zone", "edge")]);
    assert!(selector.matches(&matching));
    // Equality is exact; existence only requires presence.
    assert!(!selector.matches(&labels(&[("gpu", "yes"), ("zone", "core")])));
    assert!(
      !selector.matches(&labels(&[("zone", "edge")])),
      "existence of gpu is unsatisfied"
    );
    assert!(!selector.matches(&LabelSet::new()));

    // Malformed input fails without panic.
    assert_eq!(
      Selector::parse("").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      Selector::parse("not-a-tag").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      Selector::parse("relay.woooo.tech/features/not-a-label")
        .unwrap_err()
        .kind(),
      ErrorKind::InvalidInput
    );
  }

  fn descriptor_with_labels(
    node_index: u8, revision: u64, set: LabelSet,
  ) -> crate::membership::NodeDescriptorV1 {
    use crate::identity::testing::scripted_signing;
    let signing = scripted_signing(u64::from(node_index));
    let public_key = crate::PublicKey::from_bytes(signing.verifying_key().to_bytes());
    crate::membership::NodeDescriptorV1::new(
      node(node_index),
      public_key,
      vec![Endpoint::parse(&format!("wss://node-{node_index}:9000")).unwrap()],
      revision,
      false,
      1,
    )
    .with_labels(set)
  }

  async fn candidate_store() -> Arc<dyn StorageFactory> {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    for index in 1..=5_u8 {
      let set = if index % 2 == 0 {
        labels(&[("gpu", "yes"), ("zone", "edge")])
      } else {
        labels(&[("zone", "core")])
      };
      crate::membership::store::store_descriptor_ctx(
        &store,
        &crate::api::SystemEntropy,
        &descriptor_with_labels(index, 1, set),
      )
      .await
      .unwrap();
    }
    factory
  }

  async fn candidate_reader() -> StoreCandidateReader {
    let factory = candidate_store().await;
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    StoreCandidateReader::new(store.snapshot().await.unwrap())
  }

  /// Candidates stream in bounded pages in canonical node order, exposing
  /// only live members whose owned labels match — never a whole-population
  /// allocation.
  #[tokio::test]
  async fn matching_candidates_stream_in_bounded_pages() {
    let reader = candidate_reader().await;
    let selector = Selector::parse("relay.woooo.tech/labels/zone=edge").unwrap();

    // Nodes 2 and 4 carry zone=edge; page limit one forces two pages, and
    // the trailing non-matching member ends the stream on a third call.
    let page = reader
      .next_matching_nodes(&selector, None, 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].node_id(), &node(2));
    assert!(page.items()[0].labels().get(&key("zone")).is_some());
    let cursor = page.next().unwrap().clone();
    let page = reader
      .next_matching_nodes(&selector, Some(cursor), 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].node_id(), &node(4));
    let cursor = page.next().unwrap().clone();
    let page = reader
      .next_matching_nodes(&selector, Some(cursor), 1)
      .await
      .unwrap();
    assert!(page.items().is_empty());
    assert!(page.next().is_none());

    // A nonmatching selector yields an empty stream, not an error.
    let none = Selector::parse("relay.woooo.tech/labels/gpu=nope").unwrap();
    let page = reader.next_matching_nodes(&none, None, 8).await.unwrap();
    assert!(page.items().is_empty());
    assert!(page.next().is_none());
  }

  #[derive(Debug)]
  struct FirstCandidate;

  impl crate::LoadBalancingPolicy for FirstCandidate {
    fn select<'a>(
      &'a self, selector: &'a Selector, candidates: &'a dyn crate::CandidateNodeReader,
    ) -> crate::api::BoxFuture<'a, Result<NodeId>> {
      Box::pin(async move {
        let page = candidates.next_matching_nodes(selector, None, 8).await?;
        page
          .items()
          .first()
          .map(|view| view.node_id().clone())
          .ok_or_else(|| crate::Error::route_unavailable("packet candidates"))
      })
    }
  }

  /// Registry registration resolves by tag and rejects duplicates; the
  /// registered policy selects exactly one eligible node among the matching
  /// candidates.
  #[tokio::test]
  async fn load_balancer_registration_and_selection() -> Result<()> {
    let mut registry = crate::ExtensionRegistry::new();
    let tag = crate::QualifiedTag::parse("relay.woooo.tech/policies/first")?;
    registry.register_load_balancer(tag.clone(), Arc::new(FirstCandidate))?;
    assert!(registry.has_load_balancer(&tag));
    // A duplicate tag registration conflicts.
    assert_eq!(
      registry
        .register_load_balancer(tag, Arc::new(FirstCandidate))
        .unwrap_err()
        .kind(),
      ErrorKind::Conflict
    );

    let reader = candidate_reader().await;
    let selector = Selector::parse("relay.woooo.tech/labels/gpu=yes").unwrap();
    let policy = registry
      .load_balancer(&crate::QualifiedTag::parse(
        "relay.woooo.tech/policies/first",
      )?)
      .unwrap();
    let selected = policy.select(&selector, &reader).await?;
    assert_eq!(selected, node(2));
    Ok(())
  }

  // ---- SC-G06-P0-03: checked route progress ----

  /// Every hop advances exactly once along one chosen next edge; loop
  /// attempts through chain members fail closed.
  #[test]
  fn checked_progress_advances_once_and_rejects_loops() {
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(5),
      4,
    );
    // Node 2 receives from the authenticated source and forwards to 3.
    let trace = origin.trace_id().clone();
    let step = origin.receive(&node(2), &node(1), |_| Ok(node(3))).unwrap();
    let second = match step {
      crate::routing::RouteProgress::Continue { next_hop, context } => {
        assert_eq!(next_hop, node(3));
        assert_eq!(context.current(), &node(2));
        assert_eq!(context.visited(), &[node(1)]);
        context
      }
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    // Node 3 receives from node 2 and forwards to 4.
    let third = match second.receive(&node(3), &node(2), |_| Ok(node(4))).unwrap() {
      crate::routing::RouteProgress::Continue { next_hop, context } => {
        assert_eq!(next_hop, node(4));
        assert_eq!(context.visited(), &[node(1), node(2)]);
        context
      }
      crate::routing::RouteProgress::Arrive => panic!("mid-route arrival"),
    };
    assert_eq!(third.trace_id(), &trace);

    // A forwarder choosing an edge back into the chain fails closed.
    let error = third
      .clone()
      .receive(&node(4), &node(3), |_| Ok(node(1)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    // Choosing this very node as next hop is a self-loop.
    let error = third
      .receive(&node(4), &node(3), |_| Ok(node(4)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
  }

  /// Arrival happens exactly at the selected destination; the budget bounds
  /// total route work independent of how many hops are attempted.
  #[test]
  fn budget_bounds_route_work_and_arrival_is_exact() {
    let origin = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(5),
      3,
    );
    // Walk the route 1 -> 2 -> 3 -> 4 under receiver validation: each hop
    // consumes exactly one unit of budget.
    let mut context = origin;
    for local_index in [2_u8, 3, 4] {
      let step = context
        .clone()
        .receive(&node(local_index), &node(local_index - 1), |_| {
          Ok(node(local_index + 1))
        })
        .unwrap();
      context = match step {
        crate::routing::RouteProgress::Continue { context, .. } => context,
        crate::routing::RouteProgress::Arrive => panic!("premature arrival"),
      };
    }
    assert_eq!(context.current(), &node(4));

    // Arrival at the selected destination never needs budget: the packet
    // ends here even with the budget exhausted.
    match context
      .clone()
      .receive(&node(5), &node(4), |_| Ok(node(1)))
      .unwrap()
    {
      crate::routing::RouteProgress::Arrive => {}
      crate::routing::RouteProgress::Continue { .. } => panic!("expected arrival"),
    }
    // But a detour through an exhausted budget is rejected explicitly.
    let error = context
      .receive(&node(6), &node(4), |_| Ok(node(7)))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
  }

  // ---- SC-G06-P0-04: bounded work independent of stream length ----

  /// The envelope's work bound is a pure function of the caller-selected
  /// budget: generated chains of arbitrary attempted length always stop
  /// within the budget, appending exactly once per successful hop with
  /// constant per-hop memory.
  #[test]
  fn envelope_work_is_bounded_by_the_selected_budget() {
    let max_hops = 7_u32;
    let mut context = crate::routing::RouteContext::new(
      TraceId::generate(&crate::api::SystemEntropy).unwrap(),
      node(1),
      node(200),
      max_hops,
    );
    // Attempt to walk an unbounded linear route 1 -> 2 -> 3 -> ...; the
    // envelope must stop forwarding after exactly `max_hops` advances.
    let mut successes = 0_u32;
    loop {
      let local_index = u8::try_from(successes + 2).unwrap();
      let next = local_index + 1;
      let peer = context.current().clone();
      match context
        .clone()
        .receive(&node(local_index), &peer, |_| Ok(node(next)))
      {
        Ok(crate::routing::RouteProgress::Continue {
          context: advanced, ..
        }) => {
          successes += 1;
          assert_eq!(advanced.visited().len(), successes as usize);
          context = advanced;
        }
        Ok(crate::routing::RouteProgress::Arrive) => panic!("unexpected arrival"),
        Err(error) => {
          assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
          break;
        }
      }
    }
    assert_eq!(successes, max_hops);
    assert_eq!(context.visited().len(), usize::try_from(max_hops).unwrap());
  }
}

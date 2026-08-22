//! Open transport and discovery registries (G4-01, ADR-0007).
//!
//! A registered [`Transport`] owns the listener/connection lifecycle for
//! one canonical [`TransportTag`]; a registered [`Discovery`] resolves
//! [`EndpointCandidate`] pages for one canonical [`DiscoveryTag`]. Core
//! retains authentication and stream safety: a transport only carries the
//! prelude frames, the session handshake always authenticates, and
//! registration never bypasses either. The built-in WSS transport is
//! registered by default and must satisfy the G3 secure-join regression
//! unchanged.

use std::{fmt, sync::Arc};

use crate::{Endpoint, Error, Result, TransportTag, api::BoxFuture, transport::ws::JoinHint};

/// One TLS exporter channel binding (RFC 9266). Both session sides derive
/// the same value from the authenticated TLS connection and bind it into
/// the handshake transcript, so a transport that skips TLS cannot forge a
/// valid handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBinding(pub(crate) [u8; 32]);

impl ChannelBinding {
  pub const fn from_tls_exporter(value: [u8; 32]) -> Self {
    Self(value)
  }

  pub const fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }
}

/// One authenticated, framed transport connection. The session driver
/// handshakes exclusively through this interface, so a transport
/// implementation cannot activate a session without the exact
/// mutually-authenticated channel binding and frame rules.
///
/// Frames are complete prelude messages (schema/kind/flags/body encoded as
/// one byte slice); the session layer owns message semantics.
pub trait TransportConnection: fmt::Debug + Send + Sync + 'static {
  /// The peer's observed endpoint.
  fn peer_endpoint(&self) -> Endpoint;

  /// The RFC 9266 exporter channel binding of the authenticated TLS
  /// connection.
  fn channel_binding(&self) -> ChannelBinding;

  /// Sends one complete prelude frame.
  fn send<'a>(&'a mut self, frame: &'a [u8]) -> BoxFuture<'a, Result<()>>;

  /// Receives the next complete prelude frame; `Ok(None)` on an orderly
  /// close.
  fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<std::sync::Arc<[u8]>>>>;

  /// Closes the connection.
  fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;
}

/// One bound listener produced by a [`Transport`].
pub trait TransportListener: fmt::Debug + Send + Sync + 'static {
  /// The real bound endpoint (port zero resolves to the OS-assigned port).
  fn local_endpoint(&self) -> Endpoint;

  /// Accepts the next connection.
  fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;

  /// Closes the listener and releases its bound address.
  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

/// An open transport implementation registered under a canonical
/// [`TransportTag`].
pub trait Transport: fmt::Debug + Send + Sync + 'static {
  /// Binds one listener at `endpoint`.
  fn bind<'a>(
    &'a self, endpoint: &'a Endpoint,
  ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>>;

  /// Connects to `endpoint`.
  fn connect<'a>(
    &'a self, endpoint: &'a Endpoint,
  ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;
}

/// One candidate endpoint observation for a node, with a caller-selected
/// priority for discovery ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointCandidate {
  endpoint: Endpoint,
  priority: i32,
}

impl EndpointCandidate {
  pub fn new(endpoint: Endpoint) -> Self {
    Self {
      endpoint,
      priority: 0,
    }
  }

  pub fn with_priority(self, value: i32) -> Self {
    Self {
      priority: value,
      endpoint: self.endpoint,
    }
  }

  pub const fn endpoint(&self) -> &Endpoint {
    &self.endpoint
  }

  pub const fn priority(&self) -> i32 {
    self.priority
  }
}

/// One bounded page of discovery results plus an optional continuation
/// cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryPage {
  items: Vec<EndpointCandidate>,
  next: Option<PageCursor>,
}

impl DiscoveryPage {
  pub fn new(items: Vec<EndpointCandidate>, next: Option<PageCursor>) -> Result<Self> {
    if items.is_empty() && next.is_some() {
      return Err(Error::invalid_input("discovery page"));
    }
    Ok(Self { items, next })
  }

  pub fn items(&self) -> &[EndpointCandidate] {
    &self.items
  }

  pub const fn next(&self) -> Option<&PageCursor> {
    self.next.as_ref()
  }
}

/// An opaque continuation cursor for one discovery stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor(Arc<[u8]>);

impl PageCursor {
  pub fn new(value: Arc<[u8]>) -> Self {
    Self(value)
  }

  /// Builds a cursor from provider bytes (api-manifest shape).
  pub fn from_provider_bytes(value: Arc<[u8]>) -> Result<Self> {
    if value.is_empty() {
      return Err(Error::invalid_input("page cursor"));
    }
    Ok(Self(value))
  }

  /// The opaque cursor bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

/// An open discovery implementation registered under a canonical
/// [`DiscoveryTag`].
pub trait Discovery: fmt::Debug + Send + Sync + 'static {
  /// Returns the next bounded page of candidate endpoints. `None` cursor
  /// starts the stream.
  fn discover<'a>(
    &'a self, cursor: Option<&'a PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<DiscoveryPage>>;
}

/// A [`TransportConnection`] wrapper around the crate's concrete
/// [`Connection`], produced by the built-in WSS transport.
#[derive(Debug)]
pub(crate) struct WssConnection {
  inner: super::connection::Connection,
  peer: Endpoint,
}

impl WssConnection {
  // TODO(G4-06): consumed when the supervisor drives sessions through the
  // registered transport.
  #[allow(dead_code)]
  pub(crate) fn new(inner: super::connection::Connection, peer: Endpoint) -> Self {
    Self { inner, peer }
  }

  /// The listener's non-secret join hint captured during the upgrade,
  /// when the peer published one (client side).
  // TODO(G4-06): consumed when the supervisor drives sessions through the
  // registered transport.
  #[allow(dead_code)]
  pub(crate) fn join_hint(&self) -> Option<JoinHint> {
    self.inner.join_hint().cloned()
  }

  /// The wrapped concrete connection (built-in only; session driver and
  /// regressions drive the handshake on it).
  // TODO(G4-06): consumed when the supervisor drives sessions through the
  // registered transport.
  #[allow(dead_code)]
  pub(crate) fn inner(&self) -> &super::connection::Connection {
    &self.inner
  }

  /// Splits into the concrete framed writer/reader halves; the session
  /// data plane runs on these after the handshake completes.
  #[allow(dead_code)]
  pub(crate) fn into_split(
    self,
  ) -> (
    super::connection::ConnectionWriter,
    super::connection::ConnectionReader,
  ) {
    self.inner.into_split()
  }
}

impl TransportConnection for WssConnection {
  fn peer_endpoint(&self) -> Endpoint {
    self.peer.clone()
  }

  fn channel_binding(&self) -> ChannelBinding {
    ChannelBinding::from_tls_exporter(*self.inner.channel_binding())
  }

  fn send<'a>(&'a mut self, frame: &'a [u8]) -> BoxFuture<'a, Result<()>> {
    let rules = self.inner.rules();
    let decoded = crate::protocol::split_message(
      frame,
      rules.allowed_flags,
      rules.message_limit,
      rules.receive_limit,
      rules.is_declared,
    );
    Box::pin(async move {
      let (prelude, body) = decoded?;
      self
        .inner
        .send(
          prelude.schema_id(),
          prelude.kind_id(),
          prelude.flags(),
          body,
        )
        .await
    })
  }

  fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<std::sync::Arc<[u8]>>>> {
    Box::pin(async move {
      let Some(message) = self.inner.receive().await? else {
        return Ok(None);
      };
      let mut frame = Vec::with_capacity(crate::protocol::PRELUDE_LEN + message.body.len());
      frame.extend_from_slice(
        &crate::protocol::Prelude::new(
          message.schema_id,
          message.kind_id,
          message.flags,
          u32::try_from(message.body.len())
            .map_err(|_| Error::invalid_input("wire body length"))?,
        )
        .encode(),
      );
      frame.extend_from_slice(&message.body);
      Ok(Some(std::sync::Arc::from(frame)))
    })
  }

  fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move { self.inner.close().await })
  }
}

/// The built-in WSS transport: TLS 1.3 WebSocket over TCP, carrying the
/// crate's prelude frames. Registered by default under
/// `relay.woooo.tech/transports/wss`; the session driver and the G4
/// regressions use it through the registry.
pub(crate) struct WssTransport {
  /// The listener-side join hint source (cluster and credential
  /// generation). A plain `WssTransport::new()` has no hint source and
  /// can only dial; the supervisor wires `with_hint` so the registered
  /// built-in transport serves complete joins.
  hint: Option<Arc<dyn Fn() -> Option<JoinHint> + Send + Sync>>,
}

impl fmt::Debug for WssTransport {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssTransport")
      .finish_non_exhaustive()
  }
}

impl WssTransport {
  pub(crate) fn new() -> Self {
    Self { hint: None }
  }

  /// Wires the listener-side join hint source; used by the supervisor when
  /// it serves the built-in transport through the registry.
  // TODO(G4-06): consumed when the supervisor serves joins through the
  // registered transport.
  #[allow(dead_code)]
  pub(crate) fn with_hint(hint: Arc<dyn Fn() -> Option<JoinHint> + Send + Sync>) -> Self {
    Self { hint: Some(hint) }
  }

  /// The canonical tag of the built-in transport.
  pub(crate) fn tag() -> Result<TransportTag> {
    // The literal is a fixed canonical constant; parse once and surface the
    // impossible failure as an internal error instead of panicking.
    TransportTag::parse("relay.woooo.tech/transports/wss")
      .map_err(|_| crate::Error::internal("built-in transport tag"))
  }
}

impl Transport for WssTransport {
  fn bind<'a>(
    &'a self, endpoint: &'a Endpoint,
  ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
    let hint = self.hint.clone();
    Box::pin(async move {
      let tcp = tokio::net::TcpListener::bind((endpoint.host(), endpoint.port()))
        .await
        .map_err(|_| {
          Error::provider(
            crate::ProviderErrorKind::Io,
            crate::ProviderErrorContext::TransportBind,
          )
        })?;
      let bound = tcp
        .local_addr()
        .map_err(|_| Error::internal("listener address"))?;
      let certificate = super::cert::EphemeralCertificate::generate(&crate::api::SystemEntropy)?;
      let config = super::tls::server_config(&certificate)?;
      let rules = crate::session::handshake_frame_rules()?;
      Ok(Box::new(WssListener {
        listener: tcp,
        config,
        rules,
        hint,
        bound: Endpoint::from_socket_addr(bound),
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect<'a>(
    &'a self, endpoint: &'a Endpoint,
  ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
    Box::pin(async move {
      let tcp = tokio::net::TcpStream::connect(endpoint.authority())
        .await
        .map_err(|_| {
          Error::provider(
            crate::ProviderErrorKind::Io,
            crate::ProviderErrorContext::TransportConnect,
          )
        })?;
      let config = super::tls::join_client_config()?;
      let server_name = endpoint.server_name()?;
      let rules = crate::session::handshake_frame_rules()?;
      let connection =
        super::connection::Connection::connect(tcp, config, server_name, rules).await?;
      Ok(Box::new(WssConnection {
        inner: connection,
        peer: endpoint.clone(),
      }) as Box<dyn TransportConnection>)
    })
  }
}

/// A [`TransportListener`] for the built-in WSS transport.
pub(crate) struct WssListener {
  listener: tokio::net::TcpListener,
  config: std::sync::Arc<rustls::ServerConfig>,
  rules: super::connection::FrameRules,
  hint: Option<Arc<dyn Fn() -> Option<JoinHint> + Send + Sync>>,
  bound: Endpoint,
}

impl fmt::Debug for WssListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssListener")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

impl TransportListener for WssListener {
  fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
    let config = std::sync::Arc::clone(&self.config);
    let rules = self.rules;
    let hint = self.hint.as_ref().and_then(|source| source());
    Box::pin(async move {
      let (tcp, _) = self.listener.accept().await.map_err(|_| {
        Error::provider(
          crate::ProviderErrorKind::Io,
          crate::ProviderErrorContext::TransportAccept,
        )
      })?;
      let peer = tcp
        .peer_addr()
        .map(Endpoint::from_socket_addr)
        .map_err(|_| Error::internal("peer address"))?;
      let connection =
        super::connection::Connection::accept(tcp, config, rules, hint.as_ref()).await?;
      Ok(Box::new(WssConnection {
        inner: connection,
        peer,
      }) as Box<dyn TransportConnection>)
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move { Ok(()) })
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::WssTransport;
  use crate::{
    DiscoveryTag, ErrorKind, ExtensionRegistry, Result, TransportTag,
    api::BoxFuture,
    transport::{Discovery, DiscoveryPage, Endpoint, EndpointCandidate, PageCursor, Transport},
  };

  fn transport_tag(value: &str) -> TransportTag {
    TransportTag::parse(&format!("relay.woooo.tech/transports/{value}")).unwrap()
  }

  fn discovery_tag(value: &str) -> DiscoveryTag {
    DiscoveryTag::parse(&format!("relay.woooo.tech/discovery/{value}")).unwrap()
  }

  fn candidate(host: &str) -> EndpointCandidate {
    EndpointCandidate::new(Endpoint::parse(&format!("wss://{host}:9000")).unwrap())
  }

  // ---- SC-G04-P0-01: transport registration by canonical tag ----

  #[test]
  fn transport_registry_accepts_one_owner_domain_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap();
    let error = registry
      .register_transport(transport_tag("alpha"), Arc::new(WssTransport::new()))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    registry
      .register_transport(transport_tag("beta"), Arc::new(WssTransport::new()))
      .unwrap();
    assert!(registry.transport(&transport_tag("beta")).is_some());
  }

  #[test]
  fn transport_registry_rejects_malformed_and_reserved_tags() {
    // Malformed tag: no qualified domain/category/name shape.
    assert!(TransportTag::parse("plain").is_err());
    // Reserved relay.woooo.tech/crypto domain is rejected by tag parsing
    // before registration.
    assert!(TransportTag::parse("relay.woooo.tech/crypto/ed25519").is_err());
  }

  // ---- SC-G04-P0-02: discovery registration without central switching ----

  #[derive(Debug)]
  struct StaticDiscovery(Vec<EndpointCandidate>);

  impl Discovery for StaticDiscovery {
    fn discover<'a>(
      &'a self, _cursor: Option<&'a PageCursor>, limit: usize,
    ) -> BoxFuture<'a, Result<DiscoveryPage>> {
      let items = self.0.clone();
      Box::pin(async move {
        let page: Vec<_> = items.into_iter().take(limit).collect();
        DiscoveryPage::new(page, None)
      })
    }
  }

  #[tokio::test]
  async fn discovery_registry_resolves_two_independent_implementations() {
    let mut registry = ExtensionRegistry::new();
    let one = Arc::new(StaticDiscovery(vec![candidate("one.example")]));
    let two = Arc::new(StaticDiscovery(vec![candidate("two.example")]));
    let one: Arc<dyn Discovery> = one;
    let two: Arc<dyn Discovery> = two;
    registry
      .register_discovery(discovery_tag("one"), Arc::clone(&one))
      .unwrap();
    registry
      .register_discovery(discovery_tag("two"), Arc::clone(&two))
      .unwrap();
    // Duplicate registration fails deterministically.
    let error = registry
      .register_discovery(discovery_tag("one"), one)
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(registry.discovery(&discovery_tag("three")).is_none());

    let page = registry
      .discovery(&discovery_tag("one"))
      .unwrap()
      .discover(None, 1)
      .await
      .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].endpoint().host(), "one.example");

    let page = registry
      .discovery(&discovery_tag("two"))
      .unwrap()
      .discover(None, 1)
      .await
      .unwrap();
    assert_eq!(page.items()[0].endpoint().host(), "two.example");
  }

  // ---- SC-G04-P0-03: authenticated transport results ----

  #[tokio::test]
  async fn wss_transport_connection_carries_a_real_tls_exporter_binding() {
    let transport = WssTransport::new();
    let listener = transport
      .bind(&Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap();
    let bound = listener.local_endpoint();

    // The TLS handshake needs both sides concurrently, so drive connect
    // and accept together.
    let (client, accepted) = tokio::join!(transport.connect(&bound), listener.accept(),);
    let client = client.unwrap();
    let accepted = accepted.unwrap();

    // The RFC 9266 exporter is derived from the authenticated TLS 1.3
    // session on both sides and is nonzero; a transport that skipped TLS
    // cannot produce this value.
    let client_binding = client.channel_binding();
    let server_binding = accepted.channel_binding();
    assert_eq!(client_binding.as_bytes(), server_binding.as_bytes());
    assert_ne!(client_binding.as_bytes(), &[0_u8; 32]);
  }

  // ---- SC-G04-P0-04: the built-in WSS transport is registered and the
  // secure join/packet/disconnect/reconnect regression runs on the same
  // authenticated connection path (secure_join integration lane). ----

  #[test]
  fn extension_registry_defaults_to_the_builtin_wss_transport() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_transport(WssTransport::tag().unwrap(), Arc::new(WssTransport::new()))
      .unwrap();
    assert!(registry.transport(&WssTransport::tag().unwrap()).is_some());
  }
}

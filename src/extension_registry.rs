//! The caller-supplied extension registry (ADR-0007).
//!
//! This gate implements exactly one registration point:
//! [`ExtensionRegistry::register_protocol`] binds a [`ProtocolDefinition`]
//! to the [`PacketConsumer`] that receives admitted incoming streams for
//! that protocol tag. The remaining manifest registration points arrive
//! with their owning gates (transports and discovery G4-01, policies
//! G5/G6).

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
  DiscoveryTag, Error, FeatureTag, IncomingPacket, ProtocolTag, Result, TransportTag,
  api::BoxFuture,
  transport::registry::{Discovery, Transport},
};

/// The immutable definition of one domain-qualified packet protocol: its
/// tag and the feature that owns it. The owning feature must be selected
/// on a session before the destination admits the protocol's streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolDefinition {
  tag: ProtocolTag,
  owning_feature: FeatureTag,
}

impl ProtocolDefinition {
  pub fn new(tag: ProtocolTag, owning_feature: FeatureTag) -> Self {
    Self {
      tag,
      owning_feature,
    }
  }

  pub(crate) const fn owning_feature(&self) -> &FeatureTag {
    &self.owning_feature
  }
}

/// The caller-owned receiver of admitted incoming packet streams.
///
/// `accept` is invoked once per admitted stream, after authentication and
/// admission; it owns all application meaning of the packet.
pub trait PacketConsumer: fmt::Debug + Send + Sync + 'static {
  fn accept<'a>(&'a self, packet: IncomingPacket) -> BoxFuture<'a, Result<()>>;
}

/// One registered protocol: its definition plus the receiving consumer.
pub(crate) struct ProtocolRegistration {
  pub(crate) definition: ProtocolDefinition,
  pub(crate) consumer: Arc<dyn PacketConsumer>,
}

/// The node-local extension registry. Caller registrations are immutable
/// for the node's lifetime and are installed through
/// [`crate::NodeBuilder::extensions`]; core protocols are registered by
/// the runtime at startup through
/// [`ExtensionRegistry::register_core_protocol`].
#[derive(Default)]
pub struct ExtensionRegistry {
  protocols: std::sync::Mutex<BTreeMap<ProtocolTag, Arc<ProtocolRegistration>>>,
  transports: BTreeMap<TransportTag, Arc<dyn Transport>>,
  discoveries: BTreeMap<DiscoveryTag, Arc<dyn Discovery>>,
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }

  /// Registers one transport implementation under its canonical tag. A
  /// duplicate tag, a malformed or reserved tag, or a registration that
  /// conflicts with an existing entry is rejected before use; the built-in
  /// WSS transport is always present.
  pub(crate) fn register_transport(
    &mut self, tag: TransportTag, value: Arc<dyn Transport>,
  ) -> Result<&mut Self> {
    if self.transports.contains_key(&tag) {
      return Err(Error::conflict("transport registration"));
    }
    self.transports.insert(tag, value);
    Ok(self)
  }

  /// Registers one discovery implementation under its canonical tag, with
  /// the same duplicate/reserved/conflict rules as transports.
  #[cfg(test)]
  pub(crate) fn register_discovery(
    &mut self, tag: DiscoveryTag, value: Arc<dyn Discovery>,
  ) -> Result<&mut Self> {
    if self.discoveries.contains_key(&tag) {
      return Err(Error::conflict("discovery registration"));
    }
    self.discoveries.insert(tag, value);
    Ok(self)
  }

  /// The registered transport for one tag.
  pub(crate) fn transport(&self, tag: &TransportTag) -> Option<&Arc<dyn Transport>> {
    self.transports.get(tag)
  }

  /// The registered discovery for one tag.
  #[cfg(test)]
  pub(crate) fn discovery(&self, tag: &DiscoveryTag) -> Option<&Arc<dyn Discovery>> {
    self.discoveries.get(tag)
  }

  /// Registers one packet protocol and its consumer. A duplicate protocol
  /// tag is a conflict; registration never replaces an existing entry.
  pub fn register_protocol(
    &mut self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<&mut Self> {
    self.register_protocol_inner(value, consumer)?;
    Ok(self)
  }

  /// Registers a core (runtime-owned) packet protocol after the node's
  /// identity is provisioned; the same duplicate/conflict rules apply.
  pub(crate) fn register_core_protocol(
    &self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<()> {
    self.register_protocol_inner(value, consumer)
  }

  fn register_protocol_inner(
    &self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<()> {
    let mut protocols = self
      .protocols
      .lock()
      .map_err(|_| Error::internal("extension registry"))?;
    if protocols.contains_key(&value.tag) {
      return Err(Error::conflict("protocol registration"));
    }
    protocols.insert(
      value.tag.clone(),
      Arc::new(ProtocolRegistration {
        definition: value,
        consumer,
      }),
    );
    Ok(())
  }

  /// The registration for one protocol tag, when present.
  pub(crate) fn protocol(&self, tag: &ProtocolTag) -> Option<Arc<ProtocolRegistration>> {
    self
      .protocols
      .lock()
      .ok()
      .and_then(|protocols| protocols.get(tag).cloned())
  }

  /// Whether the protocol tag is registered locally.
  pub(crate) fn has_protocol(&self, tag: &ProtocolTag) -> bool {
    self
      .protocols
      .lock()
      .ok()
      .is_some_and(|protocols| protocols.contains_key(tag))
  }
}

impl fmt::Debug for ExtensionRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ExtensionRegistry")
      .field(
        "protocols",
        &self
          .protocols
          .lock()
          .map(|protocols| protocols.len())
          .unwrap_or(0),
      )
      .field("transports", &self.transports.len())
      .field("discoveries", &self.discoveries.len())
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{ExtensionRegistry, PacketConsumer, ProtocolDefinition};
  use crate::{ErrorKind, FeatureTag, IncomingPacket, ProtocolTag, Result, api::BoxFuture};

  #[derive(Debug)]
  struct NoopConsumer;

  impl PacketConsumer for NoopConsumer {
    fn accept<'a>(&'a self, _packet: IncomingPacket) -> BoxFuture<'a, Result<()>> {
      Box::pin(async { Ok(()) })
    }
  }

  fn definition(name: &str) -> ProtocolDefinition {
    ProtocolDefinition::new(
      ProtocolTag::parse(&format!("relay.woooo.tech/protocols/{name}")).unwrap(),
      FeatureTag::parse("relay.woooo.tech/features/data-messages").unwrap(),
    )
  }

  #[test]
  fn tls_transport_extension_registry_registers_and_rejects_duplicates() {
    let mut registry = ExtensionRegistry::new();
    registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(
      registry.has_protocol(&ProtocolTag::parse("relay.woooo.tech/protocols/alpha").unwrap())
    );

    let error = registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    // A distinct tag still registers after the failed duplicate.
    registry
      .register_protocol(definition("beta"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(registry.has_protocol(&ProtocolTag::parse("relay.woooo.tech/protocols/beta").unwrap()));
    assert!(
      !registry.has_protocol(&ProtocolTag::parse("relay.woooo.tech/protocols/gamma").unwrap())
    );
  }
}

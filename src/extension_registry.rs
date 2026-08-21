//! The caller-supplied extension registry (ADR-0007).
//!
//! This gate implements exactly one registration point:
//! [`ExtensionRegistry::register_protocol`] binds a [`ProtocolDefinition`]
//! to the [`PacketConsumer`] that receives admitted incoming streams for
//! that protocol tag. The remaining manifest registration points arrive
//! with their owning gates (transports and discovery G4-01, policies
//! G5/G6).

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{Error, FeatureTag, IncomingPacket, ProtocolTag, Result, api::BoxFuture};

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
    Self { tag, owning_feature }
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

/// The node-local extension registry. Registrations are immutable for the
/// node's lifetime and are installed through
/// [`crate::NodeBuilder::extensions`].
#[derive(Default)]
pub struct ExtensionRegistry {
  protocols: BTreeMap<ProtocolTag, ProtocolRegistration>,
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }

  /// Registers one packet protocol and its consumer. A duplicate protocol
  /// tag is a conflict; registration never replaces an existing entry.
  pub fn register_protocol(
    &mut self, value: ProtocolDefinition, consumer: Arc<dyn PacketConsumer>,
  ) -> Result<&mut Self> {
    if self.protocols.contains_key(&value.tag) {
      return Err(Error::conflict("protocol registration"));
    }
    self.protocols.insert(
      value.tag.clone(),
      ProtocolRegistration {
        definition: value,
        consumer,
      },
    );
    Ok(self)
  }

  /// The registration for one protocol tag, when present.
  pub(crate) fn protocol(&self, tag: &ProtocolTag) -> Option<&ProtocolRegistration> {
    self.protocols.get(tag)
  }

  /// Whether the protocol tag is registered locally.
  pub(crate) fn has_protocol(&self, tag: &ProtocolTag) -> bool {
    self.protocols.contains_key(tag)
  }
}

impl fmt::Debug for ExtensionRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ExtensionRegistry")
      .field("protocols", &self.protocols.len())
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
    assert!(registry.has_protocol(
      &ProtocolTag::parse("relay.woooo.tech/protocols/alpha").unwrap()
    ));

    let error = registry
      .register_protocol(definition("alpha"), Arc::new(NoopConsumer))
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);

    // A distinct tag still registers after the failed duplicate.
    registry
      .register_protocol(definition("beta"), Arc::new(NoopConsumer))
      .unwrap();
    assert!(registry.has_protocol(
      &ProtocolTag::parse("relay.woooo.tech/protocols/beta").unwrap()
    ));
    assert!(!registry.has_protocol(
      &ProtocolTag::parse("relay.woooo.tech/protocols/gamma").unwrap()
    ));
  }
}

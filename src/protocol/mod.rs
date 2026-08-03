#[allow(dead_code)]
mod envelope;
mod tag;

pub use tag::{
  DiscoveryTag, EventTag, FeatureTag, ProtocolTag, QualifiedTag, ResourceTag, SchemaTag,
  TransportTag,
};

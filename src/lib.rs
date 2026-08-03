mod config;
mod error;
mod identity;
mod protocol;

pub use config::NodeConfig;
pub use error::{Error, ErrorKind, ProviderErrorContext, ProviderErrorKind, Result};
pub use identity::{ClusterId, NodeId, TraceId};
pub use protocol::{
  DiscoveryTag, EventTag, FeatureTag, ProtocolTag, QualifiedTag, ResourceTag, SchemaTag,
  TransportTag,
};

pub fn add(left: u64, right: u64) -> u64 {
  left + right
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let result = add(2, 2);
    assert_eq!(result, 4);
  }
}

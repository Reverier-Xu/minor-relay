mod api;
mod config;
mod error;
mod identity;
mod node;
mod operation;
mod protocol;
mod provider;
mod view;

pub use api::{BoxFuture, Clock, Entropy, MonotonicTime};
pub use config::{AdmissionLimits, NodeConfig, ProtocolLimits, TraceLimits};
pub use error::{Error, ErrorKind, ProviderErrorContext, ProviderErrorKind, Result};
pub use identity::{ClusterId, Digest, NodeId, PublicKey, Signature, TraceId};
pub use node::{EventOptions, EventReceive, EventSubscription};
pub use operation::{Command, Event, GetNodeStatus, Query, Shutdown, WaitForShutdown};
pub use protocol::{
  DiscoveryTag, EventTag, FeatureTag, ProtocolTag, QualifiedTag, ResourceTag, SchemaTag,
  TransportTag,
};
pub use provider::{
  CommitOutcome, CommitReceipt, CreatedKey, DurabilityLevel, KeyCreateState, KeyDeleteState,
  KeyHandle, KeyOperationId, KeyProvider, ReconcileOutcome, Storage, StorageFactory,
  StoreCapabilities, StoreRequirements, StoreSnapshot, StoreTransaction, TransactionId,
};
pub use view::{NodeStatus, ShutdownOutcome, ShutdownReason};

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

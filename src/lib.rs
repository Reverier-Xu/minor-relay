mod api;
mod config;
mod error;
mod identity;
mod node;
mod operation;
mod protocol;
mod provider;
mod runtime;
mod view;

#[cfg(test)]
mod simulation;

pub use api::{BoxFuture, MonotonicTime};
pub use config::{AdmissionLimits, NodeConfig, ProtocolLimits, TraceLimits};
pub use error::{Error, ErrorKind, ProviderErrorContext, ProviderErrorKind, Result};
pub use identity::{ClusterId, Digest, NodeId, PublicKey, Signature, TraceId};
pub use node::{
  EventOptions, EventReceive, EventSubscription, ExtensionRegistry, NodeBuilder, NodeHandle,
};
pub use operation::{Command, Event, GetNodeStatus, Query, Shutdown, WaitForShutdown};
pub use protocol::{
  DiscoveryTag, EventTag, FeatureTag, ProtocolTag, QualifiedTag, ResourceTag, SchemaTag,
  TransportTag,
};
pub use view::{NodeStatus, ShutdownOutcome, ShutdownReason};

pub mod extension {
  pub use crate::{
    api::{Clock, Entropy},
    provider::{
      CommitOutcome, CommitReceipt, CreatedKey, DurabilityLevel, KeyCreateState, KeyDeleteState,
      KeyHandle, KeyOperationId, KeyProvider, ReconcileOutcome, Storage, StorageFactory,
      StoreCapabilities, StoreRequirements, StoreSnapshot, StoreTransaction, TransactionId,
    },
  };
}

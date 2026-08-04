#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! `minor-relay` exposes its supported API through this crate root and
//! [`extension`].
//!
//! Implementation modules remain inaccessible to downstream crates:
//!
//! ```compile_fail,E0603
//! use minor_relay::protocol;
//! ```
//!
//! ```compile_fail,E0603
//! use minor_relay::provider;
//! ```
//!
//! ```compile_fail,E0603
//! use minor_relay::runtime;
//! ```
//!
//! Test-only and future implementation modules are absent from the facade:
//!
//! ```compile_fail,E0432
//! use minor_relay::simulation;
//! ```
//!
//! ```compile_fail,E0432
//! use minor_relay::storage;
//! ```
//!
//! ```compile_fail,E0432
//! use minor_relay::add;
//! ```

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

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! G1 exposes deterministic foundation values, provider boundaries, and the
//! node lifecycle through this crate root and [`extension`]. Implementation
//! modules remain private.
//!
//! ```compile_fail,E0603
//! use minor_relay::provider;
//! ```
//!
//! ```compile_fail,E0603
//! use minor_relay::runtime;
//! ```
//!
//! Superseded limits, public clock injection, and the placeholder extension
//! registry are absent.
//!
//! ```compile_fail,E0432
//! use minor_relay::{AdmissionLimits, Clock, MonotonicTime, ProtocolLimits, TraceLimits};
//! ```
//!
//! ```compile_fail,E0432
//! use minor_relay::extension::Clock;
//! ```
//!
//! ```compile_fail,E0432
//! use minor_relay::ExtensionRegistry;
//! ```
//!
//! ```compile_fail,E0599
//! let _ = minor_relay::NodeConfig::new().with_member_limit(1_024);
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
mod session;
mod storage;
mod transport;
mod view;

#[cfg(test)]
mod simulation;

pub use api::BoxFuture;
pub use config::{NodeConfig, ParserLimits, RecoveryConfig, TraceMetadataLimits};
pub use error::{Error, ErrorKind, ProviderErrorContext, ProviderErrorKind, Result};
pub use identity::{
  ClusterId, Digest, IssuedJoinCredential, JoinCredential, ListenerId, NodeId, OperationId,
  PublicKey, SessionId, Signature, TraceId, TransactionId,
};
pub use node::{EventOptions, EventReceive, EventSubscription, NodeBuilder, NodeHandle};
pub use operation::{
  Command, CreateCluster, Event, GetLocalNode, GetNodeStatus, JoinCluster, Listen, Query,
  RotateJoinCredential, Shutdown, StopListener, WaitForShutdown,
};
pub use protocol::{
  DiscoveryTag, FeatureDefinition, FeatureTag, ProtocolTag, QualifiedTag, TransportTag,
};
pub use provider::{
  CommitOutcome, CommitReceipt, CreatedKey, DurabilityLevel, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, ReconcileOutcome, StoreCapabilities, StoreEntry,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRequirements, StoreRevision,
  StoreTransaction, StoreValue,
};
pub use transport::Endpoint;
pub use view::{
  AdmissionView, ClusterView, ListenerView, LocalNodeView, NodeStatus, ShutdownOutcome,
  ShutdownReason,
};

pub mod extension {
  pub use crate::{
    api::Entropy,
    provider::{KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
  };
}

pub mod adapters {
  //! Explicit storage-adapter constructors.
  //!
  //! Adapter selection is always an explicit caller choice; no feature
  //! selects a backend implicitly.

  #[cfg(feature = "json")]
  use std::{path::PathBuf, sync::Arc};

  #[cfg(feature = "json")]
  use crate::extension::StorageFactory;

  /// Creates a test-only immutable JSON generation store factory rooted at
  /// `path`.
  ///
  /// The directory must exist. The factory holds one alias-safe exclusive
  /// lifetime lock per open store and never overwrites a final generation.
  #[cfg(feature = "json")]
  pub fn json_store(path: PathBuf) -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::json::JsonStoreFactory::new(path))
  }
}

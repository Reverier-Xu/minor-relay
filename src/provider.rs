use std::fmt;

use crate::{BoxFuture, Digest, PublicKey, Result, Signature};

pub struct KeyOperationId {
  _private: (),
}

pub struct KeyHandle {
  _private: (),
}

pub struct CreatedKey {
  _private: (),
}

#[non_exhaustive]
pub enum KeyCreateState {
  Present(CreatedKey),
  Absent,
  Unknown,
}

#[non_exhaustive]
pub enum KeyDeleteState {
  Present,
  Absent,
  Unknown,
}

pub trait KeyProvider: fmt::Debug + Send + Sync + 'static {
  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>>;

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>>;

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>>;

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>>;

  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>>;

  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DurabilityLevel {
  ProcessCrashAtomic,
  OsCrashDurable,
}

pub struct StoreRequirements {
  _private: (),
}

pub struct StoreCapabilities {
  _private: (),
}

pub struct StoreSnapshot {
  _private: (),
}

pub struct StoreTransaction {
  _private: (),
}

pub struct TransactionId {
  _private: (),
}

pub struct CommitReceipt {
  _private: (),
}

#[non_exhaustive]
pub enum CommitOutcome {
  Committed(CommitReceipt),
  Aborted,
  Conflict,
  Unknown {
    transaction: TransactionId,
    operation_digest: Digest,
  },
}

#[non_exhaustive]
pub enum ReconcileOutcome {
  Committed(CommitReceipt),
  Aborted,
  DigestConflict,
  Unknown,
}

pub trait StorageFactory: fmt::Debug + Send + Sync + 'static {
  fn open<'a>(&'a self, requirements: StoreRequirements)
  -> BoxFuture<'a, Result<Box<dyn Storage>>>;
}

pub trait Storage: fmt::Debug + Send + Sync + 'static {
  fn capabilities(&self) -> StoreCapabilities;
  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<StoreSnapshot>>;
  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>>;
  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>>;
  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

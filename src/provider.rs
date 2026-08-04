use std::{fmt, sync::Arc};

use crate::{BoxFuture, Digest, PublicKey, Result, Signature};

pub struct KeyOperationId {
  value: Arc<[u8]>,
}

impl KeyOperationId {
  pub fn as_bytes(&self) -> &[u8] {
    &self.value
  }
}

pub struct KeyHandle {
  value: Arc<[u8]>,
}

impl KeyHandle {
  pub fn expose_provider_handle(&self) -> &[u8] {
    &self.value
  }
}

impl fmt::Debug for KeyHandle {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("KeyHandle(..)")
  }
}

pub struct CreatedKey {
  handle: KeyHandle,
  public_key: PublicKey,
}

impl CreatedKey {
  pub fn new(handle: KeyHandle, public_key: PublicKey) -> Self {
    Self { handle, public_key }
  }

  pub fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }
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
  required_durability: DurabilityLevel,
  conditional_batch: bool,
  ordered_scan: bool,
  reconciliation: bool,
  exclusive_lifetime_lock: bool,
  transactional_migration: bool,
}

impl StoreRequirements {
  pub fn required_durability(&self) -> DurabilityLevel {
    self.required_durability
  }

  pub fn requires_conditional_batch(&self) -> bool {
    self.conditional_batch
  }

  pub fn requires_ordered_scan(&self) -> bool {
    self.ordered_scan
  }

  pub fn requires_reconciliation(&self) -> bool {
    self.reconciliation
  }

  pub fn requires_exclusive_lifetime_lock(&self) -> bool {
    self.exclusive_lifetime_lock
  }

  pub fn requires_transactional_migration(&self) -> bool {
    self.transactional_migration
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreCapabilities {
  durability: DurabilityLevel,
  conditional_batch: bool,
  ordered_scan: bool,
  reconciliation: bool,
  exclusive_lifetime_lock: bool,
  transactional_migration: bool,
}

impl StoreCapabilities {
  pub fn new(durability: DurabilityLevel) -> Self {
    Self {
      durability,
      conditional_batch: false,
      ordered_scan: false,
      reconciliation: false,
      exclusive_lifetime_lock: false,
      transactional_migration: false,
    }
  }

  pub fn conditional_batch(mut self, supported: bool) -> Self {
    self.conditional_batch = supported;
    self
  }

  pub fn ordered_scan(mut self, supported: bool) -> Self {
    self.ordered_scan = supported;
    self
  }

  pub fn reconciliation(mut self, supported: bool) -> Self {
    self.reconciliation = supported;
    self
  }

  pub fn exclusive_lifetime_lock(mut self, supported: bool) -> Self {
    self.exclusive_lifetime_lock = supported;
    self
  }

  pub fn transactional_migration(mut self, supported: bool) -> Self {
    self.transactional_migration = supported;
    self
  }

  pub fn durability(&self) -> DurabilityLevel {
    self.durability
  }

  pub fn has_conditional_batch(&self) -> bool {
    self.conditional_batch
  }

  pub fn has_ordered_scan(&self) -> bool {
    self.ordered_scan
  }

  pub fn has_reconciliation(&self) -> bool {
    self.reconciliation
  }

  pub fn has_exclusive_lifetime_lock(&self) -> bool {
    self.exclusive_lifetime_lock
  }

  pub fn has_transactional_migration(&self) -> bool {
    self.transactional_migration
  }
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

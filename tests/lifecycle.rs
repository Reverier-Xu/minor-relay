use std::{
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  time::{Duration, SystemTime},
};

use minor_relay::{
  BoxFuture, Clock, CommitOutcome, CreatedKey, Digest, Entropy, Error, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, KeyProvider, MonotonicTime, ProviderErrorContext,
  ProviderErrorKind, PublicKey, ReconcileOutcome, Result, Signature, Storage, StorageFactory,
  StoreRequirements, StoreTransaction, TransactionId,
};

#[derive(Debug)]
struct VirtualClock {
  monotonic_nanos: AtomicU64,
  utc: SystemTime,
}

impl VirtualClock {
  fn new() -> Self {
    Self {
      monotonic_nanos: AtomicU64::new(0),
      utc: SystemTime::UNIX_EPOCH,
    }
  }
}

impl Clock for VirtualClock {
  fn utc_now(&self) -> SystemTime {
    self.utc
  }

  fn monotonic_now(&self) -> MonotonicTime {
    MonotonicTime::from_nanos_since_origin(self.monotonic_nanos.load(Ordering::SeqCst))
  }

  fn sleep_until<'a>(&'a self, deadline: MonotonicTime) -> BoxFuture<'a, ()> {
    Box::pin(async move {
      self
        .monotonic_nanos
        .fetch_max(deadline.as_nanos_since_origin(), Ordering::SeqCst);
    })
  }
}

#[derive(Debug)]
struct SequenceEntropy {
  bytes: Mutex<Vec<u8>>,
}

impl SequenceEntropy {
  fn new(bytes: Vec<u8>) -> Self {
    Self {
      bytes: Mutex::new(bytes),
    }
  }
}

impl Entropy for SequenceEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    let mut bytes = self
      .bytes
      .lock()
      .map_err(|_| provider_error(ProviderErrorContext::Entropy))?;
    if bytes.len() < output.len() {
      return Err(provider_error(ProviderErrorContext::Entropy));
    }
    output.copy_from_slice(&bytes[..output.len()]);
    bytes.drain(..output.len());
    Ok(())
  }
}

#[derive(Debug)]
struct DeclarationOnlyStorage;

impl StorageFactory for DeclarationOnlyStorage {
  fn open<'a>(
    &'a self, _requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::StorageOpen)) })
  }
}

#[derive(Debug)]
struct DeclarationOnlyKeys;

impl KeyProvider for DeclarationOnlyKeys {
  fn create_ed25519<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyCreate)) })
  }

  fn reconcile_create<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyReconcile)) })
  }

  fn public_key<'a>(&'a self, _handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyPublicKey)) })
  }

  fn sign<'a>(
    &'a self, _handle: &'a KeyHandle, _message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeySign)) })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyDelete)) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyReconcile)) })
  }
}

#[test]
fn g1_lifecycle_monotonic_time_checked_boundaries() {
  let start = MonotonicTime::from_nanos_since_origin(5);
  let later = start.checked_add(Duration::from_nanos(7)).unwrap();

  assert_eq!(later.as_nanos_since_origin(), 12);
  assert_eq!(
    later.checked_duration_since(start),
    Some(Duration::from_nanos(7))
  );
  assert_eq!(start.checked_duration_since(later), None);
  assert_eq!(
    MonotonicTime::from_nanos_since_origin(u64::MAX).checked_add(Duration::from_nanos(1)),
    None,
  );
}

#[tokio::test]
async fn g1_lifecycle_clock_sleep_uses_virtual_time() {
  let clock = VirtualClock::new();
  let deadline = MonotonicTime::from_nanos_since_origin(42);

  clock.sleep_until(deadline).await;

  assert_eq!(clock.utc_now(), SystemTime::UNIX_EPOCH);
  assert_eq!(clock.monotonic_now(), deadline);
}

#[test]
fn g1_lifecycle_entropy_consumes_reproducible_bytes() {
  let entropy = SequenceEntropy::new(vec![1, 2, 3, 4]);
  let mut first = [0; 3];
  let mut exhausted = [0; 2];

  entropy.fill(&mut first).unwrap();

  assert_eq!(first, [1, 2, 3]);
  assert!(entropy.fill(&mut exhausted).is_err());
}

#[test]
fn g1_lifecycle_provider_scaffold_matches_builder_signature() {
  fn assert_dependencies(_storage: Arc<dyn StorageFactory>, _keys: Arc<dyn KeyProvider>) {}

  assert_dependencies(
    Arc::new(DeclarationOnlyStorage),
    Arc::new(DeclarationOnlyKeys),
  );
}

fn provider_error(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::Internal, context)
}

#[allow(dead_code)]
fn assert_storage_signatures(
  _transaction: StoreTransaction, _commit: CommitOutcome, _reconcile: ReconcileOutcome,
  _transaction_id: TransactionId, _digest: Digest, _created: CreatedKey,
) {
}

use std::sync::{
  Arc, Mutex,
  atomic::{AtomicUsize, Ordering},
};

use minor_relay::{
  BoxFuture, CommitOutcome, Digest, DurabilityLevel, Error, ErrorKind, KeyCapabilities,
  KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, NodeBuilder, ProviderErrorContext,
  ProviderErrorKind, PublicKey, ReconcileOutcome, Result, Shutdown, Signature, StoreCapabilities,
  StoreEntry, StoreKey, StoreNamespace, StoreRequirements, StoreRevision, StoreTransaction,
  StoreValue, TransactionId,
  extension::{Entropy, KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
};

#[derive(Debug, Default)]
struct Calls {
  open: AtomicUsize,
  capabilities: AtomicUsize,
  snapshots: AtomicUsize,
  commits: AtomicUsize,
  reconciles: AtomicUsize,
  flushes: AtomicUsize,
  keys: AtomicUsize,
  events: Mutex<Vec<&'static str>>,
}

#[derive(Debug, Default)]
struct Drops {
  factory: AtomicUsize,
  storage: AtomicUsize,
  keys: AtomicUsize,
}

#[derive(Debug)]
struct RuntimeEntropy {
  calls: Arc<Calls>,
}

impl Entropy for RuntimeEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    self.calls.events.lock().unwrap().push("entropy");
    output.fill(0xA5);
    Ok(())
  }
}

#[derive(Debug)]
struct RuntimeFactory {
  calls: Arc<Calls>,
  drops: Arc<Drops>,
  capabilities: StoreCapabilities,
  open_error: Option<ProviderErrorKind>,
}

impl Drop for RuntimeFactory {
  fn drop(&mut self) {
    self.drops.factory.fetch_add(1, Ordering::SeqCst);
  }
}

impl StorageFactory for RuntimeFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    self.calls.open.fetch_add(1, Ordering::SeqCst);
    self.calls.events.lock().unwrap().push("open");
    assert_eq!(
      requirements.required_durability(),
      DurabilityLevel::OsCrashDurable
    );
    assert!(requirements.requires_conditional_batch());
    assert!(requirements.requires_ordered_scan());
    assert!(requirements.requires_reconciliation());
    assert!(requirements.requires_exclusive_lifetime_lock());
    assert!(!requirements.requires_transactional_migration());
    let calls = Arc::clone(&self.calls);
    let drops = Arc::clone(&self.drops);
    let capabilities = self.capabilities;
    let error = self.open_error;
    Box::pin(async move {
      if let Some(kind) = error {
        return Err(Error::provider(kind, ProviderErrorContext::StorageOpen));
      }
      Ok(Box::new(RuntimeStorage {
        calls,
        drops,
        capabilities,
      }) as Box<dyn Storage>)
    })
  }
}

#[derive(Debug)]
struct RuntimeStorage {
  calls: Arc<Calls>,
  drops: Arc<Drops>,
  capabilities: StoreCapabilities,
}

impl Drop for RuntimeStorage {
  fn drop(&mut self) {
    self.drops.storage.fetch_add(1, Ordering::SeqCst);
  }
}

impl Storage for RuntimeStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.calls.capabilities.fetch_add(1, Ordering::SeqCst);
    self.calls.events.lock().unwrap().push("capabilities");
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    self.calls.snapshots.fetch_add(1, Ordering::SeqCst);
    Box::pin(async {
      Ok(Box::new(NeverSnapshot {
        revision: StoreRevision::new(Arc::from([1_u8])).unwrap(),
      }) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, _transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.calls.commits.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { panic!("startup must not commit") })
  }

  fn reconcile<'a>(
    &'a self, _transaction: &'a TransactionId, _digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    self.calls.reconciles.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { panic!("startup must not reconcile") })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.calls.flushes.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { panic!("startup must not flush") })
  }
}

#[derive(Debug)]
struct RuntimeKeys {
  calls: Arc<Calls>,
  drops: Arc<Drops>,
}

impl Drop for RuntimeKeys {
  fn drop(&mut self) {
    self.drops.keys.fetch_add(1, Ordering::SeqCst);
  }
}

impl KeyProvider for RuntimeKeys {
  fn capabilities(&self) -> KeyCapabilities {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    KeyCapabilities::new()
  }

  fn create_ed25519<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(KeyCreateState::Absent) })
  }

  fn reconcile_create<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(KeyCreateState::Absent) })
  }

  fn public_key<'a>(&'a self, _handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(PublicKey::from_bytes([0; 32])) })
  }

  fn sign<'a>(
    &'a self, _handle: &'a KeyHandle, _message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(Signature::from_bytes([0; 64])) })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.calls.keys.fetch_add(1, Ordering::SeqCst);
    Box::pin(async { Ok(KeyDeleteState::Absent) })
  }
}

#[derive(Debug)]
struct NeverSnapshot {
  revision: StoreRevision,
}

impl StoreSnapshot for NeverSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, _namespace: &'a StoreNamespace, _key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    Box::pin(async { Ok(None) })
  }

  fn scan<'a>(
    &'a self, _namespace: &'a StoreNamespace, _prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    Box::pin(async { Ok(Box::new(NeverScan) as Box<dyn StoreScan>) })
  }
}

#[derive(Debug)]
struct NeverScan;

impl StoreScan for NeverScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    Box::pin(async { Ok(None) })
  }
}

#[tokio::test]
async fn storage_runtime_success_opens_then_probes_once_and_releases_every_provider() {
  let calls = Arc::new(Calls::default());
  let drops = Arc::new(Drops::default());
  let handle = builder(
    Arc::clone(&calls),
    Arc::clone(&drops),
    complete_capabilities(),
    None,
  )
  .start()
  .await
  .unwrap();

  assert_eq!(
    calls.events.lock().unwrap().as_slice(),
    &["entropy", "open", "capabilities"]
  );
  assert_eq!(calls.open.load(Ordering::SeqCst), 1);
  assert_eq!(calls.capabilities.load(Ordering::SeqCst), 1);
  assert_no_other_calls(&calls);
  assert_eq!(drops.factory.load(Ordering::SeqCst), 0);
  assert_eq!(drops.storage.load(Ordering::SeqCst), 0);
  assert_eq!(drops.keys.load(Ordering::SeqCst), 0);

  handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(drops.factory.load(Ordering::SeqCst), 1);
  assert_eq!(drops.storage.load(Ordering::SeqCst), 1);
  assert_eq!(drops.keys.load(Ordering::SeqCst), 1);
  assert_no_other_calls(&calls);
}

#[tokio::test]
async fn storage_runtime_post_open_probe_refuses_each_missing_phase_a_capability() {
  let capabilities = [
    StoreCapabilities::new(DurabilityLevel::ProcessCrashAtomic)
      .conditional_batch(true)
      .ordered_scan(true)
      .reconciliation(true)
      .exclusive_lifetime_lock(true),
    complete_capabilities().conditional_batch(false),
    complete_capabilities().ordered_scan(false),
    complete_capabilities().reconciliation(false),
    complete_capabilities().exclusive_lifetime_lock(false),
  ];

  for capabilities in capabilities {
    let calls = Arc::new(Calls::default());
    let drops = Arc::new(Drops::default());
    let error = builder(Arc::clone(&calls), drops, capabilities, None)
      .start()
      .await
      .err()
      .unwrap();
    assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
    assert_eq!(error.context(), "storage open");
    assert_eq!(calls.open.load(Ordering::SeqCst), 1);
    assert_eq!(calls.capabilities.load(Ordering::SeqCst), 1);
    assert_no_other_calls(&calls);
  }
}

#[tokio::test]
async fn storage_runtime_open_error_is_typed_redacted_and_never_calls_keys() {
  let calls = Arc::new(Calls::default());
  let drops = Arc::new(Drops::default());
  let error = builder(
    Arc::clone(&calls),
    drops,
    complete_capabilities(),
    Some(ProviderErrorKind::StorageLocked),
  )
  .start()
  .await
  .err()
  .unwrap();

  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  assert_eq!(error.context(), "storage open");
  assert!(!format!("{error:?}").contains("provider-secret"));
  assert_eq!(calls.open.load(Ordering::SeqCst), 1);
  assert_eq!(calls.capabilities.load(Ordering::SeqCst), 0);
  assert_no_other_calls(&calls);
}

fn builder(
  calls: Arc<Calls>, drops: Arc<Drops>, capabilities: StoreCapabilities,
  open_error: Option<ProviderErrorKind>,
) -> NodeBuilder {
  NodeBuilder::new(
    Arc::new(RuntimeFactory {
      calls: Arc::clone(&calls),
      drops: Arc::clone(&drops),
      capabilities,
      open_error,
    }),
    Arc::new(RuntimeKeys {
      calls: Arc::clone(&calls),
      drops,
    }),
  )
  .entropy(Arc::new(RuntimeEntropy { calls }))
}

fn complete_capabilities() -> StoreCapabilities {
  StoreCapabilities::new(DurabilityLevel::OsCrashDurable)
    .conditional_batch(true)
    .ordered_scan(true)
    .reconciliation(true)
    .exclusive_lifetime_lock(true)
}

fn assert_no_other_calls(calls: &Calls) {
  assert_eq!(calls.snapshots.load(Ordering::SeqCst), 0);
  assert_eq!(calls.commits.load(Ordering::SeqCst), 0);
  assert_eq!(calls.reconciles.load(Ordering::SeqCst), 0);
  assert_eq!(calls.flushes.load(Ordering::SeqCst), 0);
  assert_eq!(calls.keys.load(Ordering::SeqCst), 0);
}

use std::{
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  time::{Duration, SystemTime},
};

use minor_relay::{
  BoxFuture, Clock, Command, CommitOutcome, CreatedKey, Digest, Entropy, Error, EventOptions,
  ExtensionRegistry, GetNodeStatus, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId,
  KeyProvider, MonotonicTime, NodeBuilder, NodeConfig, NodeHandle, NodeStatus, ProviderErrorContext, ProviderErrorKind, PublicKey, Query,
  ReconcileOutcome, Result, Shutdown, ShutdownOutcome, Signature, Storage, StorageFactory,
  StoreRequirements, StoreTransaction, TransactionId, WaitForShutdown,
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

#[test]
fn g1_lifecycle_sealed_operations_preserve_outputs() {
  fn assert_command<Operation: Command<Output = ShutdownOutcome>>() {}
  fn assert_status_query<Operation: Query<Output = NodeStatus>>() {}
  fn assert_wait_query<Operation: Query<Output = minor_relay::ShutdownReason>>() {}

  assert_command::<Shutdown>();
  assert_status_query::<GetNodeStatus>();
  assert_wait_query::<WaitForShutdown>();

  Shutdown::new();
  GetNodeStatus::new();
  WaitForShutdown::new();
}

#[test]
fn g1_lifecycle_event_capacity_is_bounded() {
  EventOptions::new().capacity(1).unwrap();
  EventOptions::new().capacity(1_024).unwrap();

  assert!(EventOptions::new().capacity(0).is_err());
  assert!(EventOptions::new().capacity(1_025).is_err());
}

#[tokio::test]
async fn g1_lifecycle_public_builder_starts_running_runtime() {
  let handle = start_node().await;

  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
}

#[tokio::test]
async fn g1_lifecycle_cloned_handles_share_runtime_status() {
  let first = start_node().await;
  let second = first.clone();

  assert_eq!(
    first.query(GetNodeStatus::new()).await.unwrap(),
    second.query(GetNodeStatus::new()).await.unwrap(),
  );
}

async fn start_node() -> NodeHandle {
  let clock = Arc::new(VirtualClock::new());
  let entropy = Arc::new(SequenceEntropy::new(vec![7; 32]));
  NodeBuilder::new(Arc::new(DeclarationOnlyStorage), Arc::new(DeclarationOnlyKeys))
    .config(NodeConfig::new())
    .extensions(ExtensionRegistry::new())
    .clock(clock)
    .entropy(entropy)
    .start()
    .await
    .unwrap()
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

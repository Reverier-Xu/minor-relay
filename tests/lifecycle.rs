use std::{
  future::Future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
  },
  task::{Context, Poll, Waker},
  time::{Duration, SystemTime},
};

use minor_relay::{
  BoxFuture, Command, Digest, Error, ErrorKind, EventOptions, ExtensionRegistry, GetNodeStatus,
  MonotonicTime, NodeBuilder, NodeConfig, NodeHandle, NodeStatus, ProviderErrorContext,
  ProviderErrorKind, PublicKey, Query, Result, Shutdown, ShutdownOutcome, ShutdownReason,
  Signature, WaitForShutdown,
  extension::{
    Clock, CommitOutcome, CreatedKey, Entropy, KeyCreateState, KeyDeleteState, KeyHandle,
    KeyOperationId, KeyProvider, ReconcileOutcome, Storage, StorageFactory, StoreRequirements,
    StoreTransaction, TransactionId,
  },
};
use tokio::sync::Notify;

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

#[derive(Debug, Default)]
struct DropTracker {
  count: AtomicUsize,
  changed: Notify,
}

impl DropTracker {
  fn record(&self) {
    self.count.fetch_add(1, Ordering::SeqCst);
    self.changed.notify_waiters();
  }

  fn count(&self) -> usize {
    self.count.load(Ordering::SeqCst)
  }

  async fn wait_for_all(&self) {
    loop {
      let changed = self.changed.notified();
      if self.count() == 2 {
        return;
      }
      changed.await;
    }
  }
}

#[derive(Debug)]
struct DeclarationOnlyStorage {
  drops: Option<Arc<DropTracker>>,
}

impl DeclarationOnlyStorage {
  fn new() -> Self {
    Self { drops: None }
  }

  fn tracked(drops: Arc<DropTracker>) -> Self {
    Self { drops: Some(drops) }
  }
}

impl Drop for DeclarationOnlyStorage {
  fn drop(&mut self) {
    if let Some(drops) = &self.drops {
      drops.record();
    }
  }
}

impl StorageFactory for DeclarationOnlyStorage {
  fn open<'a>(
    &'a self, _requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::StorageOpen)) })
  }
}

#[derive(Debug)]
struct DeclarationOnlyKeys {
  drops: Option<Arc<DropTracker>>,
}

impl DeclarationOnlyKeys {
  fn new() -> Self {
    Self { drops: None }
  }

  fn tracked(drops: Arc<DropTracker>) -> Self {
    Self { drops: Some(drops) }
  }
}

impl Drop for DeclarationOnlyKeys {
  fn drop(&mut self) {
    if let Some(drops) = &self.drops {
      drops.record();
    }
  }
}

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
    Arc::new(DeclarationOnlyStorage::new()),
    Arc::new(DeclarationOnlyKeys::new()),
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

#[tokio::test]
async fn g1_lifecycle_shutdown_and_wait_are_idempotent() {
  let handle = start_node().await;
  let waiter = handle.clone();
  let waiting = tokio::spawn(async move { waiter.query(WaitForShutdown::new()).await });
  tokio::task::yield_now().await;

  let first = handle.command(Shutdown::new()).await.unwrap();
  let reason = waiting.await.unwrap().unwrap();

  assert!(!first.already_stopped());
  assert_eq!(reason, minor_relay::ShutdownReason::Requested);
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
  assert_eq!(
    handle.query(WaitForShutdown::new()).await.unwrap(),
    minor_relay::ShutdownReason::Requested,
  );
  assert!(
    handle
      .command(Shutdown::new())
      .await
      .unwrap()
      .already_stopped()
  );
}

#[tokio::test]
async fn g1_lifecycle_concurrent_shutdown_runs_one_drain() {
  let handle = start_node().await;
  let barrier = Arc::new(tokio::sync::Barrier::new(16));
  let mut callers = Vec::new();
  for _ in 0..16 {
    let caller = handle.clone();
    let barrier = Arc::clone(&barrier);
    callers.push(tokio::spawn(async move {
      barrier.wait().await;
      caller.command(Shutdown::new()).await
    }));
  }

  let mut initiated = 0;
  for caller in callers {
    let outcome = caller.await.unwrap().unwrap();
    if !outcome.already_stopped() {
      initiated += 1;
    }
  }

  assert_eq!(initiated, 1);
  assert_eq!(
    handle.query(WaitForShutdown::new()).await.unwrap(),
    minor_relay::ShutdownReason::Requested,
  );
}

#[test]
fn g1_lifecycle_start_without_tokio_returns_not_ready() {
  let builder = NodeBuilder::new(
    Arc::new(DeclarationOnlyStorage::new()),
    Arc::new(DeclarationOnlyKeys::new()),
  )
  .clock(Arc::new(VirtualClock::new()))
  .entropy(Arc::new(SequenceEntropy::new(vec![7; 32])));
  let mut start = Box::pin(builder.start());
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);

  let result = Future::poll(start.as_mut(), &mut context);

  assert!(
    matches!(result, Poll::Ready(Err(error)) if error.kind() == minor_relay::ErrorKind::NotReady)
  );
}

#[test]
fn g1_lifecycle_runtime_loss_publishes_failed_terminal_state() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let handle = runtime.block_on(start_node());
  assert_eq!(
    runtime
      .block_on(handle.query(GetNodeStatus::new()))
      .unwrap(),
    NodeStatus::Running
  );

  drop(runtime);

  let observer = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  observer.block_on(async {
    assert_eq!(
      handle.query(GetNodeStatus::new()).await.unwrap(),
      NodeStatus::Failed
    );
    assert_eq!(
      handle.query(WaitForShutdown::new()).await.unwrap(),
      ShutdownReason::Fatal(ErrorKind::Internal),
    );
  });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_shutdown_releases_retained_providers() {
  let drops = Arc::new(DropTracker::default());
  let handle = NodeBuilder::new(
    Arc::new(DeclarationOnlyStorage::tracked(Arc::clone(&drops))),
    Arc::new(DeclarationOnlyKeys::tracked(Arc::clone(&drops))),
  )
  .clock(Arc::new(VirtualClock::new()))
  .entropy(Arc::new(SequenceEntropy::new(vec![7; 32])))
  .start()
  .await
  .unwrap();

  handle.command(Shutdown::new()).await.unwrap();

  assert_eq!(drops.count(), 2);
}

#[tokio::test]
async fn g1_lifecycle_last_handle_drop_stops_supervisor() {
  let drops = Arc::new(DropTracker::default());
  let handle = NodeBuilder::new(
    Arc::new(DeclarationOnlyStorage::tracked(Arc::clone(&drops))),
    Arc::new(DeclarationOnlyKeys::tracked(Arc::clone(&drops))),
  )
  .clock(Arc::new(VirtualClock::new()))
  .entropy(Arc::new(SequenceEntropy::new(vec![7; 32])))
  .start()
  .await
  .unwrap();

  drop(handle);
  tokio::time::timeout(Duration::from_secs(1), drops.wait_for_all())
    .await
    .unwrap();

  assert_eq!(drops.count(), 2);
}

async fn start_node() -> NodeHandle {
  let clock = Arc::new(VirtualClock::new());
  let entropy = Arc::new(SequenceEntropy::new(vec![7; 32]));
  NodeBuilder::new(
    Arc::new(DeclarationOnlyStorage::new()),
    Arc::new(DeclarationOnlyKeys::new()),
  )
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

use std::{
  future::Future,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  task::{Context, Poll, Waker},
  time::Duration,
};

use minor_relay::{
  BoxFuture, Command, Error, ErrorKind, GetNodeStatus, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, NodeBuilder, NodeConfig, NodeHandle, NodeStatus,
  ProviderErrorContext, ProviderErrorKind, PublicKey, Query, Result, Shutdown, ShutdownOutcome,
  ShutdownReason, Signature, StoreRequirements, WaitForShutdown,
  extension::{KeyProvider, Storage, StorageFactory},
};
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct ProviderCounters {
  calls: AtomicUsize,
}

impl ProviderCounters {
  fn record(&self) {
    self.calls.fetch_add(1, Ordering::SeqCst);
  }

  fn calls(&self) -> usize {
    self.calls.load(Ordering::SeqCst)
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
struct CountingStorageFactory {
  counters: Arc<ProviderCounters>,
  drops: Option<Arc<DropTracker>>,
}

impl Drop for CountingStorageFactory {
  fn drop(&mut self) {
    if let Some(drops) = &self.drops {
      drops.record();
    }
  }
}

impl StorageFactory for CountingStorageFactory {
  fn open<'a>(
    &'a self, _requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::StorageOpen)) })
  }
}

#[derive(Debug)]
struct CountingKeys {
  counters: Arc<ProviderCounters>,
  drops: Option<Arc<DropTracker>>,
}

impl Drop for CountingKeys {
  fn drop(&mut self) {
    if let Some(drops) = &self.drops {
      drops.record();
    }
  }
}

impl KeyProvider for CountingKeys {
  fn capabilities(&self) -> KeyCapabilities {
    self.counters.record();
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyCreate)) })
  }

  fn reconcile_create<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyReconcile)) })
  }

  fn public_key<'a>(&'a self, _handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyPublicKey)) })
  }

  fn sign<'a>(
    &'a self, _handle: &'a KeyHandle, _message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeySign)) })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyDelete)) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.counters.record();
    Box::pin(async { Err(provider_error(ProviderErrorContext::KeyReconcile)) })
  }
}

#[test]
fn g1_lifecycle_sealed_operations_preserve_outputs() {
  fn assert_command<Operation: Command<Output = ShutdownOutcome>>() {}
  fn assert_status_query<Operation: Query<Output = NodeStatus>>() {}
  fn assert_wait_query<Operation: Query<Output = ShutdownReason>>() {}

  assert_command::<Shutdown>();
  assert_status_query::<GetNodeStatus>();
  assert_wait_query::<WaitForShutdown>();
}

#[tokio::test]
async fn g1_lifecycle_start_and_shutdown_do_not_invoke_providers() {
  let counters = Arc::new(ProviderCounters::default());
  let handle = start_node(Arc::clone(&counters), None).await;

  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  assert_eq!(counters.calls(), 0);

  let outcome = handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
  assert_eq!(counters.calls(), 0);
}

#[tokio::test]
async fn g1_lifecycle_cloned_handles_share_runtime_status() {
  let counters = Arc::new(ProviderCounters::default());
  let first = start_node(counters, None).await;
  let second = first.clone();

  assert_eq!(
    first.query(GetNodeStatus::new()).await.unwrap(),
    second.query(GetNodeStatus::new()).await.unwrap(),
  );
  first.command(Shutdown::new()).await.unwrap();
  assert_eq!(
    second.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
}

#[tokio::test]
async fn g1_lifecycle_shutdown_and_wait_are_idempotent() {
  let counters = Arc::new(ProviderCounters::default());
  let handle = start_node(counters, None).await;
  let waiter = handle.clone();
  let waiting = tokio::spawn(async move { waiter.query(WaitForShutdown::new()).await });
  tokio::task::yield_now().await;

  let first = handle.command(Shutdown::new()).await.unwrap();
  let reason = waiting.await.unwrap().unwrap();
  let second = handle.command(Shutdown::new()).await.unwrap();

  assert_eq!(first.reason(), &ShutdownReason::Explicit);
  assert_eq!(second.reason(), &ShutdownReason::Explicit);
  assert_eq!(reason, ShutdownReason::Explicit);
  assert_eq!(
    handle.query(WaitForShutdown::new()).await.unwrap(),
    ShutdownReason::Explicit,
  );
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
}

#[tokio::test]
async fn g1_lifecycle_concurrent_shutdown_runs_one_drain() {
  let counters = Arc::new(ProviderCounters::default());
  let drops = Arc::new(DropTracker::default());
  let handle = start_node(Arc::clone(&counters), Some(Arc::clone(&drops))).await;
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

  for caller in callers {
    assert_eq!(
      caller.await.unwrap().unwrap().reason(),
      &ShutdownReason::Explicit,
    );
  }

  assert_eq!(drops.count(), 2);
  assert_eq!(counters.calls(), 0);
}

#[test]
fn g1_lifecycle_start_without_tokio_returns_not_ready_without_provider_calls() {
  let counters = Arc::new(ProviderCounters::default());
  let mut start = Box::pin(builder(Arc::clone(&counters), None).start());
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);

  let result = Future::poll(start.as_mut(), &mut context);

  assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == ErrorKind::NotReady));
  assert_eq!(counters.calls(), 0);
}

#[test]
fn g1_lifecycle_runtime_loss_publishes_failed_terminal_state() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let counters = Arc::new(ProviderCounters::default());
  let handle = runtime.block_on(start_node(Arc::clone(&counters), None));
  drop(runtime);

  let observer = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  observer.block_on(async {
    assert_eq!(
      handle.query(GetNodeStatus::new()).await.unwrap(),
      NodeStatus::Failed,
    );
    assert_eq!(
      handle.query(WaitForShutdown::new()).await.unwrap(),
      ShutdownReason::Fatal(ErrorKind::Internal),
    );
  });
  assert_eq!(counters.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_shutdown_releases_retained_providers() {
  let counters = Arc::new(ProviderCounters::default());
  let drops = Arc::new(DropTracker::default());
  let handle = start_node(Arc::clone(&counters), Some(Arc::clone(&drops))).await;

  handle.command(Shutdown::new()).await.unwrap();

  assert_eq!(drops.count(), 2);
  assert_eq!(counters.calls(), 0);
}

#[tokio::test]
async fn g1_lifecycle_last_handle_drop_stops_supervisor() {
  let counters = Arc::new(ProviderCounters::default());
  let drops = Arc::new(DropTracker::default());
  let handle = start_node(Arc::clone(&counters), Some(Arc::clone(&drops))).await;

  drop(handle);
  tokio::time::timeout(Duration::from_secs(1), drops.wait_for_all())
    .await
    .unwrap();

  assert_eq!(drops.count(), 2);
  assert_eq!(counters.calls(), 0);
}

fn builder(counters: Arc<ProviderCounters>, drops: Option<Arc<DropTracker>>) -> NodeBuilder {
  NodeBuilder::new(
    Arc::new(CountingStorageFactory {
      counters: Arc::clone(&counters),
      drops: drops.clone(),
    }),
    Arc::new(CountingKeys { counters, drops }),
  )
  .config(NodeConfig::new())
}

async fn start_node(
  counters: Arc<ProviderCounters>, drops: Option<Arc<DropTracker>>,
) -> NodeHandle {
  builder(counters, drops).start().await.unwrap()
}

fn provider_error(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::Internal, context)
}

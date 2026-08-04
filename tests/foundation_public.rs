use std::sync::Arc;

use minor_relay::{
  BoxFuture, Error, GetNodeStatus, NodeBuilder, NodeStatus, ProviderErrorContext,
  ProviderErrorKind, PublicKey, Result, Shutdown, ShutdownReason, Signature, WaitForShutdown,
  extension::{
    KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, KeyProvider, Storage,
    StorageFactory, StoreRequirements,
  },
};

#[derive(Debug)]
struct FacadeStorage;

impl StorageFactory for FacadeStorage {
  fn open<'a>(
    &'a self, _requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async { Err(provider_error(ProviderErrorContext::StorageOpen)) })
  }
}

#[derive(Debug)]
struct FacadeKeys;

impl KeyProvider for FacadeKeys {
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

#[tokio::test]
async fn g1_foundation_public_facade_starts_and_stops_node() {
  let handle = NodeBuilder::new(Arc::new(FacadeStorage), Arc::new(FacadeKeys))
    .start()
    .await
    .unwrap();

  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  let shutdown = handle.command(Shutdown::new()).await.unwrap();
  assert!(!shutdown.already_stopped());
  assert_eq!(
    handle.query(WaitForShutdown::new()).await.unwrap(),
    ShutdownReason::Requested,
  );
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
}

fn provider_error(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::Internal, context)
}

//! Local-identity open and creation lifecycle over journaled metadata
//! storage.
//!
//! Opening the local identity follows the ADR-0001 key lifecycle and the
//! ADR-0003 key-provider operation protocol with exact, bounded recovery:
//!
//! 1. open the metadata store classified by the `local-identity` pending
//!    journal; a recovered journal must reconcile to `Committed` and is then
//!    cleaned up with at most one retry under a fresh transaction ID;
//! 2. refuse key providers without ed25519, reconciliation, and deletion
//!    capabilities before any key operation;
//! 3. discover the exact local-identity singleton and at most one key-creation
//!    intent, failing closed on multiples, malformed values, or a local record
//!    coexisting with an intent;
//! 4. load an existing identity only when the provider returns the persisted
//!    public key for the persisted handle, without any create, sign, delete, or
//!    replacement;
//! 5. otherwise commit a `KeyCreationIntent` (journaling its own receipt
//!    coordinates) before asking the provider to create the key, so a crash or
//!    unknown outcome always resumes through `reconcile_create` with the same
//!    operation; and
//! 6. finalize through one journaled transaction that deletes the intent, puts
//!    the exact `LocalIdentityV1` singleton, and moves the receipt references,
//!    reconciling unknown outcomes exactly and accepting only the exact final
//!    state after a proven abort.
//!
//! No path retries unboundedly and no path ever calls `KeyProvider::delete`.

use std::{sync::Arc, time::Duration};

use super::records::{
  KeyCreationIntentV1, LocalIdentityV1, key_creation_intent_key, key_creation_intent_namespace,
  local_identity_key,
};
use crate::{
  CommitOutcome, CreatedKey, Error, KeyCreateState, KeyOperationId, NodeId, ProviderErrorContext,
  ProviderErrorKind, ReconcileOutcome, Result, StoreExpectation, StoreOperation, StoreValue,
  TransactionId,
  api::Entropy,
  provider::{KeyProvider, StorageFactory, StoreSnapshot},
  storage::{
    MetadataStore,
    pending::PendingCleanupOutcome,
    receipt::{ReceiptReferenceChange, ReceiptReferenceToken},
  },
};

const LOCAL_IDENTITY_PURPOSE: &str = "local-identity";

/// An opened local identity paired with its metadata store.
///
/// The identity record was either loaded after the provider returned the
/// exact persisted public key or created and finalized through the journaled
/// intent protocol.
#[derive(Debug)]
pub(crate) struct LocalIdentityContext {
  store: MetadataStore,
  identity: LocalIdentityV1,
}

impl LocalIdentityContext {
  pub(crate) const fn store(&self) -> &MetadataStore {
    &self.store
  }

  pub(crate) const fn identity(&self) -> &LocalIdentityV1 {
    &self.identity
  }
}

/// Opens or creates the local node identity with exact crash recovery.
///
/// `keys` must report ed25519, reconciliation, and deletion capabilities
/// before any key operation runs. `entropy` supplies every generated node,
/// operation, and transaction ID. `receipt_retention` is forwarded to the
/// metadata store's receipt-retention policy.
pub(crate) async fn open_local_identity(
  factory: &Arc<dyn StorageFactory>, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  receipt_retention: Duration,
) -> Result<LocalIdentityContext> {
  let (store, recovered) =
    MetadataStore::open_pending_recovered(factory, receipt_retention, LOCAL_IDENTITY_PURPOSE)
      .await?;
  if recovered.is_some() {
    reconcile_recovered_journal(&store).await?;
    cleanup_pending_exact(&store, entropy).await?;
  }
  require_key_capabilities(keys)?;

  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref()).await?;
  let intent = discover_key_creation_intent(snapshot.as_ref()).await?;
  match (local, intent) {
    (Some(_), Some(_)) => Err(discovery_corrupt()),
    (Some((_, identity)), None) => load_existing_identity(store, keys, identity).await,
    (None, None) => create_identity(store, keys, entropy, snapshot).await,
    (None, Some((stored, intent))) => {
      resume_identity_creation(store, keys, entropy, stored, intent).await
    }
  }
}

/// Reconciles a pending journal recovered at open.
///
/// The journaled pending record proves the target transaction committed
/// atomically, so only `Committed` is acceptable.
async fn reconcile_recovered_journal(store: &MetadataStore) -> Result<()> {
  match store.reconcile().await? {
    ReconcileOutcome::Committed(_) => Ok(()),
    ReconcileOutcome::Aborted | ReconcileOutcome::DigestConflict => Err(reconcile_corrupt()),
    ReconcileOutcome::Unknown => Err(reconcile_unknown()),
  }
}

/// Deletes the pending journal record exactly once, tolerating one proven
/// abort with a fresh transaction ID.
async fn cleanup_pending_exact(store: &MetadataStore, entropy: &dyn Entropy) -> Result<()> {
  let mut attempts = 0_u8;
  loop {
    attempts += 1;
    let operation = TransactionId::generate(entropy)?;
    match store
      .cleanup_pending(LOCAL_IDENTITY_PURPOSE, operation)
      .await?
    {
      PendingCleanupOutcome::Applied(_) | PendingCleanupOutcome::Absent => return Ok(()),
      PendingCleanupOutcome::Conflict => {
        return Err(Error::conflict("local identity pending cleanup"));
      }
      PendingCleanupOutcome::Aborted => {
        if attempts >= 2 {
          return Err(Error::conflict("local identity pending cleanup"));
        }
      }
      PendingCleanupOutcome::Unknown(_) => match store.reconcile().await? {
        ReconcileOutcome::Committed(_) => return Ok(()),
        ReconcileOutcome::Aborted => {
          if attempts >= 2 {
            return Err(Error::conflict("local identity pending cleanup"));
          }
        }
        ReconcileOutcome::DigestConflict => return Err(reconcile_corrupt()),
        ReconcileOutcome::Unknown => return Err(reconcile_unknown()),
      },
    }
  }
}

fn require_key_capabilities(keys: &Arc<dyn KeyProvider>) -> Result<()> {
  let capabilities = keys.capabilities();
  if !capabilities.has_ed25519()
    || !capabilities.has_reconciliation()
    || !capabilities.has_deletion()
  {
    return Err(Error::provider(
      ProviderErrorKind::UnsupportedCapability,
      ProviderErrorContext::KeyCreate,
    ));
  }
  Ok(())
}

/// Discovers zero or one local-identity singleton from a snapshot.
///
/// Any prefix-extended key, duplicate entry, or malformed value fails closed
/// as storage corruption.
async fn discover_local_identity(
  snapshot: &dyn StoreSnapshot,
) -> Result<Option<(StoreValue, LocalIdentityV1)>> {
  let (namespace, key) = local_identity_key()?;
  let mut scan = snapshot.scan(&namespace, key.as_bytes()).await?;
  let mut found = None;
  while let Some(entry) = scan.next().await? {
    if entry.namespace() != &namespace || entry.key() != &key {
      return Err(discovery_corrupt());
    }
    if found.is_some() {
      return Err(discovery_corrupt());
    }
    let record =
      LocalIdentityV1::decode(entry.value().as_bytes()).map_err(|_| discovery_corrupt())?;
    found = Some((entry.value().clone(), record));
  }
  Ok(found)
}

/// Discovers zero or one key-creation intent from a snapshot.
///
/// The intent key must match the decoded operation exactly and the intent
/// must carry the local-identity purpose; any other shape fails closed as
/// storage corruption.
async fn discover_key_creation_intent(
  snapshot: &dyn StoreSnapshot,
) -> Result<Option<(StoreValue, KeyCreationIntentV1)>> {
  let namespace = key_creation_intent_namespace()?;
  let mut scan = snapshot.scan(&namespace, &[]).await?;
  let mut found = None;
  while let Some(entry) = scan.next().await? {
    if entry.namespace() != &namespace {
      return Err(discovery_corrupt());
    }
    if found.is_some() {
      return Err(discovery_corrupt());
    }
    let record =
      KeyCreationIntentV1::decode(entry.value().as_bytes()).map_err(|_| discovery_corrupt())?;
    let (_, expected_key) = key_creation_intent_key(record.operation())?;
    if entry.key() != &expected_key || record.purpose() != LOCAL_IDENTITY_PURPOSE {
      return Err(discovery_corrupt());
    }
    found = Some((entry.value().clone(), record));
  }
  Ok(found)
}

/// Loads a persisted identity only when the provider returns the exact
/// persisted public key for the persisted handle.
async fn load_existing_identity(
  store: MetadataStore, keys: &Arc<dyn KeyProvider>, identity: LocalIdentityV1,
) -> Result<LocalIdentityContext> {
  verify_provider_key(keys, identity.handle(), identity.public_key()).await?;
  Ok(LocalIdentityContext { store, identity })
}

/// Creates a fresh identity: generate coordinates, commit the key-creation
/// intent with its own receipt reference, reconcile an unknown intent commit
/// exactly once, then ask the provider to create the key.
async fn create_identity(
  store: MetadataStore, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  snapshot: Box<dyn StoreSnapshot>,
) -> Result<LocalIdentityContext> {
  let node = NodeId::generate(entropy)?;
  let operation = KeyOperationId::generate(entropy)?;
  let transaction = TransactionId::generate(entropy)?;
  let intent = KeyCreationIntentV1::new(
    operation,
    node,
    LOCAL_IDENTITY_PURPOSE.to_owned(),
    transaction,
    snapshot.revision().clone(),
  )?;
  let value = StoreValue::new(Arc::from(intent.encode()?));
  let (namespace, key) = key_creation_intent_key(intent.operation())?;
  let token = ReceiptReferenceToken::for_record(&namespace, &key);
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      intent.transaction().clone(),
      vec![StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value: value.clone(),
      }],
      vec![ReceiptReferenceChange::AddSelf(vec![token])],
    )
    .await?;
  drop(snapshot);
  match store.commit(prepared).await? {
    CommitOutcome::Committed(_) => {}
    CommitOutcome::Aborted | CommitOutcome::Conflict => {
      return Err(Error::conflict("local identity intent commit"));
    }
    CommitOutcome::Unknown { .. } => match store.reconcile().await? {
      ReconcileOutcome::Committed(_) => {}
      ReconcileOutcome::Aborted => {
        return Err(Error::conflict("local identity intent commit"));
      }
      ReconcileOutcome::DigestConflict => return Err(reconcile_corrupt()),
      ReconcileOutcome::Unknown => return Err(reconcile_unknown()),
    },
  }
  let created = create_key_exact(keys, intent.operation()).await?;
  finalize_identity(store, entropy, intent, value, created).await
}

/// Resumes creation from a persisted intent: reconcile the provider
/// operation first, creating only when the provider proves the key absent.
async fn resume_identity_creation(
  store: MetadataStore, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy, stored: StoreValue,
  intent: KeyCreationIntentV1,
) -> Result<LocalIdentityContext> {
  let created = match keys.reconcile_create(intent.operation()).await? {
    KeyCreateState::Present(created) => {
      verify_created_key(keys, &created).await?;
      created
    }
    KeyCreateState::Absent => create_key_exact(keys, intent.operation()).await?,
    KeyCreateState::Unknown => {
      return Err(Error::provider(
        ProviderErrorKind::CommitUnknown,
        ProviderErrorContext::KeyReconcile,
      ));
    }
  };
  finalize_identity(store, entropy, intent, stored, created).await
}

async fn create_key_exact(
  keys: &Arc<dyn KeyProvider>, operation: &KeyOperationId,
) -> Result<CreatedKey> {
  match keys.create_ed25519(operation).await? {
    KeyCreateState::Present(created) => {
      verify_created_key(keys, &created).await?;
      Ok(created)
    }
    KeyCreateState::Absent => Err(Error::not_ready("local identity key create")),
    KeyCreateState::Unknown => Err(Error::provider(
      ProviderErrorKind::CommitUnknown,
      ProviderErrorContext::KeyCreate,
    )),
  }
}

async fn verify_created_key(keys: &Arc<dyn KeyProvider>, created: &CreatedKey) -> Result<()> {
  verify_provider_key(keys, created.handle(), created.public_key()).await
}

/// Verifies that the provider returns exactly `expected` for `handle`.
async fn verify_provider_key(
  keys: &Arc<dyn KeyProvider>, handle: &crate::KeyHandle, expected: &crate::PublicKey,
) -> Result<()> {
  let provided = keys.public_key(handle).await?;
  if &provided != expected {
    return Err(Error::provider(
      ProviderErrorKind::Internal,
      ProviderErrorContext::KeyPublicKey,
    ));
  }
  Ok(())
}

/// Atomically replaces the intent with the exact local-identity singleton.
///
/// The journaled transaction deletes the intent by exact digest, puts the
/// identity record under the absent singleton, removes the intent token from
/// the intent transaction's receipt, and references the identity and pending
/// records from its own receipt. Unknown outcomes reconcile exactly once; a
/// proven abort is accepted only when a fresh snapshot shows the exact final
/// state.
async fn finalize_identity(
  store: MetadataStore, entropy: &dyn Entropy, intent: KeyCreationIntentV1,
  stored_intent: StoreValue, created: CreatedKey,
) -> Result<LocalIdentityContext> {
  let identity = LocalIdentityV1::new(
    intent.intended_node().clone(),
    created.public_key().clone(),
    intent.operation().clone(),
    created.handle().clone(),
  );
  let target = intent.recovery_identity(&stored_intent)?;
  let snapshot = store.snapshot().await?;
  let (local_namespace, local_key) = local_identity_key()?;
  let (intent_namespace, intent_key) = key_creation_intent_key(intent.operation())?;
  let local_token = ReceiptReferenceToken::for_record(&local_namespace, &local_key);
  let intent_token = ReceiptReferenceToken::for_record(&intent_namespace, &intent_key);
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      TransactionId::generate(entropy)?,
      LOCAL_IDENTITY_PURPOSE,
      vec![
        StoreOperation::Delete {
          namespace: intent_namespace,
          key: intent_key,
          expected: stored_intent.digest().clone(),
        },
        StoreOperation::Put {
          namespace: local_namespace,
          key: local_key,
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(identity.encode()?)),
        },
      ],
      vec![
        ReceiptReferenceChange::Remove {
          target,
          tokens: vec![intent_token],
        },
        ReceiptReferenceChange::AddSelf(vec![local_token]),
      ],
    )
    .await?;
  drop(snapshot);
  match store.commit(prepared).await? {
    CommitOutcome::Committed(_) => {}
    CommitOutcome::Aborted | CommitOutcome::Conflict => {
      accept_exact_final_state(&store, &identity).await?;
    }
    CommitOutcome::Unknown { .. } => match store.reconcile().await? {
      ReconcileOutcome::Committed(_) => {}
      ReconcileOutcome::Aborted => {
        accept_exact_final_state(&store, &identity).await?;
      }
      ReconcileOutcome::DigestConflict => return Err(reconcile_corrupt()),
      ReconcileOutcome::Unknown => return Err(reconcile_unknown()),
    },
  }
  cleanup_pending_exact(&store, entropy).await?;
  Ok(LocalIdentityContext { store, identity })
}

/// Accepts a proven-abort finalize only when a fresh snapshot shows the
/// exact expected identity and no remaining intent.
async fn accept_exact_final_state(store: &MetadataStore, expected: &LocalIdentityV1) -> Result<()> {
  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref()).await?;
  let intent = discover_key_creation_intent(snapshot.as_ref()).await?;
  match (local, intent) {
    (Some((_, identity)), None) if &identity == expected => Ok(()),
    _ => Err(Error::conflict("local identity finalize")),
  }
}

fn discovery_corrupt() -> Error {
  Error::provider(
    ProviderErrorKind::StorageCorrupt,
    ProviderErrorContext::StorageSnapshot,
  )
}

fn reconcile_corrupt() -> Error {
  Error::provider(
    ProviderErrorKind::StorageCorrupt,
    ProviderErrorContext::StorageReconcile,
  )
}

fn reconcile_unknown() -> Error {
  Error::provider(
    ProviderErrorKind::CommitUnknown,
    ProviderErrorContext::StorageReconcile,
  )
}

#[cfg(test)]
mod tests {
  use std::{
    collections::{BTreeMap, VecDeque},
    future,
    sync::{
      Arc, Mutex,
      atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
  };

  use ed25519_dalek::{Signer, SigningKey};

  use super::*;
  use crate::{
    BoxFuture, Digest, ErrorKind, KeyCapabilities, KeyDeleteState, KeyHandle, PublicKey,
    QualifiedTag, Signature, StoreCapabilities, StoreKey, StoreNamespace, StoreRequirements,
    StoreRevision, StoreTransaction,
    provider::{KeyProvider, Storage},
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  const RETENTION: Duration = Duration::from_secs(3_600);
  const PENDING_NAMESPACE: &str = "relay.woooo.tech/metadata/pending-transaction-v1";

  // Entropy fills produce base62 suffix values 1, 2, 3, ...; every test uses
  // fewer than ten fills, so decimal zero-padding matches base62 encoding.
  #[derive(Debug, Default)]
  struct SequenceEntropy(Mutex<u128>);

  impl Entropy for SequenceEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
      if output.len() != 16 {
        return Err(Error::internal("sequence entropy length"));
      }
      let mut next = self.0.lock().unwrap();
      *next = next
        .checked_add(1)
        .ok_or_else(|| Error::internal("sequence entropy exhausted"))?;
      output.copy_from_slice(&next.to_be_bytes());
      Ok(())
    }
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
  enum KeyCall {
    Create(KeyOperationId),
    ReconcileCreate(KeyOperationId),
    PublicKey(Vec<u8>),
    Sign,
    Delete,
    ReconcileDelete,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CreateScript {
    Apply,
    ApplyReportUnknown,
    ReportAbsent,
    HangWithoutApply,
  }

  #[derive(Debug)]
  struct ScriptedKeys {
    capabilities: KeyCapabilities,
    inner: Arc<ScriptedKeyInner>,
  }

  #[derive(Debug)]
  struct ScriptedKeyInner {
    records: Mutex<BTreeMap<Vec<u8>, (KeyOperationId, SigningKey)>>,
    operations: Mutex<BTreeMap<KeyOperationId, Vec<u8>>>,
    calls: Mutex<Vec<KeyCall>>,
    create_script: Mutex<VecDeque<CreateScript>>,
    reconcile_unknowns: Mutex<usize>,
    public_key_override: Mutex<Option<PublicKey>>,
    next_handle: AtomicUsize,
  }

  fn scripted_signing(index: u64) -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    SigningKey::from_bytes(&seed)
  }

  impl ScriptedKeys {
    fn new(capabilities: KeyCapabilities) -> Self {
      Self {
        capabilities,
        inner: Arc::new(ScriptedKeyInner {
          records: Mutex::new(BTreeMap::new()),
          operations: Mutex::new(BTreeMap::new()),
          calls: Mutex::new(Vec::new()),
          create_script: Mutex::new(VecDeque::new()),
          reconcile_unknowns: Mutex::new(0),
          public_key_override: Mutex::new(None),
          next_handle: AtomicUsize::new(0),
        }),
      }
    }

    fn full() -> Self {
      Self::new(
        KeyCapabilities::new()
          .ed25519(true)
          .reconciliation(true)
          .deletion(true),
      )
    }

    fn take_calls(&self) -> Vec<KeyCall> {
      std::mem::take(&mut *self.inner.calls.lock().unwrap())
    }
  }

  impl ScriptedKeyInner {
    fn push_call(&self, call: KeyCall) {
      self.calls.lock().unwrap().push(call);
    }

    fn apply_create(&self, operation: &KeyOperationId) -> CreatedKey {
      let mut operations = self.operations.lock().unwrap();
      if let Some(handle) = operations.get(operation) {
        let records = self.records.lock().unwrap();
        let (_, signing) = records.get(handle).unwrap();
        return CreatedKey::new(
          KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
          PublicKey::from_bytes(signing.verifying_key().to_bytes()),
        );
      }
      let index = self.next_handle.fetch_add(1, Ordering::SeqCst) as u64;
      let signing = scripted_signing(index);
      let handle = format!("scripted-handle-{index}").into_bytes();
      let created = CreatedKey::new(
        KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      );
      operations.insert(operation.clone(), handle.clone());
      self
        .records
        .lock()
        .unwrap()
        .insert(handle, (operation.clone(), signing));
      created
    }

    fn lookup_operation(&self, operation: &KeyOperationId) -> Option<CreatedKey> {
      let handle = self.operations.lock().unwrap().get(operation).cloned()?;
      let records = self.records.lock().unwrap();
      let (_, signing) = records.get(&handle).unwrap();
      Some(CreatedKey::new(
        KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ))
    }
  }

  impl KeyProvider for ScriptedKeys {
    fn capabilities(&self) -> KeyCapabilities {
      self.capabilities
    }

    fn create_ed25519<'a>(
      &'a self, operation: &'a KeyOperationId,
    ) -> BoxFuture<'a, Result<KeyCreateState>> {
      self.inner.push_call(KeyCall::Create(operation.clone()));
      let script = self
        .inner
        .create_script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(CreateScript::Apply);
      Box::pin(async move {
        match script {
          CreateScript::Apply => Ok(KeyCreateState::Present(self.inner.apply_create(operation))),
          CreateScript::ApplyReportUnknown => {
            self.inner.apply_create(operation);
            Ok(KeyCreateState::Unknown)
          }
          CreateScript::ReportAbsent => Ok(KeyCreateState::Absent),
          CreateScript::HangWithoutApply => future::pending().await,
        }
      })
    }

    fn reconcile_create<'a>(
      &'a self, operation: &'a KeyOperationId,
    ) -> BoxFuture<'a, Result<KeyCreateState>> {
      self
        .inner
        .push_call(KeyCall::ReconcileCreate(operation.clone()));
      let unknown = {
        let mut left = self.inner.reconcile_unknowns.lock().unwrap();
        if *left > 0 {
          *left -= 1;
          true
        } else {
          false
        }
      };
      let present = self.inner.lookup_operation(operation);
      Box::pin(async move {
        if unknown {
          return Ok(KeyCreateState::Unknown);
        }
        Ok(match present {
          Some(created) => KeyCreateState::Present(created),
          None => KeyCreateState::Absent,
        })
      })
    }

    fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
      self
        .inner
        .push_call(KeyCall::PublicKey(handle.expose_provider_handle().to_vec()));
      let override_key = self.inner.public_key_override.lock().unwrap().clone();
      let result = match &override_key {
        Some(key) => Ok(key.clone()),
        None => self
          .inner
          .records
          .lock()
          .unwrap()
          .get(handle.expose_provider_handle())
          .map(|(_, signing)| PublicKey::from_bytes(signing.verifying_key().to_bytes()))
          .ok_or_else(|| {
            Error::provider(
              ProviderErrorKind::Internal,
              ProviderErrorContext::KeyPublicKey,
            )
          }),
      };
      Box::pin(async move { result })
    }

    fn sign<'a>(
      &'a self, handle: &'a KeyHandle, message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature>> {
      self.inner.push_call(KeyCall::Sign);
      let result = self
        .inner
        .records
        .lock()
        .unwrap()
        .get(handle.expose_provider_handle())
        .map(|(_, signing)| Signature::from_bytes(signing.sign(message).to_bytes()))
        .ok_or_else(|| Error::provider(ProviderErrorKind::Internal, ProviderErrorContext::KeySign));
      Box::pin(async move { result })
    }

    fn delete<'a>(
      &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
    ) -> BoxFuture<'a, Result<KeyDeleteState>> {
      self.inner.push_call(KeyCall::Delete);
      Box::pin(async { Err(Error::internal("unexpected key deletion")) })
    }

    fn reconcile_delete<'a>(
      &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
    ) -> BoxFuture<'a, Result<KeyDeleteState>> {
      self.inner.push_call(KeyCall::ReconcileDelete);
      Box::pin(async { Err(Error::internal("unexpected key deletion")) })
    }
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CommitFault {
    Pass,
    Aborted,
    UnknownApplied,
    UnknownNotApplied,
    HangApplied,
  }

  #[derive(Debug)]
  struct FaultingFactory {
    reference: Arc<ReferenceFactory>,
    script: Arc<Mutex<VecDeque<CommitFault>>>,
  }

  impl FaultingFactory {
    fn new(reference: &Arc<ReferenceFactory>, script: Vec<CommitFault>) -> Self {
      Self {
        reference: Arc::clone(reference),
        script: Arc::new(Mutex::new(script.into())),
      }
    }
  }

  #[derive(Debug)]
  struct FaultingStorage {
    reference: Box<dyn Storage>,
    script: Arc<Mutex<VecDeque<CommitFault>>>,
  }

  impl StorageFactory for FaultingFactory {
    fn open<'a>(
      &'a self, requirements: StoreRequirements,
    ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
      Box::pin(async move {
        let reference = self.reference.open(requirements).await?;
        Ok(Box::new(FaultingStorage {
          reference,
          script: Arc::clone(&self.script),
        }) as Box<dyn Storage>)
      })
    }
  }

  impl Storage for FaultingStorage {
    fn capabilities(&self) -> StoreCapabilities {
      self.reference.capabilities()
    }

    fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
      self.reference.snapshot()
    }

    fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
      let fault = self
        .script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(CommitFault::Pass);
      Box::pin(async move {
        let id = transaction.id().clone();
        let digest = transaction.operation_digest().clone();
        match fault {
          CommitFault::Pass => self.reference.commit(transaction).await,
          CommitFault::Aborted => Ok(CommitOutcome::Aborted),
          CommitFault::UnknownNotApplied => Ok(CommitOutcome::Unknown {
            transaction: id,
            operation_digest: digest,
          }),
          CommitFault::UnknownApplied => {
            assert!(matches!(
              self.reference.commit(transaction).await?,
              CommitOutcome::Committed(_)
            ));
            Ok(CommitOutcome::Unknown {
              transaction: id,
              operation_digest: digest,
            })
          }
          CommitFault::HangApplied => {
            assert!(matches!(
              self.reference.commit(transaction).await?,
              CommitOutcome::Committed(_)
            ));
            future::pending().await
          }
        }
      })
    }

    fn reconcile<'a>(
      &'a self, transaction: &'a TransactionId, digest: &'a Digest,
    ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
      self.reference.reconcile(transaction, digest)
    }

    fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
      self.reference.flush()
    }
  }

  fn node(value: u128) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn operation(value: u128) -> KeyOperationId {
    KeyOperationId::parse(&format!("keyop_{value:021}")).unwrap()
  }

  fn transaction(value: u128) -> TransactionId {
    TransactionId::parse(&format!("txn_{value:021}")).unwrap()
  }

  fn namespace(tag: &str) -> StoreNamespace {
    StoreNamespace::new(QualifiedTag::parse(tag).unwrap()).unwrap()
  }

  fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
  }

  fn fresh_reference() -> (Arc<ReferenceFactory>, Arc<dyn StorageFactory>) {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn StorageFactory> = reference.clone();
    (reference, factory)
  }

  async fn open_with(
    factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
  ) -> Result<LocalIdentityContext> {
    let keys: Arc<dyn KeyProvider> = keys;
    open_local_identity(&factory, &keys, entropy.as_ref(), RETENTION).await
  }

  fn stored_local(reference: &Arc<ReferenceFactory>) -> Option<LocalIdentityV1> {
    let (namespace, key) = local_identity_key().unwrap();
    reference
      .state
      .lock()
      .unwrap()
      .entries
      .get(&(namespace, key))
      .map(|value| LocalIdentityV1::decode(value.as_bytes()).unwrap())
  }

  fn stored_intents(reference: &Arc<ReferenceFactory>) -> Vec<KeyCreationIntentV1> {
    let namespace = key_creation_intent_namespace().unwrap();
    reference
      .state
      .lock()
      .unwrap()
      .entries
      .iter()
      .filter(|((entry_namespace, _), _)| entry_namespace == &namespace)
      .map(|(_, value)| KeyCreationIntentV1::decode(value.as_bytes()).unwrap())
      .collect()
  }

  fn pending_present(reference: &Arc<ReferenceFactory>) -> bool {
    let namespace = namespace(PENDING_NAMESPACE);
    reference
      .state
      .lock()
      .unwrap()
      .entries
      .keys()
      .any(|(entry_namespace, _)| entry_namespace == &namespace)
  }

  fn receipt_ids(reference: &Arc<ReferenceFactory>) -> Vec<TransactionId> {
    let mut ids: Vec<TransactionId> = reference
      .state
      .lock()
      .unwrap()
      .receipts
      .keys()
      .cloned()
      .collect();
    ids.sort();
    ids
  }

  fn commit_calls(reference: &Arc<ReferenceFactory>) -> usize {
    reference.commit_calls.load(Ordering::SeqCst)
  }

  fn assert_never_signed_or_deleted(keys: &ScriptedKeys) {
    for call in keys.inner.calls.lock().unwrap().iter() {
      assert!(
        !matches!(
          call,
          KeyCall::Sign | KeyCall::Delete | KeyCall::ReconcileDelete
        ),
        "unexpected provider call: {call:?}"
      );
    }
  }

  fn assert_final_state(reference: &Arc<ReferenceFactory>, expected: &LocalIdentityV1) {
    assert_eq!(stored_local(reference).as_ref(), Some(expected));
    assert!(stored_intents(reference).is_empty());
    assert!(!pending_present(reference));
  }

  #[tokio::test]
  async fn identity_records_lifecycle_fresh_open_runs_exact_provider_and_commit_order() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    let identity = context.identity().clone();
    let created = keys.inner.lookup_operation(&operation(2)).unwrap();

    assert_eq!(identity.node(), &node(1));
    assert_eq!(identity.operation(), &operation(2));
    assert_eq!(identity.handle(), created.handle());
    assert_eq!(identity.public_key(), created.public_key());
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    assert_final_state(&reference, &identity);
    assert_eq!(commit_calls(&reference), 3);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(5)]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_restart_loads_persisted_identity_without_create() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());

    let first = open_with(factory.clone(), keys.clone(), entropy.clone())
      .await
      .unwrap();
    let identity = first.identity().clone();
    let handle = identity.handle().expose_provider_handle().to_vec();
    let commits = commit_calls(&reference);
    keys.take_calls();
    drop(first);

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    assert_eq!(context.identity(), &identity);
    assert_eq!(keys.take_calls(), vec![KeyCall::PublicKey(handle)]);
    assert_eq!(commit_calls(&reference), commits);
    assert_final_state(&reference, &identity);
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_missing_handle_fails_closed_without_replacement() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());

    let first = open_with(factory.clone(), keys, entropy.clone())
      .await
      .unwrap();
    let identity = first.identity().clone();
    let commits = commit_calls(&reference);
    drop(first);

    let missing = Arc::new(ScriptedKeys::full());
    let error = open_with(factory, missing.clone(), entropy)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "key public key");
    assert_eq!(
      missing.take_calls(),
      vec![KeyCall::PublicKey(
        identity.handle().expose_provider_handle().to_vec()
      )]
    );
    assert_eq!(commit_calls(&reference), commits);
    assert_eq!(stored_local(&reference).as_ref(), Some(&identity));
    assert_never_signed_or_deleted(&missing);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_mismatched_public_key_fails_closed_without_replacement() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());

    let first = open_with(factory.clone(), keys, entropy.clone())
      .await
      .unwrap();
    let identity = first.identity().clone();
    let commits = commit_calls(&reference);
    drop(first);

    let mismatched = ScriptedKeys::full();
    *mismatched.inner.public_key_override.lock().unwrap() = Some(PublicKey::from_bytes(
      scripted_signing(9_999).verifying_key().to_bytes(),
    ));
    let mismatched = Arc::new(mismatched);
    let error = open_with(factory, mismatched.clone(), entropy)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "key public key");
    assert_eq!(
      mismatched.take_calls(),
      vec![KeyCall::PublicKey(
        identity.handle().expose_provider_handle().to_vec()
      )]
    );
    assert_eq!(commit_calls(&reference), commits);
    assert_eq!(stored_local(&reference).as_ref(), Some(&identity));
    assert_never_signed_or_deleted(&mismatched);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_missing_capabilities_refused_before_key_mutation() {
    for capabilities in [
      KeyCapabilities::new()
        .ed25519(false)
        .reconciliation(true)
        .deletion(true),
      KeyCapabilities::new()
        .ed25519(true)
        .reconciliation(false)
        .deletion(true),
      KeyCapabilities::new()
        .ed25519(true)
        .reconciliation(true)
        .deletion(false),
      KeyCapabilities::new(),
    ] {
      let (reference, factory) = fresh_reference();
      let keys = Arc::new(ScriptedKeys::new(capabilities));
      let entropy = Arc::new(SequenceEntropy::default());

      let error = open_with(factory.clone(), keys.clone(), entropy.clone())
        .await
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
      assert_eq!(keys.take_calls(), vec![]);
      assert_eq!(commit_calls(&reference), 0);
      assert!(stored_local(&reference).is_none());
      assert!(stored_intents(&reference).is_empty());

      let capable = Arc::new(ScriptedKeys::full());
      let context = open_with(factory, capable.clone(), entropy).await.unwrap();
      assert_final_state(&reference, context.identity());
      assert_eq!(commit_calls(&reference), 3);
      assert_never_signed_or_deleted(&capable);
    }
  }

  #[tokio::test]
  async fn identity_records_lifecycle_create_unknown_restart_reconciles_same_operation() {
    let (reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    keys
      .inner
      .create_script
      .lock()
      .unwrap()
      .push_back(CreateScript::ApplyReportUnknown);
    let keys = Arc::new(keys);
    let entropy = Arc::new(SequenceEntropy::default());

    let error = open_with(factory.clone(), keys.clone(), entropy.clone())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);
    assert_eq!(error.context(), "key create");
    let first_calls = keys.take_calls();
    assert_eq!(first_calls, vec![KeyCall::Create(operation(2))]);

    let intents = stored_intents(&reference);
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].operation(), &operation(2));
    assert_eq!(intents[0].intended_node(), &node(1));
    assert!(stored_local(&reference).is_none());
    assert!(!pending_present(&reference));
    assert_eq!(commit_calls(&reference), 1);
    assert_eq!(receipt_ids(&reference), vec![transaction(3)]);

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    let identity = context.identity().clone();
    let created = keys.inner.lookup_operation(&operation(2)).unwrap();
    assert_eq!(identity.node(), &node(1));
    assert_eq!(identity.operation(), &operation(2));
    assert_eq!(identity.handle(), created.handle());
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::ReconcileCreate(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    let creates = first_calls
      .iter()
      .chain(keys.inner.calls.lock().unwrap().iter())
      .filter(|call| matches!(call, KeyCall::Create(_)))
      .count();
    assert_eq!(creates, 1);
    assert_final_state(&reference, &identity);
    assert_eq!(commit_calls(&reference), 3);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(5)]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_finalize_interrupted_after_apply_recovers_via_journal() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![CommitFault::Pass, CommitFault::HangApplied],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault;

    let task = tokio::spawn({
      let fault_factory = fault_factory.clone();
      let keys = keys.clone();
      let entropy = entropy.clone();
      async move { open_with(fault_factory, keys, entropy).await }
    });
    for _ in 0..10_000 {
      if reference.state.lock().unwrap().receipts.len() >= 2 {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(reference.state.lock().unwrap().receipts.len(), 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(fault_factory);

    let created = keys.inner.lookup_operation(&operation(2)).unwrap();
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    let interrupted = stored_local(&reference).unwrap();
    assert_eq!(interrupted.node(), &node(1));
    assert!(stored_intents(&reference).is_empty());
    assert!(pending_present(&reference));

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    assert_eq!(context.identity(), &interrupted);
    assert_eq!(
      keys.take_calls(),
      vec![KeyCall::PublicKey(
        created.handle().expose_provider_handle().to_vec()
      )]
    );
    assert_final_state(&reference, &interrupted);
    assert_eq!(commit_calls(&reference), 3);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(5)]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_finalize_unknown_not_applied_resumes_intent() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![CommitFault::Pass, CommitFault::UnknownNotApplied],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault;

    let error = open_with(fault_factory, keys.clone(), entropy.clone())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(error.context(), "local identity finalize");
    let created = keys.inner.lookup_operation(&operation(2)).unwrap();
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    assert_eq!(stored_intents(&reference).len(), 1);
    assert!(stored_local(&reference).is_none());
    assert!(!pending_present(&reference));
    assert_eq!(receipt_ids(&reference), vec![transaction(3)]);

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    let identity = context.identity().clone();
    assert_eq!(identity.node(), &node(1));
    assert_eq!(identity.operation(), &operation(2));
    assert_eq!(identity.handle(), created.handle());
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::ReconcileCreate(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    assert_final_state(&reference, &identity);
    assert_eq!(commit_calls(&reference), 3);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(5), transaction(6)]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_finalize_unknown_applied_reconciles_in_run() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::UnknownApplied,
        CommitFault::Pass,
      ],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault;

    let context = open_with(fault_factory, keys.clone(), entropy.clone())
      .await
      .unwrap();
    let identity = context.identity().clone();
    assert_eq!(identity.node(), &node(1));
    let created = keys.inner.lookup_operation(&operation(2)).unwrap();
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    assert_final_state(&reference, &identity);
    assert_eq!(commit_calls(&reference), 3);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(5)]
    );
    drop(context);

    let reloaded = open_with(factory, keys.clone(), entropy).await.unwrap();
    assert_eq!(reloaded.identity(), &identity);
    assert_eq!(
      keys.take_calls(),
      vec![KeyCall::PublicKey(
        created.handle().expose_provider_handle().to_vec()
      )]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_cleanup_aborted_retries_once_with_fresh_id() {
    let (reference, _factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Aborted,
        CommitFault::Pass,
      ],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault.clone();

    let context = open_with(fault_factory, keys.clone(), entropy)
      .await
      .unwrap();
    assert_final_state(&reference, context.identity());
    assert_eq!(commit_calls(&reference), 3);
    assert!(fault.script.lock().unwrap().is_empty());
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(6)]
    );
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_cleanup_unknown_reconciles_exactly_once() {
    for (script, expected) in [
      (
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::UnknownApplied,
        ],
        vec![transaction(3), transaction(4), transaction(5)],
      ),
      (
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::UnknownNotApplied,
          CommitFault::Pass,
        ],
        vec![transaction(3), transaction(4), transaction(6)],
      ),
    ] {
      let (reference, _factory) = fresh_reference();
      let keys = Arc::new(ScriptedKeys::full());
      let entropy = Arc::new(SequenceEntropy::default());
      let fault = Arc::new(FaultingFactory::new(&reference, script));
      let fault_factory: Arc<dyn StorageFactory> = fault;

      let context = open_with(fault_factory, keys.clone(), entropy)
        .await
        .unwrap();
      assert_final_state(&reference, context.identity());
      assert_eq!(receipt_ids(&reference), expected);
      assert_never_signed_or_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_lifecycle_reconcile_create_unknown_leaves_intent_untouched() {
    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![CommitFault::HangApplied],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault;

    let task = tokio::spawn({
      let fault_factory = fault_factory.clone();
      let keys = keys.clone();
      let entropy = entropy.clone();
      async move { open_with(fault_factory, keys, entropy).await }
    });
    for _ in 0..10_000 {
      if !reference.state.lock().unwrap().receipts.is_empty() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(reference.state.lock().unwrap().receipts.len(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(fault_factory);
    assert_eq!(keys.take_calls(), vec![]);
    assert_eq!(stored_intents(&reference).len(), 1);
    assert_eq!(commit_calls(&reference), 1);

    *keys.inner.reconcile_unknowns.lock().unwrap() += 1;
    let error = open_with(factory.clone(), keys.clone(), entropy.clone())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);
    assert_eq!(error.context(), "key reconcile");
    assert_eq!(
      keys.take_calls(),
      vec![KeyCall::ReconcileCreate(operation(2))]
    );
    assert_eq!(stored_intents(&reference).len(), 1);
    assert!(stored_local(&reference).is_none());
    assert_eq!(commit_calls(&reference), 1);

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    let identity = context.identity().clone();
    let created = keys.inner.lookup_operation(&operation(2)).unwrap();
    assert_eq!(identity.node(), &node(1));
    assert_eq!(identity.operation(), &operation(2));
    assert_eq!(identity.handle(), created.handle());
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::ReconcileCreate(operation(2)),
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
      ]
    );
    assert_final_state(&reference, &identity);
    assert_eq!(commit_calls(&reference), 3);
    assert_never_signed_or_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_lifecycle_intent_commit_unknown_reconciles_exactly_once() {
    let (reference, _factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![
        CommitFault::UnknownApplied,
        CommitFault::Pass,
        CommitFault::Pass,
      ],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault;

    let context = open_with(fault_factory, keys.clone(), entropy.clone())
      .await
      .unwrap();
    let identity = context.identity().clone();
    assert_eq!(identity.node(), &node(1));
    assert_eq!(
      keys.take_calls(),
      vec![
        KeyCall::Create(operation(2)),
        KeyCall::PublicKey(
          keys
            .inner
            .lookup_operation(&operation(2))
            .unwrap()
            .handle()
            .expose_provider_handle()
            .to_vec()
        ),
      ]
    );
    assert_final_state(&reference, &identity);
    assert_eq!(
      receipt_ids(&reference),
      vec![transaction(3), transaction(4), transaction(5)]
    );

    let (reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());
    let fault = Arc::new(FaultingFactory::new(
      &reference,
      vec![CommitFault::UnknownNotApplied],
    ));
    let fault_factory: Arc<dyn StorageFactory> = fault.clone();

    let error = open_with(fault_factory, keys.clone(), entropy.clone())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(error.context(), "local identity intent commit");
    assert_eq!(keys.take_calls(), vec![]);
    assert!(stored_local(&reference).is_none());
    assert!(stored_intents(&reference).is_empty());
    assert!(receipt_ids(&reference).is_empty());
    assert_eq!(commit_calls(&reference), 0);
    assert!(fault.script.lock().unwrap().is_empty());

    let context = open_with(factory, keys.clone(), entropy).await.unwrap();
    let identity = context.identity().clone();
    assert_eq!(identity.node(), &node(4));
    assert_eq!(identity.operation(), &operation(5));
    assert_final_state(&reference, &identity);
    assert_never_signed_or_deleted(&keys);
  }

  async fn assert_discovery_corrupt(index: usize, setup: impl Fn(&Arc<ReferenceFactory>)) {
    let (reference, factory) = fresh_reference();
    setup(&reference);
    let keys = Arc::new(ScriptedKeys::full());
    let error = open_with(factory, keys.clone(), Arc::new(SequenceEntropy::default()))
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StorageCorrupt, "case {index}");
    assert_eq!(error.context(), "storage snapshot", "case {index}");
    assert_eq!(keys.take_calls(), vec![], "case {index}");
    assert_eq!(commit_calls(&reference), 0, "case {index}");
  }

  fn inject_entry(
    reference: &Arc<ReferenceFactory>, entry: (StoreNamespace, StoreKey), bytes: Vec<u8>,
  ) {
    reference
      .state
      .lock()
      .unwrap()
      .entries
      .insert(entry, StoreValue::new(Arc::from(bytes)));
  }

  fn valid_local_bytes() -> Vec<u8> {
    let public_key = PublicKey::from_bytes(scripted_signing(7).verifying_key().to_bytes());
    let handle =
      KeyHandle::from_provider_bytes(Arc::from(b"scripted-handle-x".as_slice())).unwrap();
    LocalIdentityV1::new(node(1), public_key, operation(2), handle)
      .encode()
      .unwrap()
  }

  fn valid_intent_bytes(op: KeyOperationId, purpose: &str) -> Vec<u8> {
    KeyCreationIntentV1::new(
      op,
      node(1),
      purpose.to_owned(),
      transaction(3),
      StoreRevision::new(Arc::from([1])).unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap()
  }

  #[tokio::test]
  async fn identity_records_lifecycle_malformed_and_multiple_records_fail_closed() {
    assert_discovery_corrupt(0, |reference| {
      inject_entry(
        reference,
        local_identity_key().unwrap(),
        b"not a local identity".to_vec(),
      );
    })
    .await;

    assert_discovery_corrupt(1, |reference| {
      let (namespace, _) = local_identity_key().unwrap();
      inject_entry(
        reference,
        (
          namespace,
          StoreKey::new(Arc::from(b"self-extended".as_slice())),
        ),
        valid_local_bytes(),
      );
    })
    .await;

    assert_discovery_corrupt(2, |reference| {
      inject_entry(
        reference,
        key_creation_intent_key(&operation(2)).unwrap(),
        b"not a key creation intent".to_vec(),
      );
    })
    .await;

    assert_discovery_corrupt(3, |reference| {
      inject_entry(
        reference,
        key_creation_intent_key(&operation(2)).unwrap(),
        valid_intent_bytes(operation(2), LOCAL_IDENTITY_PURPOSE),
      );
      inject_entry(
        reference,
        key_creation_intent_key(&operation(5)).unwrap(),
        valid_intent_bytes(operation(5), LOCAL_IDENTITY_PURPOSE),
      );
    })
    .await;

    assert_discovery_corrupt(4, |reference| {
      inject_entry(
        reference,
        local_identity_key().unwrap(),
        valid_local_bytes(),
      );
      inject_entry(
        reference,
        key_creation_intent_key(&operation(2)).unwrap(),
        valid_intent_bytes(operation(2), LOCAL_IDENTITY_PURPOSE),
      );
    })
    .await;

    assert_discovery_corrupt(5, |reference| {
      inject_entry(
        reference,
        key_creation_intent_key(&operation(5)).unwrap(),
        valid_intent_bytes(operation(2), LOCAL_IDENTITY_PURPOSE),
      );
    })
    .await;

    assert_discovery_corrupt(6, |reference| {
      inject_entry(
        reference,
        key_creation_intent_key(&operation(2)).unwrap(),
        valid_intent_bytes(operation(2), "other-purpose"),
      );
    })
    .await;
  }

  #[tokio::test]
  async fn identity_records_lifecycle_errors_are_typed_and_redacted() {
    let (_reference, factory) = fresh_reference();
    let keys = Arc::new(ScriptedKeys::full());
    let entropy = Arc::new(SequenceEntropy::default());

    let first = open_with(factory.clone(), keys, entropy.clone())
      .await
      .unwrap();
    let identity = first.identity().clone();
    drop(first);

    let mismatched = ScriptedKeys::full();
    *mismatched.inner.public_key_override.lock().unwrap() = Some(PublicKey::from_bytes(
      scripted_signing(9_999).verifying_key().to_bytes(),
    ));
    let mismatched = Arc::new(mismatched);
    let error = open_with(factory, mismatched, entropy).await.unwrap_err();
    let rendered = format!("{error:?}");
    assert_eq!(
      rendered,
      "Error { kind: Internal, context: \"key public key\" }"
    );
    assert!(!rendered.contains(&hex(identity.public_key().as_bytes())));
    assert!(!rendered.contains(&hex(identity.handle().expose_provider_handle())));
    assert!(!rendered.contains("scripted-handle"));
    assert!(!rendered.contains(identity.node().as_str()));

    let (reference, factory) = fresh_reference();
    let (local_namespace, local_key) = local_identity_key().unwrap();
    reference.state.lock().unwrap().entries.insert(
      (local_namespace, local_key),
      StoreValue::new(Arc::from(b"opaque-corrupt-value".as_slice())),
    );
    let keys = Arc::new(ScriptedKeys::full());
    let error = open_with(factory, keys, Arc::new(SequenceEntropy::default()))
      .await
      .unwrap_err();
    let rendered = format!("{error:?}");
    assert_eq!(
      rendered,
      "Error { kind: StorageCorrupt, context: \"storage snapshot\" }"
    );
    assert!(!rendered.contains("opaque-corrupt-value"));
  }
}

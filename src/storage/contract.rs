use std::{
  collections::{BTreeMap, HashMap},
  sync::{Arc, Mutex},
};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, DurabilityLevel, Error, ProviderErrorContext,
  ProviderErrorKind, QualifiedTag, ReconcileOutcome, Result, StoreCapabilities, StoreEntry,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRequirements, StoreRevision,
  StoreTransaction, StoreValue, TransactionId,
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
};

#[derive(Debug)]
struct ReferenceState {
  generation: u64,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  receipts: HashMap<TransactionId, CommitReceipt>,
}

#[derive(Debug)]
struct ReferenceFactory {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<ReferenceState>>,
}

impl ReferenceFactory {
  fn new(capabilities: StoreCapabilities) -> Self {
    Self {
      capabilities,
      state: Arc::new(Mutex::new(ReferenceState {
        generation: 1,
        entries: BTreeMap::new(),
        receipts: HashMap::new(),
      })),
    }
  }
}

#[derive(Debug)]
struct ReferenceStorage {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<ReferenceState>>,
}

#[derive(Debug)]
struct ReferenceSnapshot {
  revision: StoreRevision,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
}

#[derive(Debug)]
struct ReferenceScan {
  entries: std::vec::IntoIter<StoreEntry>,
}

impl StorageFactory for ReferenceFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let capabilities = self.capabilities;
    let state = Arc::clone(&self.state);
    Box::pin(async move {
      if !capabilities.satisfies(&requirements) {
        return Err(Error::provider(
          ProviderErrorKind::UnsupportedCapability,
          ProviderErrorContext::StorageOpen,
        ));
      }
      Ok(Box::new(ReferenceStorage {
        capabilities,
        state,
      }) as Box<dyn Storage>)
    })
  }
}

impl Storage for ReferenceStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    let state = self.state.lock().unwrap();
    let snapshot = ReferenceSnapshot {
      revision: reference_revision(state.generation),
      entries: state.entries.clone(),
    };
    Box::pin(async move { Ok(Box::new(snapshot) as Box<dyn StoreSnapshot>) })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    let outcome = reference_commit(&self.state, transaction);
    Box::pin(async move { outcome })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let state = self.state.lock().unwrap();
    let outcome = match state.receipts.get(transaction) {
      Some(receipt) if receipt.operation_digest() == digest => {
        ReconcileOutcome::Committed(receipt.clone())
      }
      Some(_) => ReconcileOutcome::DigestConflict,
      None => ReconcileOutcome::Aborted,
    };
    Box::pin(async move { Ok(outcome) })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

impl StoreSnapshot for ReferenceSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    let value = self.entries.get(&(namespace.clone(), key.clone())).cloned();
    Box::pin(async move { Ok(value) })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    let entries = self
      .entries
      .iter()
      .filter(|((entry_namespace, key), _)| {
        entry_namespace == namespace && key.as_bytes().starts_with(prefix)
      })
      .map(|((entry_namespace, key), value)| {
        StoreEntry::new(entry_namespace.clone(), key.clone(), value.clone())
      })
      .collect::<Vec<_>>()
      .into_iter();
    Box::pin(async move { Ok(Box::new(ReferenceScan { entries }) as Box<dyn StoreScan + 'a>) })
  }
}

impl StoreScan for ReferenceScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    let next = self.entries.next();
    Box::pin(async move { Ok(next) })
  }
}

fn reference_commit(
  state: &Mutex<ReferenceState>, transaction: StoreTransaction,
) -> Result<CommitOutcome> {
  let mut state = state.lock().unwrap();
  if let Some(receipt) = state.receipts.get(transaction.id()) {
    return if receipt.operation_digest() == transaction.operation_digest() {
      Ok(CommitOutcome::Committed(receipt.clone()))
    } else {
      Ok(CommitOutcome::Conflict)
    };
  }
  if transaction.operation_digest() != &transaction.computed_operation_digest() {
    return Ok(CommitOutcome::Conflict);
  }
  if transaction.base_revision() != &reference_revision(state.generation) {
    return Ok(CommitOutcome::Conflict);
  }
  if !transaction
    .operations()
    .iter()
    .all(|operation| condition_matches(&state, operation))
  {
    return Ok(CommitOutcome::Aborted);
  }

  let mut entries = state.entries.clone();
  for operation in transaction.operations() {
    match operation {
      StoreOperation::Check { .. } => {}
      StoreOperation::Put {
        namespace,
        key,
        value,
        ..
      } => {
        entries.insert((namespace.clone(), key.clone()), value.clone());
      }
      StoreOperation::Delete { namespace, key, .. } => {
        entries.remove(&(namespace.clone(), key.clone()));
      }
      StoreOperation::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => {
        if state
          .receipts
          .get(transaction)
          .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest)
        {
          state.receipts.remove(transaction);
        }
      }
    }
  }
  state.generation += 1;
  state.entries = entries;
  let receipt = CommitReceipt::new(
    transaction.id().clone(),
    transaction.operation_digest().clone(),
    reference_revision(state.generation),
  );
  state
    .receipts
    .insert(transaction.id().clone(), receipt.clone());
  Ok(CommitOutcome::Committed(receipt))
}

fn condition_matches(state: &ReferenceState, operation: &StoreOperation) -> bool {
  match operation {
    StoreOperation::Check {
      namespace,
      key,
      expected,
    }
    | StoreOperation::Put {
      namespace,
      key,
      expected,
      ..
    } => expectation_matches(
      state.entries.get(&(namespace.clone(), key.clone())),
      expected,
    ),
    StoreOperation::Delete {
      namespace,
      key,
      expected,
    } => state
      .entries
      .get(&(namespace.clone(), key.clone()))
      .is_some_and(|value| value.digest() == expected),
    StoreOperation::ForgetReceipt {
      transaction,
      expected_operation_digest,
    } => state
      .receipts
      .get(transaction)
      .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest),
  }
}

fn expectation_matches(value: Option<&StoreValue>, expected: &StoreExpectation) -> bool {
  match (value, expected) {
    (None, StoreExpectation::Absent) => true,
    (Some(value), StoreExpectation::Exact(digest)) => value.digest() == digest,
    _ => false,
  }
}

async fn run_storage_contract<F>(fresh: F)
where
  F: Fn() -> Arc<dyn StorageFactory>, {
  storage_contract_snapshot_lookup_and_ordering(fresh()).await;
  storage_contract_conflicts_atomicity_and_idempotence(fresh()).await;
}

async fn storage_contract_snapshot_lookup_and_ordering(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let old = storage.snapshot().await.unwrap();
  assert!(!old.revision().as_bytes().is_empty());
  let old_revision = old.revision().clone();
  let target_namespace = namespace("one");
  let other_namespace = namespace("two");
  let keys = [
    vec![],
    vec![0x00],
    vec![0x7F],
    vec![0x80],
    vec![0xFF],
    vec![0xFF, 0x00],
    vec![0xFF, 0xFF],
  ];
  let operations = keys
    .iter()
    .enumerate()
    .map(|(index, key)| StoreOperation::Put {
      namespace: target_namespace.clone(),
      key: store_key(key),
      expected: StoreExpectation::Absent,
      value: value(&[index as u8]),
    })
    .chain([StoreOperation::Put {
      namespace: other_namespace.clone(),
      key: store_key(&[0x00]),
      expected: StoreExpectation::Absent,
      value: value(b"other"),
    }])
    .collect();
  let transaction = transaction(0, old_revision.clone(), operations).unwrap();
  assert!(matches!(
    storage.commit(transaction).await.unwrap(),
    CommitOutcome::Committed(_)
  ));

  assert_eq!(old.revision(), &old_revision);
  assert!(
    old
      .get(&target_namespace, &store_key(&[]))
      .await
      .unwrap()
      .is_none()
  );
  let current = storage.snapshot().await.unwrap();
  assert!(!current.revision().as_bytes().is_empty());
  assert_ne!(current.revision(), &old_revision);
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[3],
  );
  assert!(
    current
      .get(&other_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .is_none()
  );

  let all = collect_scan(current.scan(&target_namespace, &[]).await.unwrap()).await;
  assert_eq!(
    all
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    keys,
  );
  assert!(
    all
      .iter()
      .all(|entry| entry.namespace() == &target_namespace)
  );
  let ff = collect_scan(current.scan(&target_namespace, &[0xFF]).await.unwrap()).await;
  assert_eq!(
    ff.iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    vec![vec![0xFF], vec![0xFF, 0x00], vec![0xFF, 0xFF]],
  );
  let mut empty = current
    .scan(&target_namespace, &[0x01, 0x02])
    .await
    .unwrap();
  assert!(empty.next().await.unwrap().is_none());
  assert!(empty.next().await.unwrap().is_none());
}

async fn storage_contract_conflicts_atomicity_and_idempotence(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let initial = storage.snapshot().await.unwrap();
  let first_namespace = namespace("first");
  let second_namespace = namespace("second");
  let first_key = store_key(b"key");
  let second_key = store_key(b"key");
  let original = transaction(
    10,
    initial.revision().clone(),
    vec![StoreOperation::Put {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"first"),
    }],
  )
  .unwrap();
  let original_receipt = match storage.commit(original.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };

  let stale = transaction(
    11,
    initial.revision().clone(),
    vec![StoreOperation::Put {
      namespace: second_namespace.clone(),
      key: second_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"stale"),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(stale).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let current = storage.snapshot().await.unwrap();
  let failed_condition = transaction(
    12,
    current.revision().clone(),
    vec![StoreOperation::Put {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"wrong"),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(failed_condition).await.unwrap(),
    CommitOutcome::Aborted
  ));

  let atomic_failure = transaction(
    13,
    current.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: first_namespace.clone(),
        key: store_key(b"new"),
        expected: StoreExpectation::Absent,
        value: value(b"new"),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: second_key.clone(),
        expected: StoreExpectation::Exact(Digest::from_bytes([0; 32])),
        value: value(b"second"),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(atomic_failure).await.unwrap(),
    CommitOutcome::Aborted
  ));
  let unchanged = storage.snapshot().await.unwrap();
  assert!(
    unchanged
      .get(&first_namespace, &store_key(b"new"))
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    unchanged
      .get(&second_namespace, &second_key)
      .await
      .unwrap()
      .is_none()
  );
  for failed_id in [transaction_id(11), transaction_id(12), transaction_id(13)] {
    assert!(matches!(
      storage
        .reconcile(&failed_id, &Digest::from_bytes([0; 32]))
        .await
        .unwrap(),
      ReconcileOutcome::Aborted
    ));
  }

  let repeated = match storage.commit(original.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert_eq!(repeated, original_receipt);
  let changed_digest = transaction(
    10,
    unchanged.revision().clone(),
    vec![StoreOperation::Check {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Exact(value(b"first").digest().clone()),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(changed_digest).await.unwrap(),
    CommitOutcome::Conflict
  ));

  let exact_digest = value(b"first").digest().clone();
  let successful_batch = transaction(
    14,
    unchanged.revision().clone(),
    vec![
      StoreOperation::Check {
        namespace: first_namespace.clone(),
        key: first_key.clone(),
        expected: StoreExpectation::Exact(exact_digest),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: second_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"second"),
      },
    ],
  )
  .unwrap();
  let receipt = match storage.commit(successful_batch).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == receipt
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), &Digest::from_bytes([9; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    storage
      .reconcile(&transaction_id(99), &Digest::from_bytes([0; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));

  let duplicate = vec![
    StoreOperation::Check {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
    },
    StoreOperation::Delete {
      namespace: first_namespace,
      key: first_key,
      expected: Digest::from_bytes([0; 32]),
    },
  ];
  assert!(transaction(15, receipt.committed_revision().clone(), duplicate).is_err());
  assert!(transaction(16, receipt.committed_revision().clone(), vec![]).is_err());

  let duplicate_receipt = vec![
    StoreOperation::ForgetReceipt {
      transaction: transaction_id(20),
      expected_operation_digest: Digest::from_bytes([1; 32]),
    },
    StoreOperation::ForgetReceipt {
      transaction: transaction_id(20),
      expected_operation_digest: Digest::from_bytes([2; 32]),
    },
  ];
  assert!(transaction(17, receipt.committed_revision().clone(), duplicate_receipt).is_err());
}

#[tokio::test]
async fn storage_contract_reference_provider_covers_raw_storage_semantics() {
  run_storage_contract(|| Arc::new(ReferenceFactory::new(required_capabilities()))).await;
}

#[test]
fn storage_contract_capability_refusal_checks_each_phase_a_requirement() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let capabilities = [
    StoreCapabilities::new(DurabilityLevel::ProcessCrashAtomic)
      .conditional_batch(true)
      .ordered_scan(true)
      .reconciliation(true)
      .exclusive_lifetime_lock(true),
    required_capabilities().conditional_batch(false),
    required_capabilities().ordered_scan(false),
    required_capabilities().reconciliation(false),
    required_capabilities().exclusive_lifetime_lock(false),
  ];
  for capability in capabilities {
    let factory = ReferenceFactory::new(capability);
    let error = runtime
      .block_on(factory.open(StoreRequirements::metadata()))
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedCapability);
  }
  assert!(!StoreRequirements::metadata().requires_transactional_migration());
  assert!(
    runtime
      .block_on(ReferenceFactory::new(required_capabilities()).open(StoreRequirements::metadata()))
      .is_ok()
  );
}

async fn collect_scan(mut scan: Box<dyn StoreScan + '_>) -> Vec<StoreEntry> {
  let mut entries = Vec::new();
  while let Some(entry) = scan.next().await.unwrap() {
    entries.push(entry);
  }
  assert!(scan.next().await.unwrap().is_none());
  entries
}

fn required_capabilities() -> StoreCapabilities {
  StoreCapabilities::new(DurabilityLevel::OsCrashDurable)
    .conditional_batch(true)
    .ordered_scan(true)
    .reconciliation(true)
    .exclusive_lifetime_lock(true)
}

fn namespace(suffix: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(&format!("relay.woooo.tech/metadata/{suffix}")).unwrap())
    .unwrap()
}

fn store_key(value: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(value))
}

fn value(bytes: &[u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

fn transaction(
  index: u8, base_revision: StoreRevision, operations: Vec<StoreOperation>,
) -> Result<StoreTransaction> {
  StoreTransaction::new(transaction_id(index), base_revision, operations)
}

fn transaction_id(index: u8) -> TransactionId {
  TransactionId::parse(&format!("txn_{index:021}")).unwrap()
}

fn reference_revision(generation: u64) -> StoreRevision {
  StoreRevision::new(Arc::from(generation.to_be_bytes())).unwrap()
}

use std::{
  collections::{BTreeMap, HashMap},
  future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, DurabilityLevel, Error, ProviderErrorContext,
  ProviderErrorKind, QualifiedTag, ReconcileOutcome, Result, StoreCapabilities, StoreEntry,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRequirements, StoreRevision,
  StoreTransaction, StoreValue, TransactionId,
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
  storage::{
    MetadataStore,
    receipt::{
      PreparedTransaction, ReceiptCleanupOutcome, ReceiptIdentity, ReceiptReferenceOutcome,
      ReceiptReferenceToken, WallClock, decode_wall_time, eligibility_anchor_key, encode_wall_time,
      internal_namespace, reference_head_key, used_id_key,
    },
  },
};

#[derive(Debug)]
struct ReferenceState {
  generation: u64,
  open: bool,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  receipts: HashMap<TransactionId, CommitReceipt>,
}

#[derive(Debug)]
struct ReferenceFactory {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<ReferenceState>>,
  commit_calls: Arc<AtomicUsize>,
}

impl ReferenceFactory {
  fn new(capabilities: StoreCapabilities) -> Self {
    Self {
      capabilities,
      state: Arc::new(Mutex::new(ReferenceState {
        generation: 1,
        open: false,
        entries: BTreeMap::new(),
        receipts: HashMap::new(),
      })),
      commit_calls: Arc::new(AtomicUsize::new(0)),
    }
  }
}

#[derive(Debug)]
struct ReferenceStorage {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<ReferenceState>>,
  commit_calls: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug)]
enum UnknownFaultMode {
  Applied,
  NotApplied,
  Pending,
}

#[derive(Debug)]
struct UnknownFaultFactory {
  reference: Arc<ReferenceFactory>,
  mode: UnknownFaultMode,
  commit_calls: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct UnknownFaultStorage {
  reference: Box<dyn Storage>,
  mode: UnknownFaultMode,
  commit_calls: Arc<AtomicUsize>,
  pending: Mutex<Option<(TransactionId, Digest)>>,
}

#[derive(Debug)]
struct ReferenceSnapshot {
  revision: StoreRevision,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
}

#[derive(Debug)]
struct ReferenceScan<'a> {
  entries: std::collections::btree_map::Iter<'a, (StoreNamespace, StoreKey), StoreValue>,
  namespace: &'a StoreNamespace,
  prefix: &'a [u8],
}

impl StorageFactory for ReferenceFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let capabilities = self.capabilities;
    let state = Arc::clone(&self.state);
    let commit_calls = Arc::clone(&self.commit_calls);
    Box::pin(async move {
      if !capabilities.satisfies(&requirements) {
        return Err(Error::provider(
          ProviderErrorKind::UnsupportedCapability,
          ProviderErrorContext::StorageOpen,
        ));
      }
      {
        let mut state = state.lock().unwrap();
        if state.open {
          return Err(Error::provider(
            ProviderErrorKind::StorageLocked,
            ProviderErrorContext::StorageOpen,
          ));
        }
        state.open = true;
      }
      Ok(Box::new(ReferenceStorage {
        capabilities,
        state,
        commit_calls,
      }) as Box<dyn Storage>)
    })
  }
}

impl Drop for ReferenceStorage {
  fn drop(&mut self) {
    self.state.lock().unwrap().open = false;
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
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
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

impl StorageFactory for UnknownFaultFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let mode = self.mode;
    let commit_calls = Arc::clone(&self.commit_calls);
    Box::pin(async move {
      let reference = self.reference.open(requirements).await?;
      Ok(Box::new(UnknownFaultStorage {
        reference,
        mode,
        commit_calls,
        pending: Mutex::new(None),
      }) as Box<dyn Storage>)
    })
  }
}

impl Storage for UnknownFaultStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.reference.capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    self.reference.snapshot()
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
    let identity = (
      transaction.id().clone(),
      transaction.operation_digest().clone(),
    );
    *self.pending.lock().unwrap() = Some(identity.clone());
    Box::pin(async move {
      match self.mode {
        UnknownFaultMode::Applied => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
        }
        UnknownFaultMode::NotApplied => {}
        UnknownFaultMode::Pending => return future::pending().await,
      }
      Ok(CommitOutcome::Unknown {
        transaction: identity.0,
        operation_digest: identity.1,
      })
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let pending = self.pending.lock().unwrap().clone();
    Box::pin(async move {
      if pending
        .as_ref()
        .is_some_and(|(pending_transaction, pending_digest)| {
          pending_transaction != transaction || pending_digest != digest
        })
      {
        return Ok(ReconcileOutcome::DigestConflict);
      }
      self.reference.reconcile(transaction, digest).await
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.reference.flush()
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
    let scan = ReferenceScan {
      entries: self.entries.iter(),
      namespace,
      prefix,
    };
    Box::pin(async move { Ok(Box::new(scan) as Box<dyn StoreScan + 'a>) })
  }
}

impl StoreScan for ReferenceScan<'_> {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    let next = self.entries.find_map(|((namespace, key), value)| {
      (namespace == self.namespace && key.as_bytes().starts_with(self.prefix))
        .then(|| StoreEntry::new(namespace.clone(), key.clone(), value.clone()))
    });
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
    return Ok(CommitOutcome::Conflict);
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
  let initial_transaction = transaction(0, old_revision.clone(), operations).unwrap();
  assert!(matches!(
    storage.commit(initial_transaction).await.unwrap(),
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
  drop(empty);

  let overwrite_and_delete = transaction(
    1,
    current.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: target_namespace.clone(),
        key: store_key(&[0x80]),
        expected: StoreExpectation::Exact(value(&[3]).digest().clone()),
        value: value(b"overwritten"),
      },
      StoreOperation::Delete {
        namespace: target_namespace.clone(),
        key: store_key(&[0x7F]),
        expected: value(&[2]).digest().clone(),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(overwrite_and_delete).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[3],
  );
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x7F]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[2],
  );
  let retained = collect_scan(current.scan(&target_namespace, &[]).await.unwrap()).await;
  assert_eq!(
    retained
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    keys,
  );
  let latest = storage.snapshot().await.unwrap();
  assert_eq!(
    latest
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"overwritten",
  );
  assert!(
    latest
      .get(&target_namespace, &store_key(&[0x7F]))
      .await
      .unwrap()
      .is_none()
  );
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
    CommitOutcome::Conflict
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
    CommitOutcome::Conflict
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

  let delete_failure = transaction(
    18,
    unchanged.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: store_key(b"delete-rollback"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      },
      StoreOperation::Delete {
        namespace: first_namespace.clone(),
        key: first_key.clone(),
        expected: Digest::from_bytes([8; 32]),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(delete_failure).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let after_delete_failure = storage.snapshot().await.unwrap();
  assert!(
    after_delete_failure
      .get(&second_namespace, &store_key(b"delete-rollback"))
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(
    after_delete_failure
      .get(&first_namespace, &first_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"first",
  );
  for failed_id in [
    transaction_id(11),
    transaction_id(12),
    transaction_id(13),
    transaction_id(18),
  ] {
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
    initial.revision().clone(),
    vec![StoreOperation::Check {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
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

  let forget_mismatch = transaction(
    19,
    receipt.committed_revision().clone(),
    vec![
      StoreOperation::ForgetReceipt {
        transaction: original_receipt.transaction().clone(),
        expected_operation_digest: Digest::from_bytes([7; 32]),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: store_key(b"receipt-rollback"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(forget_mismatch).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let after_forget_mismatch = storage.snapshot().await.unwrap();
  assert!(
    after_forget_mismatch
      .get(&second_namespace, &store_key(b"receipt-rollback"))
      .await
      .unwrap()
      .is_none()
  );
  assert!(matches!(
    storage
      .reconcile(
        original_receipt.transaction(),
        original_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == original_receipt
  ));

  let forget = transaction(
    20,
    after_forget_mismatch.revision().clone(),
    vec![StoreOperation::ForgetReceipt {
      transaction: original_receipt.transaction().clone(),
      expected_operation_digest: original_receipt.operation_digest().clone(),
    }],
  )
  .unwrap();
  let forget_receipt = match storage.commit(forget).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert!(matches!(
    storage
      .reconcile(
        original_receipt.transaction(),
        original_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    storage
      .reconcile(
        forget_receipt.transaction(),
        forget_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == forget_receipt
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

#[derive(Debug)]
struct ManualClock {
  value: Mutex<SystemTime>,
}

impl ManualClock {
  fn new(value: SystemTime) -> Self {
    Self {
      value: Mutex::new(value),
    }
  }

  fn set(&self, value: SystemTime) {
    *self.value.lock().unwrap() = value;
  }
}

impl WallClock for ManualClock {
  fn now(&self) -> SystemTime {
    *self.value.lock().unwrap()
  }
}

#[tokio::test]
async fn storage_contract_prepared_transactions_are_atomic_idempotent_and_permanently_used() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction(
      contract_transaction_id(1),
      snapshot.revision().clone(),
      vec![
        StoreOperation::Put {
          namespace: namespace("prepared-one"),
          key: store_key(b"one"),
          expected: StoreExpectation::Absent,
          value: value(b"one"),
        },
        StoreOperation::Put {
          namespace: namespace("prepared-two"),
          key: store_key(b"two"),
          expected: StoreExpectation::Absent,
          value: value(b"two"),
        },
      ],
    )
    .unwrap();
  let marker_key = used_id_key(prepared.id()).unwrap();
  assert_eq!(prepared.operations().len(), 3);
  assert!(prepared.operations().iter().any(|operation| {
    matches!(
      operation,
      StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value,
      } if namespace.as_str() == internal_namespace().unwrap().as_str()
        && key == &marker_key
        && value.as_bytes().is_empty()
    )
  }));

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    committed(store.commit(prepared.clone()).await.unwrap()),
    receipt
  );
  assert_eq!(
    store
      .snapshot()
      .await
      .unwrap()
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[],
  );

  let target = ReceiptIdentity::from_receipt(&receipt);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(2))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(3))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(50));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(4))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(100));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(5))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(110));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(6))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
  drop(store);

  let raw = factory.open(StoreRequirements::metadata()).await.unwrap();
  assert!(matches!(
    raw
      .reconcile(target.transaction(), target.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    raw.commit(prepared.0.clone()).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert!(
    raw
      .snapshot()
      .await
      .unwrap()
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .is_some()
  );
}

#[tokio::test]
async fn storage_contract_opaque_reference_categories_block_cleanup_until_final_removal() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(200)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 20).await;
  let owner = ReceiptReferenceToken::from_digest(Digest::from_bytes([1; 32]));
  let pending = ReceiptReferenceToken::from_digest(Digest::from_bytes([2; 32]));
  let provider_intent = ReceiptReferenceToken::from_digest(Digest::from_bytes([3; 32]));
  let migration = ReceiptReferenceToken::from_digest(Digest::from_bytes([4; 32]));
  let unknown = ReceiptReferenceToken::from_digest(Digest::from_bytes([5; 32]));
  let tokens = [owner, pending, provider_intent, migration, unknown];

  for (offset, token) in tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &target,
          token,
          contract_transaction_id(21 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let commits_before_cleanup = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(30))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Referenced
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_cleanup
  );

  for (offset, token) in tokens[..4].iter().enumerate() {
    assert!(matches!(
      store
        .remove_receipt_reference(
          &target,
          token,
          contract_transaction_id(31 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
    let before = factory.commit_calls.load(Ordering::SeqCst);
    assert!(matches!(
      store
        .cleanup_receipt(
          &target,
          contract_transaction_id(40 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Referenced
    ));
    assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  }
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &tokens[4], contract_transaction_id(50))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(
        &internal_namespace().unwrap(),
        &reference_head_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    snapshot
      .get(
        &internal_namespace().unwrap(),
        &eligibility_anchor_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  drop(snapshot);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(51))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(210));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(52))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
}

#[tokio::test]
async fn storage_contract_reference_addition_and_final_disappearance_reset_retention() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(300)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 60).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([9; 32]));

  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(61))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(305));
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(62))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  assert!(
    store
      .snapshot()
      .await
      .unwrap()
      .get(
        &internal_namespace().unwrap(),
        &eligibility_anchor_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  clock.set(UNIX_EPOCH + Duration::from_secs(310));
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &token, contract_transaction_id(63))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(320));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(64))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  let anchor = store
    .snapshot()
    .await
    .unwrap()
    .get(
      &internal_namespace().unwrap(),
      &eligibility_anchor_key(target.transaction()).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    decode_wall_time(anchor.as_bytes()).unwrap(),
    UNIX_EPOCH + Duration::from_secs(320)
  );
  clock.set(UNIX_EPOCH + Duration::from_secs(329));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(65))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(330));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(66))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
}

#[tokio::test]
async fn storage_contract_reserved_injection_duplicates_corruption_and_overflow_fail_closed() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(400)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 70).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([10; 32]));
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    store
      .prepare_transaction(
        contract_transaction_id(71),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace: internal_namespace().unwrap(),
          key: store_key(b"injected"),
          expected: StoreExpectation::Absent,
          value: value(b"injected"),
        }],
      )
      .unwrap_err()
      .kind(),
    crate::ErrorKind::InvalidInput
  );
  assert_eq!(
    store
      .prepare_transaction(
        contract_transaction_id(711),
        snapshot.revision().clone(),
        vec![StoreOperation::ForgetReceipt {
          transaction: target.transaction().clone(),
          expected_operation_digest: target.operation_digest().clone(),
        }],
      )
      .unwrap_err()
      .kind(),
    crate::ErrorKind::InvalidInput
  );
  drop(snapshot);
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(72))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let before_duplicate = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(73))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
  let missing = ReceiptReferenceToken::from_digest(Digest::from_bytes([11; 32]));
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &missing, contract_transaction_id(74))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );

  let head_key = reference_head_key(target.transaction()).unwrap();
  {
    let mut state = factory.state.lock().unwrap();
    state
      .entries
      .remove(&(internal_namespace().unwrap(), head_key.clone()));
  }
  assert_eq!(
    store
      .remove_receipt_reference(&target, &token, contract_transaction_id(75))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (internal_namespace().unwrap(), head_key),
      StoreValue::new(Arc::from(u64::MAX.to_be_bytes())),
    );
  }
  let overflow_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([12; 32]));
  assert_eq!(
    store
      .add_receipt_reference(&target, &overflow_token, contract_transaction_id(76))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
}

#[tokio::test]
async fn storage_contract_malformed_reference_count_and_anchor_fail_without_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(450)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 85).await;
  let namespace = internal_namespace().unwrap();
  let head_key = reference_head_key(target.transaction()).unwrap();
  let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();

  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (namespace.clone(), head_key.clone()),
      StoreValue::new(Arc::from([1_u8, 2, 3].as_slice())),
    );
  }
  let before = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .cleanup_receipt(&target, contract_transaction_id(86))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );

  {
    let mut state = factory.state.lock().unwrap();
    state.entries.remove(&(namespace.clone(), head_key));
    let mut malformed_time = [0_u8; 13];
    malformed_time[9..13].copy_from_slice(&1_000_000_000_u32.to_be_bytes());
    state.entries.insert(
      (namespace, anchor_key),
      StoreValue::new(Arc::from(malformed_time)),
    );
  }
  assert_eq!(
    store
      .cleanup_receipt(&target, contract_transaction_id(87))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );
}

#[test]
fn storage_contract_wall_time_encoding_is_canonical_pre_epoch_and_rejects_malformed_values() {
  let before_epoch = UNIX_EPOCH - Duration::new(7, 123_456_789);
  let encoded = encode_wall_time(before_epoch);
  assert_eq!(encoded.len(), 13);
  assert_eq!(decode_wall_time(&encoded).unwrap(), before_epoch);
  assert_eq!(
    encode_wall_time(decode_wall_time(&encoded).unwrap()),
    encoded
  );

  let mut invalid_nanos = encoded;
  invalid_nanos[9..13].copy_from_slice(&1_000_000_000_u32.to_be_bytes());
  assert_eq!(
    decode_wall_time(&invalid_nanos).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  let mut invalid_sign = encoded;
  invalid_sign[0] = 2;
  assert_eq!(
    decode_wall_time(&invalid_sign).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    decode_wall_time(&encoded[..12]).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
}

#[tokio::test]
async fn storage_contract_deadline_overflow_retains_without_provider_commit() {
  let Some(anchor_time) = UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64)) else {
    return;
  };
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(anchor_time));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 80).await;
  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (
        internal_namespace().unwrap(),
        eligibility_anchor_key(target.transaction()).unwrap(),
      ),
      StoreValue::new(Arc::from(encode_wall_time(anchor_time))),
    );
  }
  let before = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(81))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
}

#[derive(Clone, Copy, Debug)]
enum FaultedReceiptOperation {
  Add,
  Remove,
  Anchor,
  Forget,
}

#[tokio::test]
async fn storage_contract_unknown_receipt_mutations_freeze_and_reconcile_exact_operation() {
  for mode in [UnknownFaultMode::Applied, UnknownFaultMode::NotApplied] {
    for phase in [
      FaultedReceiptOperation::Add,
      FaultedReceiptOperation::Remove,
      FaultedReceiptOperation::Anchor,
      FaultedReceiptOperation::Forget,
    ] {
      exercise_unknown_receipt_operation(mode, phase).await;
    }
  }
}

async fn exercise_unknown_receipt_operation(
  mode: UnknownFaultMode, phase: FaultedReceiptOperation,
) {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(500)));
  let seed = open_engine(&reference, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&seed, 90).await;
  let (_, unrelated) = commit_target(&seed, 91).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([13; 32]));
  if matches!(phase, FaultedReceiptOperation::Remove) {
    assert!(matches!(
      seed
        .add_receipt_reference(&target, &token, contract_transaction_id(92))
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  if matches!(phase, FaultedReceiptOperation::Forget) {
    assert!(matches!(
      seed
        .cleanup_receipt(&target, contract_transaction_id(93))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
    clock.set(UNIX_EPOCH + Duration::from_secs(510));
  }
  drop(seed);

  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode,
    commit_calls: Arc::clone(&fault_calls),
  });
  let wall_clock: Arc<dyn WallClock> = clock;
  let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), wall_clock)
    .await
    .unwrap();
  let unknown = match phase {
    FaultedReceiptOperation::Add => match store
      .add_receipt_reference(&target, &token, contract_transaction_id(94))
      .await
      .unwrap()
    {
      ReceiptReferenceOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected add outcome: {outcome:?}"),
    },
    FaultedReceiptOperation::Remove => match store
      .remove_receipt_reference(&target, &token, contract_transaction_id(95))
      .await
      .unwrap()
    {
      ReceiptReferenceOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected remove outcome: {outcome:?}"),
    },
    FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => match store
      .cleanup_receipt(&target, contract_transaction_id(96))
      .await
      .unwrap()
    {
      ReceiptCleanupOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected cleanup outcome: {outcome:?}"),
    },
  };
  assert_eq!(
    unknown.transaction(),
    &contract_transaction_id(match phase {
      FaultedReceiptOperation::Add => 94,
      FaultedReceiptOperation::Remove => 95,
      FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => 96,
    })
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
  assert_eq!(
    store
      .cleanup_receipt(&unrelated, contract_transaction_id(97))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::NotReady
  );
  let reconciled = store.reconcile().await.unwrap();
  match mode {
    UnknownFaultMode::Applied => assert!(matches!(reconciled, ReconcileOutcome::Committed(_))),
    UnknownFaultMode::NotApplied => assert!(matches!(reconciled, ReconcileOutcome::Aborted)),
    UnknownFaultMode::Pending => unreachable!("pending mode is tested through cancellation"),
  }
  assert_eq!(
    reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction()),
    !matches!(
      (mode, phase),
      (UnknownFaultMode::Applied, FaultedReceiptOperation::Forget)
    )
  );
}

#[tokio::test]
async fn storage_contract_cancelled_receipt_mutations_stay_frozen_until_exact_reconciliation() {
  for phase in [
    FaultedReceiptOperation::Add,
    FaultedReceiptOperation::Remove,
    FaultedReceiptOperation::Anchor,
    FaultedReceiptOperation::Forget,
  ] {
    exercise_cancelled_receipt_operation(phase).await;
  }
}

async fn exercise_cancelled_receipt_operation(phase: FaultedReceiptOperation) {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(600)));
  let seed = open_engine(&reference, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&seed, 100).await;
  let (_, unrelated) = commit_target(&seed, 101).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([14; 32]));
  if matches!(phase, FaultedReceiptOperation::Remove) {
    assert!(matches!(
      seed
        .add_receipt_reference(&target, &token, contract_transaction_id(102))
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  if matches!(phase, FaultedReceiptOperation::Forget) {
    assert!(matches!(
      seed
        .cleanup_receipt(&target, contract_transaction_id(103))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
    clock.set(UNIX_EPOCH + Duration::from_secs(610));
  }
  drop(seed);

  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::Pending,
    commit_calls: Arc::clone(&fault_calls),
  });
  let wall_clock: Arc<dyn WallClock> = clock;
  let store = Arc::new(
    MetadataStore::open_with_clock(&factory, Duration::from_secs(10), wall_clock)
      .await
      .unwrap(),
  );
  let task_store = Arc::clone(&store);
  let task_target = target.clone();
  let task_token = token.clone();
  let task = tokio::spawn(async move {
    match phase {
      FaultedReceiptOperation::Add => task_store
        .add_receipt_reference(&task_target, &task_token, contract_transaction_id(104))
        .await
        .map(|_| ()),
      FaultedReceiptOperation::Remove => task_store
        .remove_receipt_reference(&task_target, &task_token, contract_transaction_id(105))
        .await
        .map(|_| ()),
      FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => task_store
        .cleanup_receipt(&task_target, contract_transaction_id(106))
        .await
        .map(|_| ()),
    }
  });
  while fault_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  assert_eq!(
    store
      .cleanup_receipt(&unrelated, contract_transaction_id(107))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::NotReady
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(
    reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );
}

#[tokio::test]
async fn storage_contract_reference_provider_covers_raw_storage_semantics() {
  run_storage_contract(|| Arc::new(ReferenceFactory::new(required_capabilities()))).await;
}

#[tokio::test]
async fn storage_contract_reference_provider_holds_exclusive_lock_for_storage_lifetime() {
  let factory = ReferenceFactory::new(required_capabilities());
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();

  let unsupported = factory
    .open(StoreRequirements::metadata().transactional_migration(true))
    .await
    .unwrap_err();
  assert_eq!(unsupported.kind(), crate::ErrorKind::UnsupportedCapability);
  let locked = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(locked.kind(), crate::ErrorKind::StorageLocked);

  drop(storage);
  assert!(factory.open(StoreRequirements::metadata()).await.is_ok());
}

#[tokio::test]
async fn storage_contract_unknown_fault_adapter_proves_exact_raw_reconciliation() {
  for (mode, expected) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let commit_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::new(ReferenceFactory::new(required_capabilities())),
      mode,
      commit_calls: Arc::clone(&commit_calls),
    });
    storage_contract_unknown_reconciliation(factory, expected, &commit_calls).await;
  }
}

async fn storage_contract_unknown_reconciliation(
  factory: Arc<dyn StorageFactory>, applied: bool, commit_calls: &AtomicUsize,
) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let snapshot = storage.snapshot().await.unwrap();
  let submitted = transaction(
    30,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("unknown"),
      key: store_key(b"key"),
      expected: StoreExpectation::Absent,
      value: value(b"value"),
    }],
  )
  .unwrap();
  let transaction_id = submitted.id().clone();
  let operation_digest = submitted.operation_digest().clone();
  assert_eq!(
    storage.commit(submitted).await.unwrap(),
    CommitOutcome::Unknown {
      transaction: transaction_id.clone(),
      operation_digest: operation_digest.clone(),
    },
  );
  assert_eq!(commit_calls.load(Ordering::SeqCst), 1);
  assert!(matches!(
    storage
      .reconcile(&transaction_id, &Digest::from_bytes([4; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  let reconciled = storage
    .reconcile(&transaction_id, &operation_digest)
    .await
    .unwrap();
  if applied {
    assert_eq!(
      reconciled,
      ReconcileOutcome::Committed(CommitReceipt::new(
        transaction_id,
        operation_digest,
        reference_revision(2),
      )),
    );
  } else {
    assert!(matches!(reconciled, ReconcileOutcome::Aborted));
  }
  assert_eq!(commit_calls.load(Ordering::SeqCst), 1);
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

async fn open_engine(
  factory: &Arc<ReferenceFactory>, retention: Duration, clock: Arc<ManualClock>,
) -> MetadataStore {
  let storage_factory: Arc<dyn StorageFactory> = factory.clone();
  let wall_clock: Arc<dyn WallClock> = clock;
  MetadataStore::open_with_clock(&storage_factory, retention, wall_clock)
    .await
    .unwrap()
}

async fn commit_target(
  store: &MetadataStore, transaction: u16,
) -> (PreparedTransaction, ReceiptIdentity) {
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("receipt-target"),
        key: store_key(&transaction.to_be_bytes()),
        expected: StoreExpectation::Absent,
        value: value(b"target"),
      }],
    )
    .unwrap();
  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  let identity = ReceiptIdentity::from_receipt(&receipt);
  (prepared, identity)
}

fn committed(outcome: CommitOutcome) -> CommitReceipt {
  match outcome {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  }
}

fn contract_transaction_id(index: u16) -> TransactionId {
  TransactionId::parse(&format!("txn_{index:021}")).unwrap()
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

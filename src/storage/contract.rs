use std::{
  collections::BTreeMap,
  future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, DurabilityLevel, Error, NodeId,
  ProviderErrorContext, ProviderErrorKind, QualifiedTag, ReconcileOutcome, Result,
  StoreCapabilities, StoreEntry, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreRequirements, StoreRevision, StoreTransaction, StoreValue, TransactionId,
  identity::records::{identity_binding_key, local_identity_key},
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
  storage::{
    MetadataStore,
    pending::{PendingCleanupOutcome, PendingTransactionV1, pending_key, pending_namespace},
    receipt::{
      ACTIVE_MARKER_VALUE, FORGOTTEN_MARKER_VALUE, PreparedTransaction, ReceiptCleanupOutcome,
      ReceiptIdentity, ReceiptReferenceChange, ReceiptReferenceOutcome, ReceiptReferenceToken,
      WallClock, decode_wall_time, eligibility_anchor_key, encode_wall_time,
      increment_reference_count, internal_namespace, reference_edge_key, reference_head_key,
      used_id_key,
    },
  },
};

#[derive(Debug)]
pub(crate) struct ReferenceState {
  generation: u64,
  open: bool,
  pub(crate) entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  pub(crate) receipts: BTreeMap<TransactionId, CommitReceipt>,
}

#[derive(Debug)]
pub(crate) struct ReferenceFactory {
  capabilities: StoreCapabilities,
  pub(crate) state: Arc<Mutex<ReferenceState>>,
  pub(crate) commit_calls: Arc<AtomicUsize>,
}

impl ReferenceFactory {
  pub(crate) fn new(capabilities: StoreCapabilities) -> Self {
    Self {
      capabilities,
      state: Arc::new(Mutex::new(ReferenceState {
        generation: 1,
        open: false,
        entries: BTreeMap::new(),
        receipts: BTreeMap::new(),
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
  PendingApplied,
  PendingNotApplied,
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
        UnknownFaultMode::Applied | UnknownFaultMode::PendingApplied => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
        }
        UnknownFaultMode::NotApplied | UnknownFaultMode::PendingNotApplied => {}
      }
      if matches!(
        self.mode,
        UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied
      ) {
        return future::pending().await;
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
    .all(|operation| crate::provider::condition_matches(&state.entries, &state.receipts, operation))
  {
    return Ok(CommitOutcome::Conflict);
  }

  let next_generation = state.generation.checked_add(1).ok_or_else(|| {
    Error::provider(
      ProviderErrorKind::ResourceExhausted,
      ProviderErrorContext::StorageCommit,
    )
  })?;
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
  state.generation = next_generation;
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

pub(super) async fn run_storage_contract<F>(fresh: F)
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
        && value.as_bytes() == ACTIVE_MARKER_VALUE
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
    ACTIVE_MARKER_VALUE,
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
  let forgotten_snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    forgotten_snapshot
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    FORGOTTEN_MARKER_VALUE,
  );
  let reused = store
    .prepare_transaction(
      target.transaction().clone(),
      forgotten_snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("current-reuse"),
        key: store_key(b"otherwise-valid"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      }],
    )
    .unwrap();
  drop(forgotten_snapshot);
  let commits_before_reuse = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store.commit(reused).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_reuse + 1,
  );
  drop(store);

  let reopened = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let stale_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([99; 32]));
  let state_before_stale_attempts = {
    let state = factory.state.lock().unwrap();
    (
      state.generation,
      state.entries.clone(),
      state.receipts.clone(),
    )
  };
  let commits_before_stale_attempts = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    reopened
      .add_receipt_reference(&target, &stale_token, contract_transaction_id(7))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert!(matches!(
    reopened
      .remove_receipt_reference(&target, &stale_token, contract_transaction_id(8))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert!(matches!(
    reopened
      .cleanup_receipt(&target, contract_transaction_id(9))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_stale_attempts,
  );
  {
    let state = factory.state.lock().unwrap();
    assert_eq!(state.generation, state_before_stale_attempts.0);
    assert_eq!(state.entries, state_before_stale_attempts.1);
    assert_eq!(state.receipts, state_before_stale_attempts.2);
  }
  drop(reopened);

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
  assert_eq!(
    raw
      .snapshot()
      .await
      .unwrap()
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    FORGOTTEN_MARKER_VALUE,
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
      (internal_namespace().unwrap(), head_key.clone()),
      StoreValue::new(Arc::from([1_u8, 2, 3].as_slice())),
    );
  }
  assert_eq!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(751))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
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

#[test]
fn storage_contract_reference_count_overflow_is_resource_exhaustion() {
  assert_eq!(
    increment_reference_count(u64::MAX).unwrap_err().kind(),
    crate::ErrorKind::ResourceExhausted,
  );
  assert_eq!(increment_reference_count(u64::MAX - 1).unwrap(), u64::MAX);
}

#[tokio::test]
async fn storage_contract_streamed_edge_audit_rejects_orphans_and_count_mismatches() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(425)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let namespace = internal_namespace().unwrap();

  let (_, orphan_target) = commit_target(&store, 770).await;
  let orphan_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([21; 32]));
  let orphan_edge = reference_edge_key(orphan_target.transaction(), &orphan_token).unwrap();
  {
    factory.state.lock().unwrap().entries.insert(
      (namespace.clone(), orphan_edge),
      StoreValue::new(Arc::from([])),
    );
  }
  let orphan_state = factory.state.lock().unwrap().entries.clone();
  let before_orphan_cleanup = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .cleanup_receipt(&orphan_target, contract_transaction_id(771))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_orphan_cleanup,
  );
  assert_eq!(factory.state.lock().unwrap().entries, orphan_state);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(orphan_target.transaction()),
  );

  let (_, undercount_target) = commit_target(&store, 780).await;
  let undercount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([22; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([23; 32])),
  ];
  for (offset, token) in undercount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &undercount_target,
          token,
          contract_transaction_id(781 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let undercount_head = reference_head_key(undercount_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace.clone(), undercount_head),
    StoreValue::new(Arc::from(1_u64.to_be_bytes())),
  );
  let undercount_state = factory.state.lock().unwrap().entries.clone();
  let before_undercount = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .remove_receipt_reference(
        &undercount_target,
        &undercount_tokens[0],
        contract_transaction_id(783),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store
      .cleanup_receipt(&undercount_target, contract_transaction_id(784))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_undercount
  );
  assert_eq!(factory.state.lock().unwrap().entries, undercount_state);

  let (_, overcount_target) = commit_target(&store, 790).await;
  let overcount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([24; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([25; 32])),
  ];
  for (offset, token) in overcount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &overcount_target,
          token,
          contract_transaction_id(791 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let overcount_head = reference_head_key(overcount_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace.clone(), overcount_head),
    StoreValue::new(Arc::from(3_u64.to_be_bytes())),
  );
  let before_overcount = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .cleanup_receipt(&overcount_target, contract_transaction_id(793))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_overcount
  );

  let (_, malformed_marker_target) = commit_target(&store, 800).await;
  let malformed_marker_key = used_id_key(malformed_marker_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace, malformed_marker_key),
    StoreValue::new(Arc::from(b"\x01forgotten\0malformed".as_slice())),
  );
  let malformed_state = factory.state.lock().unwrap().entries.clone();
  let before_malformed = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .add_receipt_reference(
        &malformed_marker_target,
        &ReceiptReferenceToken::from_digest(Digest::from_bytes([26; 32])),
        contract_transaction_id(801),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_malformed
  );
  assert_eq!(factory.state.lock().unwrap().entries, malformed_state);
}

#[tokio::test]
async fn storage_contract_reference_provider_revision_exhaustion_is_atomic() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  factory.state.lock().unwrap().generation = u64::MAX - 1;

  let near_max = storage.snapshot().await.unwrap();
  let reaches_max = transaction(
    40,
    near_max.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("revision-overflow"),
      key: store_key(b"first"),
      expected: StoreExpectation::Absent,
      value: value(b"first"),
    }],
  )
  .unwrap();
  let receipt = committed(storage.commit(reaches_max).await.unwrap());
  assert_eq!(receipt.committed_revision(), &reference_revision(u64::MAX));

  let at_max = storage.snapshot().await.unwrap();
  let exhausted = transaction(
    41,
    at_max.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("revision-overflow"),
      key: store_key(b"second"),
      expected: StoreExpectation::Absent,
      value: value(b"second"),
    }],
  )
  .unwrap();
  let state_before = {
    let state = factory.state.lock().unwrap();
    (state.entries.clone(), state.receipts.clone())
  };
  assert_eq!(
    storage.commit(exhausted).await.unwrap_err().kind(),
    crate::ErrorKind::ResourceExhausted,
  );
  let state = factory.state.lock().unwrap();
  assert_eq!(state.generation, u64::MAX);
  assert_eq!(state.entries, state_before.0);
  assert_eq!(state.receipts, state_before.1);
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
      .remove_receipt_reference(
        &target,
        &ReceiptReferenceToken::from_digest(Digest::from_bytes([15; 32])),
        contract_transaction_id(861),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
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
  let wall_clock: Arc<dyn WallClock> = clock.clone();
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
  let recovered_transaction = unknown.transaction().clone();
  let recovered_digest = unknown.operation_digest().clone();
  drop(store);
  let wall_clock: Arc<dyn WallClock> = clock;
  let store = MetadataStore::open_recovered_with_clock(
    &factory,
    Duration::from_secs(10),
    recovered_transaction,
    recovered_digest,
    wall_clock,
  )
  .await
  .unwrap();
  assert_eq!(
    store
      .cleanup_receipt(&unrelated, contract_transaction_id(97))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::NotReady
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
  let reconciled = store.reconcile().await.unwrap();
  match mode {
    UnknownFaultMode::Applied => assert!(matches!(reconciled, ReconcileOutcome::Committed(_))),
    UnknownFaultMode::NotApplied => assert!(matches!(reconciled, ReconcileOutcome::Aborted)),
    UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied => {
      unreachable!("pending modes are tested through cancellation")
    }
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
async fn storage_contract_recovered_open_resolves_applied_and_not_applied_unknown() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let prepared = prepare_contract_put(&store, 110, 0).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    assert_eq!(
      store.commit(prepared).await.unwrap(),
      CommitOutcome::Unknown {
        transaction: transaction.clone(),
        operation_digest: digest.clone(),
      }
    );
    let original_receipt = reference
      .state
      .lock()
      .unwrap()
      .receipts
      .get(&transaction)
      .cloned();
    assert_eq!(original_receipt.is_some(), applied);
    drop(store);

    let store =
      MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, digest)
        .await
        .unwrap();
    let unrelated = prepare_contract_put(&store, 111, 1).await;
    assert_eq!(
      store.commit(unrelated.clone()).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);

    let reconciled = store.reconcile().await.unwrap();
    if let Some(receipt) = original_receipt {
      assert_eq!(reconciled, ReconcileOutcome::Committed(receipt));
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
    }
    assert!(matches!(
      store.commit(unrelated).await.unwrap(),
      CommitOutcome::Unknown { .. }
    ));
    assert_eq!(fault_calls.load(Ordering::SeqCst), 2);

    drop(store);
    assert!(
      MetadataStore::open(&factory, Duration::from_secs(10))
        .await
        .is_ok()
    );
  }
}

#[tokio::test]
async fn storage_contract_recovered_open_keeps_wrong_digest_frozen() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference,
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  let prepared = prepare_contract_put(&store, 112, 0).await;
  let transaction = prepared.id().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  let wrong_digest = Digest::from_bytes([23; 32]);
  let store =
    MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, wrong_digest)
      .await
      .unwrap();
  let unrelated = prepare_contract_put(&store, 113, 1).await;
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn storage_contract_recovered_open_reconciles_cancelled_provider_submission() {
  for (mode, applied) in [
    (UnknownFaultMode::PendingApplied, true),
    (UnknownFaultMode::PendingNotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let store = Arc::new(
      MetadataStore::open(&factory, Duration::from_secs(10))
        .await
        .unwrap(),
    );
    let prepared = prepare_contract_put(&store, 114, 0).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move { task_store.commit(prepared).await });
    while fault_calls.load(Ordering::SeqCst) == 0
      || (applied
        && !reference
          .state
          .lock()
          .unwrap()
          .receipts
          .contains_key(&transaction))
    {
      tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let original_receipt = reference
      .state
      .lock()
      .unwrap()
      .receipts
      .get(&transaction)
      .cloned();
    assert_eq!(original_receipt.is_some(), applied);
    drop(store);

    let store = Arc::new(
      MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, digest)
        .await
        .unwrap(),
    );
    let unrelated = prepare_contract_put(&store, 115, 1).await;
    assert_eq!(
      store.commit(unrelated.clone()).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    let reconciled = store.reconcile().await.unwrap();
    if let Some(receipt) = original_receipt {
      assert_eq!(reconciled, ReconcileOutcome::Committed(receipt));
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
    }
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move { task_store.commit(unrelated).await });
    while fault_calls.load(Ordering::SeqCst) < 2 {
      tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(fault_calls.load(Ordering::SeqCst), 2);
  }
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
    mode: UnknownFaultMode::PendingNotApplied,
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

async fn prepare_contract_put(
  store: &MetadataStore, transaction: u16, key: u8,
) -> PreparedTransaction {
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("recovered-open"),
        key: store_key(&[key]),
        expected: StoreExpectation::Absent,
        value: value(&[key]),
      }],
    )
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

pub(crate) fn required_capabilities() -> StoreCapabilities {
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

fn owner_record_key() -> (StoreNamespace, StoreKey) {
  identity_binding_key(&NodeId::parse("node_100000000000000000000").unwrap()).unwrap()
}

fn pointer_record_key() -> (StoreNamespace, StoreKey) {
  local_identity_key().unwrap()
}

#[test]
fn identity_records_record_reference_tokens_are_domain_separated_and_exact() {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let owner = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let pointer = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);

  let golden: [u8; 32] = [
    0x2A, 0x24, 0xA1, 0xE2, 0xBF, 0x60, 0x50, 0xB9, 0xB2, 0x12, 0xBF, 0xEA, 0x1F, 0xC3, 0xAC, 0xB6,
    0xB6, 0x17, 0x65, 0xCA, 0x29, 0x4E, 0xBF, 0x67, 0x0C, 0x21, 0x7F, 0x3A, 0xA8, 0x2F, 0x4B, 0x8A,
  ];
  assert_eq!(
    owner,
    ReceiptReferenceToken::from_digest(Digest::from_bytes(golden))
  );
  assert_eq!(
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    owner
  );
  assert_ne!(owner, pointer);
  let (other_namespace, other_key) =
    identity_binding_key(&NodeId::parse("node_200000000000000000000").unwrap()).unwrap();
  assert_eq!(other_namespace, owner_namespace);
  assert_ne!(
    owner,
    ReceiptReferenceToken::for_record(&owner_namespace, &other_key)
  );
}

#[tokio::test]
async fn identity_records_owner_put_and_self_references_commit_atomically() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(700)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let tokens = [
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
  ];

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(300),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(tokens.to_vec())],
    )
    .await
    .unwrap();
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let head_key = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert_eq!(operations.len(), 1 + 1 + 2 + 1);
  let head_operations: Vec<_> = operations
    .iter()
    .filter(|operation| matches!(operation, StoreOperation::Put { key, .. } if key == &head_key))
    .collect();
  assert_eq!(head_operations.len(), 1);
  assert!(
    matches!(head_operations[0], StoreOperation::Put { expected: StoreExpectation::Absent, value, .. } if value.as_bytes() == 2_u64.to_be_bytes().as_slice())
  );
  for token in &tokens {
    let edge_key = reference_edge_key(prepared.id(), token).unwrap();
    assert!(operations.iter().any(|operation| {
      matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &edge_key && value.as_bytes().is_empty())
    }));
  }
  let marker_key = used_id_key(prepared.id()).unwrap();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &marker_key && value.as_bytes() == ACTIVE_MARKER_VALUE)
  }));

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );

  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"binding"
  );
  assert_eq!(
    snapshot
      .get(&internal, &head_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    2_u64.to_be_bytes().as_slice()
  );
  for token in &tokens {
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(receipt.transaction(), token).unwrap()
        )
        .await
        .unwrap()
        .is_some()
    );
  }
  assert_eq!(
    snapshot
      .get(&internal, &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
  drop(snapshot);

  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(
        &ReceiptIdentity::from_receipt(&receipt),
        contract_transaction_id(301),
      )
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Referenced
  ));
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
}

#[tokio::test]
async fn identity_records_finalization_moves_references_between_receipts_atomically() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(720)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, old_target) = commit_target(&store, 310).await;
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let old_token = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);
  assert!(matches!(
    store
      .add_receipt_reference(&old_target, &old_token, contract_transaction_id(311))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let (owner_namespace, owner_key) = owner_record_key();
  let new_token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(312),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![
        ReceiptReferenceChange::Remove {
          target: old_target.clone(),
          tokens: vec![old_token.clone()],
        },
        ReceiptReferenceChange::AddSelf(vec![new_token.clone()]),
      ],
    )
    .await
    .unwrap();
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let old_head = reference_head_key(old_target.transaction()).unwrap();
  let old_edge = reference_edge_key(old_target.transaction(), &old_token).unwrap();
  let old_anchor = eligibility_anchor_key(old_target.transaction()).unwrap();
  let self_head = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, .. } if key == &old_head)
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, .. } if key == &old_edge)
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &self_head && value.as_bytes() == 1_u64.to_be_bytes().as_slice())
  }));
  assert!(!operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, .. } | StoreOperation::Delete { key, .. } if key == &old_anchor)
  }));

  let receipt = committed(store.commit(prepared).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );

  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"binding"
  );
  assert!(snapshot.get(&internal, &old_head).await.unwrap().is_none());
  assert!(snapshot.get(&internal, &old_edge).await.unwrap().is_none());
  assert_eq!(
    snapshot
      .get(&internal, &self_head)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    1_u64.to_be_bytes().as_slice()
  );
  assert!(
    snapshot
      .get(
        &internal,
        &reference_edge_key(receipt.transaction(), &new_token).unwrap(),
      )
      .await
      .unwrap()
      .is_some()
  );
  assert_eq!(
    snapshot
      .get(&internal, &used_id_key(old_target.transaction()).unwrap())
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
  drop(snapshot);

  assert!(matches!(
    store
      .cleanup_receipt(&old_target, contract_transaction_id(313))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
}

#[tokio::test]
async fn identity_records_existing_target_add_uses_exact_expectations_and_removes_anchor() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(740)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 320).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let first = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let second = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);

  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(321))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  let internal = internal_namespace().unwrap();
  let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();
  let snapshot = store.snapshot().await.unwrap();
  let anchor_digest = snapshot
    .get(&internal, &anchor_key)
    .await
    .unwrap()
    .unwrap()
    .digest()
    .clone();
  drop(snapshot);

  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(322),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![first.clone()],
      }],
    )
    .await
    .unwrap();
  drop(snapshot);
  let head_key = reference_head_key(target.transaction()).unwrap();
  let operations = prepared.operations();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &head_key && value.as_bytes() == 1_u64.to_be_bytes().as_slice())
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, expected, .. } if key == &anchor_key && expected == &anchor_digest)
  }));
  committed(store.commit(prepared).await.unwrap());

  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&internal, &anchor_key)
      .await
      .unwrap()
      .is_none()
  );
  let head = snapshot.get(&internal, &head_key).await.unwrap().unwrap();
  assert_eq!(head.as_bytes(), 1_u64.to_be_bytes().as_slice());
  let head_digest = head.digest().clone();
  drop(snapshot);

  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(323),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![second.clone()],
      }],
    )
    .await
    .unwrap();
  drop(snapshot);
  assert!(prepared.operations().iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Exact(expected), value, .. } if key == &head_key && expected == &head_digest && value.as_bytes() == 2_u64.to_be_bytes().as_slice())
  }));
  committed(store.commit(prepared).await.unwrap());

  let stale_snapshot = store.snapshot().await.unwrap();
  let (..) = commit_target(&store, 324).await;
  let stale = store
    .prepare_transaction_with_receipt_changes(
      stale_snapshot.as_ref(),
      contract_transaction_id(325),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![ReceiptReferenceToken::from_digest(Digest::from_bytes(
          [30; 32],
        ))],
      }],
    )
    .await
    .unwrap();
  drop(stale_snapshot);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  assert!(matches!(
    store.commit(stale).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_receipt_change_requests_are_rejected_before_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(760)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 330).await;
  let token_a = ReceiptReferenceToken::from_digest(Digest::from_bytes([31; 32]));
  let token_b = ReceiptReferenceToken::from_digest(Digest::from_bytes([32; 32]));
  let self_identity = ReceiptIdentity::from_receipt(&CommitReceipt::new(
    contract_transaction_id(332),
    Digest::from_bytes([0; 32]),
    reference_revision(1),
  ));
  let cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::AddSelf(vec![
      token_a.clone(),
      token_a.clone(),
    ])],
    vec![
      ReceiptReferenceChange::AddSelf(vec![token_a.clone()]),
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
    ],
    vec![
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
      ReceiptReferenceChange::Remove {
        target: target.clone(),
        tokens: vec![token_b.clone()],
      },
    ],
    vec![
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_b.clone()],
      },
    ],
    vec![ReceiptReferenceChange::AddSelf(vec![])],
    vec![
      ReceiptReferenceChange::AddSelf(vec![token_a.clone()]),
      ReceiptReferenceChange::AddSelf(vec![token_b.clone()]),
    ],
    vec![ReceiptReferenceChange::Remove {
      target: self_identity,
      tokens: vec![token_a.clone()],
    }],
  ];

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  for (index, changes) in cases.into_iter().enumerate() {
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(332),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput, "case {index}");
  }
  for operation in [
    StoreOperation::Put {
      namespace: internal_namespace().unwrap(),
      key: store_key(b"injected"),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::ForgetReceipt {
      transaction: target.transaction().clone(),
      expected_operation_digest: target.operation_digest().clone(),
    },
  ] {
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(333),
        vec![operation],
        vec![],
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  }
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_receipt_change_snapshot_mismatches_fail_before_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(780)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 340).await;
  let (_, forgotten) = commit_target(&store, 341).await;
  assert!(matches!(
    store
      .cleanup_receipt(&forgotten, contract_transaction_id(342))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(790));
  assert!(matches!(
    store
      .cleanup_receipt(&forgotten, contract_transaction_id(343))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
  let present = ReceiptReferenceToken::from_digest(Digest::from_bytes([33; 32]));
  assert!(matches!(
    store
      .add_receipt_reference(&target, &present, contract_transaction_id(344))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));

  let missing = ReceiptReferenceToken::from_digest(Digest::from_bytes([34; 32]));
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  let conflict_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Remove {
      target: target.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Add {
      target: target.clone(),
      tokens: vec![present.clone()],
    }],
    vec![ReceiptReferenceChange::Add {
      target: forgotten.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: forgotten.clone(),
      tokens: vec![present.clone()],
    }],
  ];
  for (index, changes) in conflict_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(345),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Conflict, "case {index}");
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);

  let (_, orphan) = commit_target(&store, 346).await;
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let orphan_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([35; 32]));
  factory.state.lock().unwrap().entries.insert(
    (
      internal_namespace().unwrap(),
      reference_edge_key(orphan.transaction(), &orphan_token).unwrap(),
    ),
    StoreValue::new(Arc::from([])),
  );
  let orphan_state = factory.state.lock().unwrap().entries.clone();
  let orphan_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Add {
      target: orphan.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: orphan.clone(),
      tokens: vec![orphan_token.clone()],
    }],
  ];
  for (index, changes) in orphan_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(347),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(
      error.kind(),
      crate::ErrorKind::StorageCorrupt,
      "case {index}"
    );
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, orphan_state);

  let (_, undercount) = commit_target(&store, 348).await;
  let undercount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([36; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([37; 32])),
  ];
  for (offset, token) in undercount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &undercount,
          token,
          contract_transaction_id(349 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let undercount_head = reference_head_key(undercount.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (internal_namespace().unwrap(), undercount_head.clone()),
    StoreValue::new(Arc::from(1_u64.to_be_bytes())),
  );
  let undercount_state = factory.state.lock().unwrap().entries.clone();
  let undercount_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Add {
      target: undercount.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: undercount.clone(),
      tokens: vec![undercount_tokens[0].clone()],
    }],
  ];
  for (index, changes) in undercount_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(351),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(
      error.kind(),
      crate::ErrorKind::StorageCorrupt,
      "case {index}"
    );
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, undercount_state);
  factory.state.lock().unwrap().entries.insert(
    (internal_namespace().unwrap(), undercount_head),
    StoreValue::new(Arc::from(u64::MAX.to_be_bytes())),
  );
  let overflow_state = factory.state.lock().unwrap().entries.clone();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(352),
        vec![],
        vec![ReceiptReferenceChange::Add {
          target: undercount.clone(),
          tokens: vec![missing.clone()],
        }],
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, overflow_state);
}

#[tokio::test]
async fn identity_records_combined_commit_unknown_freezes_and_reconciles_exactly() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(800)));
    let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let (owner_namespace, owner_key) = owner_record_key();
    let token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(360),
        vec![StoreOperation::Put {
          namespace: owner_namespace.clone(),
          key: owner_key.clone(),
          expected: StoreExpectation::Absent,
          value: value(b"binding"),
        }],
        vec![ReceiptReferenceChange::AddSelf(vec![token.clone()])],
      )
      .await
      .unwrap();
    drop(snapshot);
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    assert_eq!(
      store.commit(prepared).await.unwrap(),
      CommitOutcome::Unknown {
        transaction: transaction.clone(),
        operation_digest: digest.clone(),
      }
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    let unrelated = prepare_contract_put(&store, 361, 1).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    drop(store);

    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(800)));
    let store = MetadataStore::open_recovered_with_clock(
      &factory,
      Duration::from_secs(10),
      transaction.clone(),
      digest,
      clock,
    )
    .await
    .unwrap();
    let reconciled = store.reconcile().await.unwrap();
    let internal = internal_namespace().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let edge_key = reference_edge_key(&transaction, &token).unwrap();
    if applied {
      assert!(matches!(reconciled, ReconcileOutcome::Committed(_)));
      assert_eq!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .unwrap()
          .as_bytes(),
        b"binding"
      );
      assert!(snapshot.get(&internal, &edge_key).await.unwrap().is_some());
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
      assert!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(snapshot.get(&internal, &edge_key).await.unwrap().is_none());
    }
  }
}

#[tokio::test]
async fn identity_records_cancelled_combined_commit_stays_frozen_until_exact_reconciliation() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::PendingNotApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(820)));
  let store = Arc::new(
    MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap(),
  );
  let (owner_namespace, owner_key) = owner_record_key();
  let token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(370),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(vec![token.clone()])],
    )
    .await
    .unwrap();
  drop(snapshot);
  let transaction = prepared.id().clone();
  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.commit(prepared).await });
  while fault_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);

  let unrelated = prepare_contract_put(&store, 371, 2).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Aborted
  ));
  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    snapshot
      .get(
        &internal,
        &reference_edge_key(&transaction, &token).unwrap()
      )
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    snapshot
      .get(&internal, &used_id_key(&transaction).unwrap())
      .await
      .unwrap()
      .is_none()
  );
}

const JOURNAL_PURPOSE: &str = "local-identity";

fn journaled_tokens() -> (
  ReceiptReferenceToken,
  ReceiptReferenceToken,
  ReceiptReferenceToken,
) {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  (
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
    ReceiptReferenceToken::for_record(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE)),
  )
}

async fn prepare_journaled_owner_put(
  store: &MetadataStore, transaction: u16,
) -> PreparedTransaction {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(transaction),
      JOURNAL_PURPOSE,
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(vec![
        ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
        ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
      ])],
    )
    .await
    .unwrap()
}

async fn open_pending(
  factory: &Arc<dyn StorageFactory>, seconds: u64,
) -> (MetadataStore, Option<ReceiptIdentity>) {
  let clock: Arc<dyn WallClock> =
    Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(seconds)));
  MetadataStore::open_pending_recovered_with_clock(
    factory,
    Duration::from_secs(10),
    JOURNAL_PURPOSE,
    clock,
  )
  .await
  .unwrap()
}

async fn prepare_plain_put(
  store: &MetadataStore, transaction: u16, key: u8,
) -> PreparedTransaction {
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("journaled-unrelated"),
        key: store_key(&[key]),
        expected: StoreExpectation::Absent,
        value: value(&[key]),
      }],
    )
    .unwrap()
}

#[tokio::test]
async fn identity_records_journaled_prepare_writes_exact_plan_record_and_marker() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(840)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let (owner_token, pointer_token, pending_token) = journaled_tokens();
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);
  let internal = internal_namespace().unwrap();

  let snapshot = store.snapshot().await.unwrap();
  let base_revision = snapshot.revision().clone();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = prepare_journaled_owner_put(&store, 400).await;
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let head_key = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert_eq!(operations.len(), 7);
  assert!(
    matches!(&operations[0], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &owner_namespace && key == &owner_key && put.as_bytes() == b"binding")
  );
  assert!(
    matches!(&operations[1], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &head_key && put.as_bytes() == 3_u64.to_be_bytes().as_slice())
  );
  for (index, token) in [&owner_token, &pointer_token, &pending_token]
    .iter()
    .enumerate()
  {
    let edge_key = reference_edge_key(prepared.id(), token).unwrap();
    assert!(
      matches!(&operations[2 + index], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &edge_key && put.as_bytes().is_empty()),
      "edge {index}"
    );
  }
  let StoreOperation::Put {
    namespace: record_namespace,
    key: record_key,
    expected: StoreExpectation::Absent,
    value: record_value,
  } = &operations[5]
  else {
    panic!("unexpected pending record operation: {:?}", operations[5]);
  };
  assert_eq!(record_namespace, &pending_namespace);
  assert_eq!(record_key, &pending_key);
  let record = PendingTransactionV1::decode(record_value.as_bytes()).unwrap();
  assert_eq!(record.purpose(), JOURNAL_PURPOSE);
  assert_eq!(record.transaction(), prepared.id());
  assert_eq!(record.base_revision(), &base_revision);
  assert_eq!(record.planned_operations(), &operations[..5]);
  let recovered = record.recover_identity(record_value).unwrap();
  assert_eq!(recovered.transaction(), prepared.id());
  assert_eq!(recovered.operation_digest(), prepared.operation_digest());
  assert!(
    matches!(&operations[6], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &used_id_key(prepared.id()).unwrap() && put.as_bytes() == ACTIVE_MARKER_VALUE)
  );

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&pending_namespace, &pending_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    record_value.as_bytes()
  );
  assert_eq!(
    snapshot
      .get(&internal, &head_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    3_u64.to_be_bytes().as_slice()
  );
  for token in [&owner_token, &pointer_token, &pending_token] {
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(receipt.transaction(), token).unwrap()
        )
        .await
        .unwrap()
        .is_some()
    );
  }
  assert_eq!(
    snapshot
      .get(&internal, &used_id_key(receipt.transaction()).unwrap())
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
}

#[tokio::test]
async fn identity_records_journaled_prepare_rejects_forbidden_caller_operations() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(850)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  for operation in [
    StoreOperation::Put {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::Check {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
    },
    StoreOperation::Delete {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: Digest::from_bytes([0; 32]),
    },
    StoreOperation::Put {
      namespace: internal_namespace().unwrap(),
      key: store_key(b"injected"),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::ForgetReceipt {
      transaction: contract_transaction_id(410),
      expected_operation_digest: Digest::from_bytes([0; 32]),
    },
  ] {
    let error = store
      .prepare_journaled_transaction(
        snapshot.as_ref(),
        contract_transaction_id(411),
        JOURNAL_PURPOSE,
        vec![operation],
        vec![],
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  }
  let error = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(412),
      JOURNAL_PURPOSE,
      vec![],
      vec![ReceiptReferenceChange::AddSelf(vec![
        ReceiptReferenceToken::for_record(&pending_namespace, &pending_key),
      ])],
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  let error = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(413),
      "bad\tpurpose",
      vec![],
      vec![],
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_journaled_unknown_recovers_reconciles_and_cleans_up() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(860)));
    let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let prepared = prepare_journaled_owner_put(&store, 420).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    assert_eq!(
      store.commit(prepared).await.unwrap(),
      CommitOutcome::Unknown {
        transaction: transaction.clone(),
        operation_digest: digest.clone(),
      }
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    drop(store);

    let (owner_namespace, owner_key) = owner_record_key();
    let (owner_token, pointer_token, pending_token) = journaled_tokens();
    let pending_namespace = pending_namespace().unwrap();
    let pending_key = pending_key(JOURNAL_PURPOSE);
    let internal = internal_namespace().unwrap();
    let head_key = reference_head_key(&transaction).unwrap();

    let plain_factory: Arc<dyn StorageFactory> = reference.clone();
    let (store, recovered) = open_pending(&plain_factory, 861).await;
    if !applied {
      assert!(recovered.is_none());
      assert!(reference.state.lock().unwrap().receipts.is_empty());
      let snapshot = store.snapshot().await.unwrap();
      assert!(
        snapshot
          .get(&pending_namespace, &pending_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(
        snapshot
          .get(&internal, &used_id_key(&transaction).unwrap())
          .await
          .unwrap()
          .is_none()
      );
      assert!(snapshot.get(&internal, &head_key).await.unwrap().is_none());
      drop(snapshot);
      let unrelated = prepare_plain_put(&store, 421, 1).await;
      assert!(matches!(
        store.commit(unrelated).await.unwrap(),
        CommitOutcome::Committed(_)
      ));
      continue;
    }

    let identity = recovered.unwrap();
    assert_eq!(identity.transaction(), &transaction);
    assert_eq!(identity.operation_digest(), &digest);
    let unrelated = prepare_plain_put(&store, 422, 2).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );

    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      snapshot
        .get(&internal, &head_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      3_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token, &pending_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    drop(snapshot);

    let reconciled = store.reconcile().await.unwrap();
    assert!(matches!(reconciled, ReconcileOutcome::Committed(_)));
    let cleanup = store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(423))
      .await
      .unwrap();
    assert!(matches!(cleanup, PendingCleanupOutcome::Applied(_)));

    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&internal, &head_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      2_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(&transaction, &pending_token).unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&owner_namespace, &owner_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"binding"
    );
    drop(snapshot);
    assert!(matches!(
      store
        .cleanup_receipt(&identity, contract_transaction_id(424))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Referenced
    ));
    assert!(matches!(
      store
        .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(425))
        .await
        .unwrap(),
      PendingCleanupOutcome::Absent
    ));
  }
}

#[tokio::test]
async fn identity_records_journaled_cancellation_after_submission_recovers() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::PendingApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(880)));
  let store = Arc::new(
    MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap(),
  );
  let prepared = prepare_journaled_owner_put(&store, 430).await;
  let transaction = prepared.id().clone();
  let digest = prepared.operation_digest().clone();
  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.commit(prepared).await });
  while fault_calls.load(Ordering::SeqCst) == 0
    || !reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(&transaction)
  {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  drop(store);

  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 881).await;
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &transaction);
  assert_eq!(identity.operation_digest(), &digest);
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Committed(_)
  ));
  assert!(matches!(
    store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(431))
      .await
      .unwrap(),
    PendingCleanupOutcome::Applied(_)
  ));
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE))
      .await
      .unwrap()
      .is_none()
  );
}

#[tokio::test]
async fn identity_records_journaled_recovered_digest_conflict_stays_frozen() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(900)));
  let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let prepared = prepare_journaled_owner_put(&store, 432).await;
  let transaction = prepared.id().clone();
  let digest = prepared.operation_digest().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  let tampered = CommitReceipt::new(
    transaction.clone(),
    Digest::from_bytes([0x77; 32]),
    reference_revision(2),
  );
  reference
    .state
    .lock()
    .unwrap()
    .receipts
    .insert(transaction.clone(), tampered);

  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 901).await;
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &transaction);
  assert_eq!(identity.operation_digest(), &digest);
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  let unrelated = prepare_plain_put(&store, 433, 3).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
}

#[tokio::test]
async fn identity_records_journaled_malformed_and_multiple_pending_fail_closed() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);
  let (owner_namespace, owner_key) = owner_record_key();
  let planned = vec![StoreOperation::Put {
    namespace: owner_namespace.clone(),
    key: owner_key.clone(),
    expected: StoreExpectation::Absent,
    value: value(b"binding"),
  }];
  let valid = PendingTransactionV1::encode_for_test(
    JOURNAL_PURPOSE,
    &contract_transaction_id(440),
    &reference_revision(1),
    &planned,
  )
  .unwrap();
  let open = || {
    let factory = Arc::clone(&plain_factory);
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(920)));
    async move {
      MetadataStore::open_pending_recovered_with_clock(
        &factory,
        Duration::from_secs(10),
        JOURNAL_PURPOSE,
        clock,
      )
      .await
    }
  };

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(b"not a pending record"),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&valid),
  );
  let (store, recovered) = open().await.unwrap();
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &contract_transaction_id(440));
  assert_eq!(
    store.reconcile().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  let unrelated = prepare_plain_put(&store, 441, 4).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  drop(store);

  let mismatched = PendingTransactionV1::encode_for_test(
    "other-purpose",
    &contract_transaction_id(440),
    &reference_revision(1),
    &planned,
  )
  .unwrap();
  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&mismatched),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  let self_referencing = PendingTransactionV1::encode_for_test(
    JOURNAL_PURPOSE,
    &contract_transaction_id(440),
    &reference_revision(1),
    &[StoreOperation::Put {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"recursive"),
    }],
  )
  .unwrap();
  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&self_referencing),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&valid),
  );
  reference.state.lock().unwrap().entries.insert(
    (
      pending_namespace.clone(),
      store_key(b"local-identity-extended"),
    ),
    value(&valid),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.remove(&(
    pending_namespace.clone(),
    store_key(b"local-identity-extended"),
  ));
  let (store, recovered) = open().await.unwrap();
  assert!(recovered.is_some());
  drop(store);
}

#[tokio::test]
async fn identity_records_journaled_duplicate_pending_insertion_conflicts_without_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(940)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let first = prepare_journaled_owner_put(&store, 450).await;
  committed(store.commit(first).await.unwrap());

  let second = prepare_journaled_owner_put(&store, 451).await;
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  assert!(matches!(
    store.commit(second).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
  assert!(
    !factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(&contract_transaction_id(451))
  );
}

#[tokio::test]
async fn identity_records_journaled_cleanup_unknown_stays_exact_and_restart_retries() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let plain_factory: Arc<dyn StorageFactory> = reference.clone();
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(960)));
    let seed = MetadataStore::open_with_clock(&plain_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let prepared = prepare_journaled_owner_put(&seed, 460).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    committed(seed.commit(prepared).await.unwrap());
    drop(seed);

    let fault_calls = Arc::new(AtomicUsize::new(0));
    let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(960)));
    let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let cleanup_identity = match store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(461))
      .await
      .unwrap()
    {
      PendingCleanupOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected cleanup outcome: {outcome:?}"),
    };
    assert_eq!(
      cleanup_identity.transaction(),
      &contract_transaction_id(461)
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    let unrelated = prepare_plain_put(&store, 462, 5).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    let reconciled = store.reconcile().await.unwrap();
    match mode {
      UnknownFaultMode::Applied => {
        assert!(matches!(reconciled, ReconcileOutcome::Committed(_)))
      }
      UnknownFaultMode::NotApplied => {
        assert!(matches!(reconciled, ReconcileOutcome::Aborted))
      }
      UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied => unreachable!(),
    }
    let pending_namespace = pending_namespace().unwrap();
    let pending_key = pending_key(JOURNAL_PURPOSE);
    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_some(),
      !applied
    );
    drop(snapshot);
    drop(store);

    let (store, recovered) = open_pending(&plain_factory, 961).await;
    if applied {
      assert!(recovered.is_none());
      let unrelated = prepare_plain_put(&store, 463, 6).await;
      assert!(matches!(
        store.commit(unrelated).await.unwrap(),
        CommitOutcome::Committed(_)
      ));
      continue;
    }
    let identity = recovered.unwrap();
    assert_eq!(identity.transaction(), &transaction);
    assert_eq!(identity.operation_digest(), &digest);
    assert!(matches!(
      store.reconcile().await.unwrap(),
      ReconcileOutcome::Committed(_)
    ));
    assert!(matches!(
      store
        .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(464))
        .await
        .unwrap(),
      PendingCleanupOutcome::Applied(_)
    ));
    let (owner_token, pointer_token, pending_token) = journaled_tokens();
    let internal = internal_namespace().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&internal, &reference_head_key(&transaction).unwrap())
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      2_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(&transaction, &pending_token).unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
  }
}

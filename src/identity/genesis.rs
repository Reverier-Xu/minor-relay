//! Cluster genesis over journaled metadata storage.
//!
//! Cluster creation is allowed only when authoritative storage reads show a
//! standalone local identity: no genesis, cluster pointer, trusted binding,
//! credential use, or admission grant exists. One journaled transaction then
//! commits the versioned signed `ClusterGenesis`, the creator's immutable
//! `IdentityBinding`, and the local cluster pointer, so every crash or
//! unknown outcome recovers to exactly the old or new state.

use std::sync::Arc;

use super::{
  lifecycle::{
    LocalIdentityContext, cleanup_pending_exact, discover_local_identity, discovery_corrupt,
    reconcile_corrupt, reconcile_recovered_journal, reconcile_unknown,
  },
  records::{
    ClusterGenesisV1, IdentityBindingV1, LocalClusterPointerV1, admission_grant_namespace,
    cluster_genesis_key, cluster_genesis_namespace, credential_use_namespace, identity_binding_key,
    identity_binding_namespace, local_cluster_pointer_key, local_identity_key,
  },
  signature::{CLUSTER_GENESIS_V1_DOMAIN, signature_message},
};
use crate::{
  CommitOutcome, Error, ReconcileOutcome, Result, StoreExpectation, StoreOperation, StoreValue,
  TransactionId,
  api::Entropy,
  provider::{KeyProvider, StoreSnapshot},
  storage::receipt::{ReceiptReferenceChange, ReceiptReferenceToken},
};

const CLUSTER_GENESIS_PURPOSE: &str = "cluster-genesis";

/// Creates the local cluster or returns the exact existing genesis.
///
/// The creator signature is produced by the injected key provider and is
/// strictly verified by core before any commit. A recovered pending journal
/// reconciles the exact transaction before any other write.
pub(crate) async fn create_cluster(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
) -> Result<ClusterGenesisV1> {
  let store = context.store();
  if store
    .recover_pending(CLUSTER_GENESIS_PURPOSE)
    .await?
    .is_some()
  {
    reconcile_recovered_journal(store).await?;
    cleanup_pending_exact(
      store,
      entropy,
      CLUSTER_GENESIS_PURPOSE,
      "cluster genesis pending cleanup",
    )
    .await?;
  } else {
    store.reconcile_if_frozen().await?;
  }
  if let Some(existing) = existing_cluster(context).await? {
    return Ok(existing);
  }

  let identity = context.identity();
  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref())
    .await?
    .ok_or_else(discovery_corrupt)?;
  if local.1 != *identity {
    return Err(discovery_corrupt());
  }
  require_empty_namespace(snapshot.as_ref(), &cluster_genesis_namespace()?).await?;
  require_empty_namespace(snapshot.as_ref(), &identity_binding_namespace()?).await?;
  require_empty_namespace(snapshot.as_ref(), &credential_use_namespace()?).await?;
  require_empty_namespace(snapshot.as_ref(), &admission_grant_namespace()?).await?;
  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  if snapshot
    .get(&pointer_namespace, &pointer_key)
    .await?
    .is_some()
  {
    return Err(discovery_corrupt());
  }

  let cluster = crate::ClusterId::generate(entropy)?;
  let body =
    ClusterGenesisV1::encode_signed_body(&cluster, identity.node(), identity.public_key())?;
  let signature = keys
    .sign(
      identity.handle(),
      &signature_message(CLUSTER_GENESIS_V1_DOMAIN, &body),
    )
    .await?;
  let genesis = ClusterGenesisV1::new(
    cluster,
    identity.node().clone(),
    identity.public_key().clone(),
    signature,
  );
  genesis.verify()?;
  let binding = IdentityBindingV1::new(identity.node().clone(), identity.public_key().clone());
  let pointer = LocalClusterPointerV1::new(genesis.cluster().clone(), genesis.digest()?);

  let (local_namespace, local_key) = local_identity_key()?;
  let (binding_namespace, binding_key) = identity_binding_key(identity.node())?;
  let (genesis_namespace, genesis_key) = cluster_genesis_key(genesis.cluster())?;
  let caller_operations = vec![
    StoreOperation::Check {
      namespace: local_namespace,
      key: local_key,
      expected: StoreExpectation::Exact(local.0.digest().clone()),
    },
    StoreOperation::Put {
      namespace: binding_namespace.clone(),
      key: binding_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(binding.encode()?)),
    },
    StoreOperation::Put {
      namespace: genesis_namespace.clone(),
      key: genesis_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(genesis.encode()?)),
    },
    StoreOperation::Put {
      namespace: pointer_namespace.clone(),
      key: pointer_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(pointer.encode()?)),
    },
  ];
  let tokens = vec![
    ReceiptReferenceToken::for_record(&binding_namespace, &binding_key),
    ReceiptReferenceToken::for_record(&genesis_namespace, &genesis_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
  ];
  let transaction = TransactionId::generate(entropy)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      transaction,
      CLUSTER_GENESIS_PURPOSE,
      caller_operations,
      vec![ReceiptReferenceChange::AddSelf(tokens)],
    )
    .await?;
  drop(snapshot);

  match store.commit(prepared).await? {
    CommitOutcome::Committed(_) => {
      cleanup_pending_exact(
        store,
        entropy,
        CLUSTER_GENESIS_PURPOSE,
        "cluster genesis pending cleanup",
      )
      .await?;
      Ok(genesis)
    }
    CommitOutcome::Unknown { .. } => match store.reconcile().await? {
      ReconcileOutcome::Committed(_) => {
        cleanup_pending_exact(
          store,
          entropy,
          CLUSTER_GENESIS_PURPOSE,
          "cluster genesis pending cleanup",
        )
        .await?;
        Ok(genesis)
      }
      ReconcileOutcome::Aborted => Err(Error::conflict("cluster genesis commit")),
      ReconcileOutcome::DigestConflict => Err(reconcile_corrupt()),
      ReconcileOutcome::Unknown => Err(reconcile_unknown()),
    },
    CommitOutcome::Aborted | CommitOutcome::Conflict => match existing_cluster(context).await? {
      Some(existing) if existing == genesis => {
        cleanup_pending_exact(
          store,
          entropy,
          CLUSTER_GENESIS_PURPOSE,
          "cluster genesis pending cleanup",
        )
        .await?;
        Ok(existing)
      }
      _ => Err(Error::conflict("cluster genesis commit")),
    },
  }
}

/// Loads the local cluster pointer, if any.
///
/// Unlike [`existing_cluster`], this works for both cluster creators (full
/// genesis record) and adopters (pointer + verified grant): both paths
/// commit the pointer with an exact verified digest.
pub(crate) async fn local_cluster(
  context: &LocalIdentityContext,
) -> Result<Option<LocalClusterPointerV1>> {
  let snapshot = context.store().snapshot().await?;
  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  let Some(value) = snapshot.get(&pointer_namespace, &pointer_key).await? else {
    return Ok(None);
  };
  let pointer = LocalClusterPointerV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
  Ok(Some(pointer))
}

/// Loads the exact existing cluster state, if any.
///
/// A complete state has the singleton pointer, the referenced signed
/// genesis, and the creator binding. Partial or mismatched state is storage
/// corruption.
pub(crate) async fn existing_cluster(
  context: &LocalIdentityContext,
) -> Result<Option<ClusterGenesisV1>> {
  let snapshot = context.store().snapshot().await?;
  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  let Some(pointer_value) = snapshot.get(&pointer_namespace, &pointer_key).await? else {
    return Ok(None);
  };
  let pointer =
    LocalClusterPointerV1::decode(pointer_value.as_bytes()).map_err(|_| discovery_corrupt())?;

  let genesis_namespace = cluster_genesis_namespace()?;
  let mut scan = snapshot.scan(&genesis_namespace, &[]).await?;
  let mut genesis_entries = Vec::new();
  while let Some(entry) = scan.next().await? {
    genesis_entries
      .try_reserve(1)
      .map_err(|_| Error::resource_exhausted("cluster genesis scan"))?;
    genesis_entries.push(entry);
  }
  drop(scan);
  if genesis_entries.len() != 1 {
    return Err(discovery_corrupt());
  }
  let genesis_entry = &genesis_entries[0];
  let genesis =
    ClusterGenesisV1::decode(genesis_entry.value().as_bytes()).map_err(|_| discovery_corrupt())?;
  genesis.verify().map_err(|_| discovery_corrupt())?;
  let (expected_namespace, expected_key) = cluster_genesis_key(genesis.cluster())?;
  if genesis_entry.namespace() != &expected_namespace
    || genesis_entry.key() != &expected_key
    || genesis.cluster() != pointer.cluster()
    || &genesis.digest().map_err(|_| discovery_corrupt())? != pointer.genesis_digest()
  {
    return Err(discovery_corrupt());
  }

  let (binding_namespace, binding_key) = identity_binding_key(genesis.creator())?;
  let binding_value = snapshot
    .get(&binding_namespace, &binding_key)
    .await?
    .ok_or_else(discovery_corrupt)?;
  let binding =
    IdentityBindingV1::decode(binding_value.as_bytes()).map_err(|_| discovery_corrupt())?;
  if binding.node() != genesis.creator() || binding.public_key() != genesis.creator_key() {
    return Err(discovery_corrupt());
  }
  Ok(Some(genesis))
}

pub(crate) async fn require_empty_namespace(
  snapshot: &dyn StoreSnapshot, namespace: &crate::StoreNamespace,
) -> Result<()> {
  let mut scan = snapshot.scan(namespace, &[]).await?;
  if scan.next().await?.is_some() {
    return Err(Error::conflict("cluster genesis state"));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::Notify;

  use super::{create_cluster, existing_cluster};
  use crate::{
    ErrorKind, ReconcileOutcome, StoreOperation,
    identity::{
      lifecycle::LocalIdentityContext,
      records::{
        ClusterGenesisV1, IdentityBindingV1, LocalClusterPointerV1, cluster_genesis_key,
        identity_binding_key, local_cluster_pointer_key,
      },
      testing::{
        CommitFault, FaultingFactory, KeyCall, ScriptedKeys, SequenceEntropy, SignScript,
        assert_never_deleted, commit_calls, entry, fresh_reference, open_context, pending_keys,
        receipt_ids, remove_entry,
      },
    },
    provider::KeyProvider,
    storage::receipt::internal_namespace,
  };

  fn provider_of(keys: &Arc<ScriptedKeys>) -> Arc<dyn KeyProvider> {
    keys.as_provider()
  }

  async fn genesis_context() -> (
    Arc<crate::storage::contract::ReferenceFactory>,
    Arc<dyn crate::provider::StorageFactory>,
    Arc<ScriptedKeys>,
    Arc<SequenceEntropy>,
    LocalIdentityContext,
  ) {
    let (reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    (reference, factory, keys, entropy, context)
  }

  fn receipt_head_counts(reference: &Arc<crate::storage::contract::ReferenceFactory>) -> Vec<u64> {
    let internal = internal_namespace().unwrap();
    let mut counts: Vec<u64> = reference
      .state
      .lock()
      .unwrap()
      .entries
      .iter()
      .filter(|((namespace, key), _)| {
        namespace == &internal && key.as_bytes().starts_with(b"\x02reference-head\0")
      })
      .map(|(_, value)| u64::from_be_bytes(value.as_bytes().try_into().unwrap()))
      .collect();
    counts.sort_unstable();
    counts
  }

  #[tokio::test]
  async fn identity_records_genesis_commits_signed_records_and_references_atomically() {
    let (reference, _factory, keys, entropy, context) = genesis_context().await;
    let commits_before = commit_calls(&reference);

    let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    genesis.verify().unwrap();
    assert_eq!(genesis.creator(), context.identity().node());
    assert_eq!(genesis.creator_key(), context.identity().public_key());
    assert_eq!(commit_calls(&reference), commits_before + 2);

    let (binding_namespace, binding_key) = identity_binding_key(context.identity().node()).unwrap();
    let binding = IdentityBindingV1::decode(
      entry(&reference, &binding_namespace, &binding_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(binding.node(), context.identity().node());
    assert_eq!(binding.public_key(), context.identity().public_key());

    let (genesis_namespace, genesis_key) = cluster_genesis_key(genesis.cluster()).unwrap();
    let stored = ClusterGenesisV1::decode(
      entry(&reference, &genesis_namespace, &genesis_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(stored, genesis);

    let (pointer_namespace, pointer_key) = local_cluster_pointer_key().unwrap();
    let pointer = LocalClusterPointerV1::decode(
      entry(&reference, &pointer_namespace, &pointer_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(pointer.cluster(), genesis.cluster());
    assert_eq!(pointer.genesis_digest(), &genesis.digest().unwrap());

    assert!(pending_keys(&reference).is_empty());
    let sign_calls = keys
      .all_calls()
      .into_iter()
      .filter(|call| matches!(call, KeyCall::Sign(_)))
      .count();
    assert_eq!(sign_calls, 1);
    // The genesis receipt references all three owner records; the finalized
    // local identity receipt references its own record.
    assert_eq!(receipt_head_counts(&reference), vec![1, 3]);

    let commits_before = commit_calls(&reference);
    let replay = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    assert_eq!(replay, genesis);
    assert_eq!(commit_calls(&reference), commits_before);
    let sign_calls = keys
      .all_calls()
      .into_iter()
      .filter(|call| matches!(call, KeyCall::Sign(_)))
      .count();
    assert_eq!(sign_calls, 1);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_genesis_unknown_outcomes_reconcile_exactly() {
    for applied in [true, false] {
      let (reference, _factory) = fresh_reference();
      let fault = if applied {
        CommitFault::UnknownApplied
      } else {
        CommitFault::UnknownNotApplied
      };
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          fault,
        ],
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();

      let result = create_cluster(&context, &provider_of(&keys), entropy.as_ref()).await;
      if applied {
        let genesis = result.unwrap();
        genesis.verify().unwrap();
        assert!(pending_keys(&reference).is_empty());
        assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
        let existing = existing_cluster(&context).await.unwrap().unwrap();
        assert_eq!(existing, genesis);
      } else {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Conflict);
        assert!(existing_cluster(&context).await.unwrap().is_none());
        assert!(pending_keys(&reference).is_empty());
        let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
          .await
          .unwrap();
        genesis.verify().unwrap();
        assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
      }
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_genesis_pending_journal_recovers_after_reopen() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::HangApplied,
      ],
    );
    faulting.pad_hooks(3);
    let committed = Arc::new(Notify::new());
    {
      let committed = Arc::clone(&committed);
      faulting.push_hook(Box::new(move || committed.notify_one()));
    }
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();

    let task = tokio::spawn({
      let provider = provider_of(&keys);
      let entropy = Arc::clone(&entropy);
      async move { create_cluster(&context, &provider, entropy.as_ref()).await }
    });
    committed.notified().await;
    for _ in 0..64 {
      if !pending_keys(&reference).is_empty() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(pending_keys(&reference).len(), 1);
    task.abort();
    let _ = task.await;

    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    genesis.verify().unwrap();
    assert!(pending_keys(&reference).is_empty());
    assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
    assert_eq!(existing_cluster(&context).await.unwrap().unwrap(), genesis);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_genesis_invalid_signature_is_rejected_before_commit() {
    for script in [SignScript::InvalidBytes, SignScript::WrongMessage] {
      let (reference, _factory, keys, entropy, context) = genesis_context().await;
      keys.push_sign_script(script);
      let commits_before = commit_calls(&reference);
      let error = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
      assert_eq!(commit_calls(&reference), commits_before);
      assert!(existing_cluster(&context).await.unwrap().is_none());
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_genesis_frozen_store_recovers_after_reconcile_unknown() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::UnknownApplied,
      ],
    );
    faulting.push_reconcile_fault(ReconcileOutcome::Unknown);
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();

    let error = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);

    // The provider healed; the same context must recover instead of
    // dead-ending on the frozen store.
    let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    genesis.verify().unwrap();
    assert!(pending_keys(&reference).is_empty());
    assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
    assert_eq!(existing_cluster(&context).await.unwrap().unwrap(), genesis);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_genesis_not_applied_unknown_unfreezes_for_retry() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::UnknownNotApplied,
      ],
    );
    faulting.push_reconcile_fault(ReconcileOutcome::Unknown);
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();

    let error = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);

    // The aborted unknown left no journal; the frozen store reconciles to
    // ready and a fresh transaction commits exactly one genesis.
    let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    genesis.verify().unwrap();
    assert!(pending_keys(&reference).is_empty());
    assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_genesis_equivocated_outcomes_clean_pending_and_return_existing() {
    for fault in [CommitFault::Aborted, CommitFault::Conflict] {
      let (reference, _factory) = fresh_reference();
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          fault,
        ],
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();

      // The provider applied the commit but reported a false definitive
      // outcome; the exact existing state is returned and the pending
      // journal is still cleaned.
      let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap();
      genesis.verify().unwrap();
      assert!(pending_keys(&reference).is_empty());
      assert_eq!(receipt_head_counts(&reference), vec![1, 3]);
      assert_eq!(existing_cluster(&context).await.unwrap().unwrap(), genesis);
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_genesis_partial_state_fails_closed() {
    let (reference, _factory, keys, entropy, context) = genesis_context().await;
    let genesis = create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();

    let (genesis_namespace, genesis_key) = cluster_genesis_key(genesis.cluster()).unwrap();
    remove_entry(&reference, &genesis_namespace, &genesis_key);
    assert_eq!(
      existing_cluster(&context).await.unwrap_err().kind(),
      ErrorKind::StorageCorrupt,
    );

    let (pointer_namespace, pointer_key) = local_cluster_pointer_key().unwrap();
    remove_entry(&reference, &pointer_namespace, &pointer_key);
    assert!(existing_cluster(&context).await.unwrap().is_none());
    assert_eq!(
      create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::Conflict,
    );
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_genesis_commit_ops_are_exact_and_redacted() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(&reference, vec![]);
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();

    let committed = faulting.committed_ops();
    let genesis_ops = &committed[committed.len() - 2];
    let put_count = genesis_ops
      .iter()
      .filter(|operation| matches!(operation, StoreOperation::Put { .. }))
      .count();
    // binding, genesis, pointer, four receipt edges (three owner records
    // plus the pending record), one receipt head, one pending record, one
    // used marker.
    assert_eq!(put_count, 10);
    let debug = format!("{genesis_ops:?}");
    assert!(!debug.contains("scripted-handle"));
    assert!(!receipt_ids(&reference).is_empty());
    assert_never_deleted(&keys);
  }
}

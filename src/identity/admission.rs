//! Atomic admission record commits over journaled metadata storage.
//!
//! The future G3 handshake validates credential and identity proofs before
//! calling this layer. This layer never sees credentials, proofs, exporters,
//! transcripts, or private material. One journaled transaction commits the
//! immutable subject `IdentityBinding`, the unique `CredentialUse`, and the
//! issuer-signed `AdmissionGrant`, so one issuer credential generation can
//! ever commit at most one subject.

use std::sync::Arc;

use super::{
  genesis::{existing_cluster, require_empty_namespace},
  lifecycle::{
    CommitWithReconcile, LocalIdentityContext, cleanup_pending_exact, commit_with_reconcile,
    discover_local_identity, discovery_corrupt, reconcile_recovered_journal,
  },
  records::{
    AdmissionGrantV1, AdmissionId, CredentialUseV1, GenerationId, IdentityBindingV1,
    LocalClusterPointerV1, admission_grant_key, admission_grant_namespace,
    cluster_genesis_namespace, credential_use_key, credential_use_namespace, identity_binding_key,
    identity_binding_namespace, local_cluster_pointer_key, local_identity_key,
  },
  signature::{ADMISSION_GRANT_V1_DOMAIN, signature_message},
};
use crate::{
  Digest, Error, NodeId, PublicKey, Result, StoreExpectation, StoreOperation, StoreValue,
  TransactionId,
  api::Entropy,
  provider::KeyProvider,
  storage::receipt::{ReceiptReferenceChange, ReceiptReferenceToken},
};

/// A proof-free admission record proposal supplied by the future handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionProposal {
  subject: NodeId,
  subject_key: PublicKey,
  generation: GenerationId,
  admission: AdmissionId,
}

impl AdmissionProposal {
  pub(crate) const fn new(
    subject: NodeId, subject_key: PublicKey, generation: GenerationId, admission: AdmissionId,
  ) -> Self {
    Self {
      subject,
      subject_key,
      generation,
      admission,
    }
  }
}

/// The durable outcome of an admission attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionState {
  /// The exact complete binding/use/grant triple exists.
  Consumed(CredentialUseV1, Box<AdmissionGrantV1>),
  /// All three records are authoritatively absent.
  Aborted,
}

/// Commits one admission triple atomically or classifies the exact existing
/// outcome.
///
/// The issuer grant signature is strictly verified by core before commit.
/// Replaying the identical complete triple is idempotent; any conflicting
/// reuse of the subject, credential generation, or admission ID fails closed
/// without mutation.
pub(crate) async fn commit_admission(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  proposal: &AdmissionProposal,
) -> Result<AdmissionGrantV1> {
  let store = context.store();
  let purpose = admission_purpose(&proposal.generation);
  if store.recover_pending(&purpose).await?.is_some() {
    reconcile_recovered_journal(store).await?;
    cleanup_pending_exact(store, entropy, &purpose, "admission pending cleanup").await?;
    return match admission_state(context, proposal).await? {
      AdmissionState::Consumed(_, grant) => Ok(*grant),
      AdmissionState::Aborted => Err(discovery_corrupt()),
    };
  }
  store.reconcile_if_frozen().await?;

  let identity = context.identity();
  let snapshot = store.snapshot().await?;
  let local = discover_local_identity(snapshot.as_ref())
    .await?
    .ok_or_else(discovery_corrupt)?;
  if local.1 != *identity {
    return Err(discovery_corrupt());
  }
  let genesis = existing_cluster(context)
    .await?
    .ok_or_else(|| Error::not_trusted("admission cluster"))?;
  let cluster = genesis.cluster().clone();

  let (issuer_namespace, issuer_key) = identity_binding_key(identity.node())?;
  let issuer_binding_value = snapshot
    .get(&issuer_namespace, &issuer_key)
    .await?
    .ok_or_else(|| Error::not_trusted("admission issuer"))?;
  let issuer_binding =
    IdentityBindingV1::decode(issuer_binding_value.as_bytes()).map_err(|_| discovery_corrupt())?;
  if issuer_binding.node() != identity.node()
    || issuer_binding.public_key() != identity.public_key()
  {
    return Err(discovery_corrupt());
  }

  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  let pointer_value = snapshot
    .get(&pointer_namespace, &pointer_key)
    .await?
    .ok_or_else(discovery_corrupt)?;
  let (binding_namespace, binding_key) = identity_binding_key(&proposal.subject)?;
  let (use_namespace, use_key) = credential_use_key(identity.node(), &proposal.generation)?;
  let (grant_namespace, grant_key) = admission_grant_key(&proposal.admission)?;
  if snapshot
    .get(&binding_namespace, &binding_key)
    .await?
    .is_some()
    || snapshot.get(&use_namespace, &use_key).await?.is_some()
    || snapshot.get(&grant_namespace, &grant_key).await?.is_some()
  {
    drop(snapshot);
    return match admission_state(context, proposal).await {
      Ok(AdmissionState::Consumed(_, existing)) => Ok(*existing),
      Ok(AdmissionState::Aborted) => Err(discovery_corrupt()),
      Err(error) if error.kind() == crate::ErrorKind::StorageCorrupt => Err(error),
      Err(_) => Err(Error::conflict("admission record")),
    };
  }

  let body = AdmissionGrantV1::encode_signed_body(
    &cluster,
    &proposal.admission,
    &proposal.subject,
    &proposal.subject_key,
    identity.node(),
    &proposal.generation,
  )?;
  let signature = keys
    .sign(
      identity.handle(),
      &signature_message(ADMISSION_GRANT_V1_DOMAIN, &body),
    )
    .await?;
  let grant = AdmissionGrantV1::new(
    cluster,
    proposal.admission.clone(),
    proposal.subject.clone(),
    proposal.subject_key.clone(),
    identity.node().clone(),
    proposal.generation.clone(),
    signature,
  );
  grant.verify(identity.public_key())?;
  let credential_use = CredentialUseV1::new(
    grant.cluster().clone(),
    identity.node().clone(),
    proposal.generation.clone(),
    proposal.admission.clone(),
    proposal.subject.clone(),
    proposal.subject_key.clone(),
  );
  let binding = IdentityBindingV1::new(proposal.subject.clone(), proposal.subject_key.clone());

  let (local_namespace, local_key) = local_identity_key()?;
  let caller_operations = vec![
    StoreOperation::Check {
      namespace: local_namespace,
      key: local_key,
      expected: StoreExpectation::Exact(local.0.digest().clone()),
    },
    StoreOperation::Check {
      namespace: pointer_namespace,
      key: pointer_key,
      expected: StoreExpectation::Exact(pointer_value.digest().clone()),
    },
    StoreOperation::Check {
      namespace: issuer_namespace,
      key: issuer_key,
      expected: StoreExpectation::Exact(issuer_binding_value.digest().clone()),
    },
    StoreOperation::Put {
      namespace: binding_namespace.clone(),
      key: binding_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(binding.encode()?)),
    },
    StoreOperation::Put {
      namespace: use_namespace.clone(),
      key: use_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(credential_use.encode()?)),
    },
    StoreOperation::Put {
      namespace: grant_namespace.clone(),
      key: grant_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(grant.encode()?)),
    },
  ];
  let tokens = vec![
    ReceiptReferenceToken::for_record(&binding_namespace, &binding_key),
    ReceiptReferenceToken::for_record(&use_namespace, &use_key),
    ReceiptReferenceToken::for_record(&grant_namespace, &grant_key),
  ];
  let transaction = TransactionId::generate(entropy)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      transaction,
      &purpose,
      caller_operations,
      vec![ReceiptReferenceChange::AddSelf(tokens)],
    )
    .await?;
  drop(snapshot);

  match commit_with_reconcile(&store, prepared).await? {
    CommitWithReconcile::Committed => {
      cleanup_pending_exact(store, entropy, &purpose, "admission pending cleanup").await?;
      Ok(grant)
    }
    CommitWithReconcile::Aborted => match admission_state(context, proposal).await? {
      AdmissionState::Consumed(_, existing) => {
        cleanup_pending_exact(store, entropy, &purpose, "admission pending cleanup").await?;
        Ok(*existing)
      }
      _ => Err(Error::conflict("admission commit")),
    },
  }
}

/// Adopts a verified issuer-signed admission grant on the joining node.
///
/// The joiner receives the grant over the authenticated session; this
/// function is the only persistence boundary for it. Before any storage
/// write the grant is strictly validated: the subject must be exactly the
/// local identity (a node never adopts a grant for another subject), a
/// self-issued grant is rejected, and the issuer signature must verify
/// against the authenticated peer's public key. One journaled transaction
/// then commits the issuer's `IdentityBinding`, the `AdmissionGrant`, and
/// the local cluster pointer, mirroring [`commit_admission`]'s atomicity.
///
/// The node must be standalone: with an existing cluster, only the exact
/// replay of the identical adoption is accepted (idempotent completion
/// after an unknown commit outcome); any other grant conflicts without
/// mutation. A recovered pending journal reconciles to the exact committed
/// state before classification.
///
/// `genesis_digest` is the receiver-supplied digest of the cluster genesis
/// record the pointer binds to; the joiner cannot verify it against the
/// genesis record until a later trust sync, so it is stored exactly as
/// delivered over the authenticated session.
pub(crate) async fn adopt_admission(
  context: &LocalIdentityContext, entropy: &dyn Entropy, grant: &AdmissionGrantV1,
  issuer_key: &PublicKey, genesis_digest: &Digest,
) -> Result<()> {
  let store = context.store();
  let purpose = adoption_purpose(grant.admission());
  if store.recover_pending(&purpose).await?.is_some() {
    reconcile_recovered_journal(store).await?;
    cleanup_pending_exact(store, entropy, &purpose, "adoption pending cleanup").await?;
    return match adoption_state(context, grant, issuer_key, genesis_digest).await? {
      AdoptionState::Adopted => Ok(()),
      AdoptionState::Absent => Err(discovery_corrupt()),
    };
  }
  store.reconcile_if_frozen().await?;

  let identity = context.identity();
  if grant.subject() != identity.node()
    || grant.subject_key() != identity.public_key()
    || grant.issuer() == identity.node()
  {
    return Err(Error::authentication_failed("adoption grant subject"));
  }
  grant.verify(issuer_key)?;

  if existing_cluster(context).await?.is_some() {
    return match adoption_state(context, grant, issuer_key, genesis_digest).await? {
      AdoptionState::Adopted => Ok(()),
      AdoptionState::Absent => Err(Error::conflict("local cluster")),
    };
  }

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

  let binding = IdentityBindingV1::new(grant.issuer().clone(), issuer_key.clone());
  let pointer = LocalClusterPointerV1::new(grant.cluster().clone(), genesis_digest.clone());

  let (local_namespace, local_key) = local_identity_key()?;
  let (binding_namespace, binding_key) = identity_binding_key(grant.issuer())?;
  let (grant_namespace, grant_key) = admission_grant_key(grant.admission())?;
  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
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
      namespace: grant_namespace.clone(),
      key: grant_key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(grant.encode()?)),
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
    ReceiptReferenceToken::for_record(&grant_namespace, &grant_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
  ];
  let transaction = TransactionId::generate(entropy)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      transaction,
      &purpose,
      caller_operations,
      vec![ReceiptReferenceChange::AddSelf(tokens)],
    )
    .await?;
  drop(snapshot);

  match commit_with_reconcile(&store, prepared).await? {
    CommitWithReconcile::Committed => {
      cleanup_pending_exact(store, entropy, &purpose, "adoption pending cleanup").await?;
      Ok(())
    }
    CommitWithReconcile::Aborted => {
      match adoption_state(context, grant, issuer_key, genesis_digest).await? {
        AdoptionState::Adopted => {
          cleanup_pending_exact(store, entropy, &purpose, "adoption pending cleanup").await?;
          Ok(())
        }
        AdoptionState::Absent => Err(Error::conflict("adoption commit")),
      }
    }
  }
}

/// The durable outcome of an adoption attempt: the exact issuer binding,
/// grant, and cluster pointer triple is either complete or fully absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdoptionState {
  Adopted,
  Absent,
}

async fn adoption_state(
  context: &LocalIdentityContext, grant: &AdmissionGrantV1, issuer_key: &PublicKey,
  genesis_digest: &Digest,
) -> Result<AdoptionState> {
  let snapshot = context.store().snapshot().await?;
  let (binding_namespace, binding_key) = identity_binding_key(grant.issuer())?;
  let (grant_namespace, grant_key) = admission_grant_key(grant.admission())?;
  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  let binding = snapshot.get(&binding_namespace, &binding_key).await?;
  let stored_grant = snapshot.get(&grant_namespace, &grant_key).await?;
  let pointer = snapshot.get(&pointer_namespace, &pointer_key).await?;

  let binding = binding
    .map(|value| {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != grant.issuer() || record.public_key() != issuer_key {
        return Err(Error::conflict("adoption record"));
      }
      Ok(record)
    })
    .transpose()?;
  let stored_grant = stored_grant
    .map(|value| {
      let record = AdmissionGrantV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if &record != grant {
        return Err(Error::conflict("adoption grant"));
      }
      record
        .verify(issuer_key)
        .map_err(|_| Error::conflict("adoption grant"))?;
      Ok(record)
    })
    .transpose()?;
  let pointer = pointer
    .map(|value| {
      let record =
        LocalClusterPointerV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.cluster() != grant.cluster() || record.genesis_digest() != genesis_digest {
        return Err(Error::conflict("adoption pointer"));
      }
      Ok(record)
    })
    .transpose()?;

  match (binding, stored_grant, pointer) {
    (Some(_), Some(_), Some(_)) => Ok(AdoptionState::Adopted),
    (None, None, None) => Ok(AdoptionState::Absent),
    _ => Err(discovery_corrupt()),
  }
}

fn adoption_purpose(admission: &AdmissionId) -> String {
  crate::identity::records::JournalPurpose::Adoption(admission.clone()).text()
}

/// Classifies the durable outcome of an admission attempt.
///
/// The credential use, grant, and subject binding are all present with exact
/// matching fields and a valid issuer signature, or all absent. Partial or
/// mismatched state fails closed.
pub(crate) async fn admission_state(
  context: &LocalIdentityContext, proposal: &AdmissionProposal,
) -> Result<AdmissionState> {
  let identity = context.identity();
  let snapshot = context.store().snapshot().await?;
  let (use_namespace, use_key) = credential_use_key(identity.node(), &proposal.generation)?;
  let (grant_namespace, grant_key) = admission_grant_key(&proposal.admission)?;
  let (binding_namespace, binding_key) = identity_binding_key(&proposal.subject)?;
  let credential_use = snapshot.get(&use_namespace, &use_key).await?;
  let grant = snapshot.get(&grant_namespace, &grant_key).await?;
  let binding = snapshot.get(&binding_namespace, &binding_key).await?;

  let (pointer_namespace, pointer_key) = local_cluster_pointer_key()?;
  let cluster = match snapshot.get(&pointer_namespace, &pointer_key).await? {
    Some(pointer_value) => {
      let pointer = super::records::LocalClusterPointerV1::decode(pointer_value.as_bytes())
        .map_err(|_| discovery_corrupt())?;
      Some(pointer.cluster().clone())
    }
    None => None,
  };

  let credential_use = credential_use
    .map(|value| {
      let record = CredentialUseV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.issuer() != identity.node()
        || record.generation() != &proposal.generation
        || record.admission() != &proposal.admission
        || record.subject() != &proposal.subject
        || record.subject_key() != &proposal.subject_key
        || cluster.as_ref() != Some(record.cluster())
      {
        return Err(Error::conflict("admission record"));
      }
      Ok(record)
    })
    .transpose()?;
  let grant = grant
    .map(|value| {
      let record = AdmissionGrantV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.admission() != &proposal.admission
        || record.subject() != &proposal.subject
        || record.subject_key() != &proposal.subject_key
        || record.issuer() != identity.node()
        || record.generation() != &proposal.generation
        || cluster.as_ref() != Some(record.cluster())
      {
        return Err(Error::conflict("admission grant"));
      }
      record
        .verify(identity.public_key())
        .map_err(|_| Error::conflict("admission grant"))?;
      Ok(record)
    })
    .transpose()?;
  let binding = binding
    .map(|value| {
      let record = IdentityBindingV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if record.node() != &proposal.subject || record.public_key() != &proposal.subject_key {
        return Err(Error::conflict("admission record"));
      }
      Ok(record)
    })
    .transpose()?;

  match (credential_use, grant, binding) {
    (Some(credential_use), Some(grant), Some(_)) => {
      if credential_use.cluster() != grant.cluster() {
        return Err(Error::conflict("admission record"));
      }
      Ok(AdmissionState::Consumed(credential_use, Box::new(grant)))
    }
    (None, None, None) => Ok(AdmissionState::Aborted),
    _ => Err(discovery_corrupt()),
  }
}

fn admission_purpose(generation: &GenerationId) -> String {
  crate::identity::records::JournalPurpose::Admission(generation.clone()).text()
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::Notify;

  use super::{AdmissionProposal, AdmissionState, admission_state, commit_admission};
  use crate::{
    ErrorKind, PublicKey,
    identity::{
      genesis::create_cluster,
      lifecycle::LocalIdentityContext,
      records::{
        AdmissionGrantV1, AdmissionId, CredentialUseV1, GenerationId, admission_grant_key,
        credential_use_key, identity_binding_key,
      },
      testing::{
        CommitFault, CommitFault::Pass, FaultingFactory, ScriptedKeys, SequenceEntropy, SignScript,
        assert_never_deleted, commit_calls, entry, fresh_reference, node, open_context,
        pending_keys, remove_entry, scripted_signing,
      },
    },
    provider::KeyProvider,
    storage::contract::ReferenceFactory,
  };

  fn provider_of(keys: &Arc<ScriptedKeys>) -> Arc<dyn KeyProvider> {
    keys.as_provider()
  }

  struct Fixture {
    reference: Arc<ReferenceFactory>,
    keys: Arc<ScriptedKeys>,
    entropy: Arc<SequenceEntropy>,
    context: LocalIdentityContext,
  }

  async fn clustered() -> Fixture {
    let (reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    Fixture {
      reference,
      keys,
      entropy,
      context,
    }
  }

  fn proposal(seed: u64, entropy: &SequenceEntropy) -> AdmissionProposal {
    let subject = node(u128::from(seed) + 1_000);
    let subject_key = PublicKey::from_bytes(scripted_signing(seed).verifying_key().to_bytes());
    AdmissionProposal::new(
      subject,
      subject_key,
      GenerationId::generate(entropy).unwrap(),
      AdmissionId::generate(entropy).unwrap(),
    )
  }

  #[tokio::test]
  async fn identity_records_admission_commits_binding_use_and_grant_atomically() {
    let fixture = clustered().await;
    let proposal = proposal(7, &fixture.entropy);
    let commits_before = commit_calls(&fixture.reference);

    let grant = commit_admission(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &proposal,
    )
    .await
    .unwrap();
    grant
      .verify(fixture.context.identity().public_key())
      .unwrap();
    assert_eq!(commit_calls(&fixture.reference), commits_before + 2);

    let (use_namespace, use_key) = credential_use_key(
      fixture.context.identity().node(),
      proposal_generation(&proposal),
    )
    .unwrap();
    let usage = CredentialUseV1::decode(
      entry(&fixture.reference, &use_namespace, &use_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(usage.subject(), proposal_subject(&proposal));
    let (grant_namespace, grant_key) = admission_grant_key(proposal_admission(&proposal)).unwrap();
    let stored = AdmissionGrantV1::decode(
      entry(&fixture.reference, &grant_namespace, &grant_key)
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(stored, grant);

    // Records never contain the issuer's opaque provider handle.
    let handle = fixture.context.identity().handle().expose_provider_handle();
    let (binding_namespace, binding_key) =
      identity_binding_key(proposal_subject(&proposal)).unwrap();
    for (namespace, key) in [
      (binding_namespace, binding_key),
      (use_namespace, use_key),
      (grant_namespace, grant_key),
    ] {
      let value = entry(&fixture.reference, &namespace, &key).unwrap();
      assert!(
        !value
          .as_bytes()
          .windows(handle.len())
          .any(|window| window == handle),
        "provider handle leaked into an admission record"
      );
    }

    match admission_state(&fixture.context, &proposal).await.unwrap() {
      AdmissionState::Consumed(usage, existing) => {
        assert_eq!(usage.subject(), proposal_subject(&proposal));
        assert_eq!(*existing, grant);
      }
      AdmissionState::Aborted => panic!("committed admission must be consumed"),
    }
    assert!(pending_keys(&fixture.reference).is_empty());

    // Exact replay is idempotent without new provider calls or commits.
    let commits_before = commit_calls(&fixture.reference);
    let calls_before = fixture.keys.all_calls().len();
    let replay = commit_admission(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &proposal,
    )
    .await
    .unwrap();
    assert_eq!(replay, grant);
    assert_eq!(commit_calls(&fixture.reference), commits_before);
    assert_eq!(fixture.keys.all_calls().len(), calls_before);
    assert_never_deleted(&fixture.keys);
  }

  #[tokio::test]
  async fn identity_records_admission_conflicts_preserve_original_records() {
    let fixture = clustered().await;
    let first = proposal(11, &fixture.entropy);
    let grant = commit_admission(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &first,
    )
    .await
    .unwrap();

    // Same subject with another public key.
    let mut conflicting = proposal(12, &fixture.entropy);
    set_subject(&mut conflicting, proposal_subject(&first).clone());
    // Same generation with another subject.
    let mut other_subject = proposal(13, &fixture.entropy);
    set_generation(&mut other_subject, proposal_generation(&first).clone());
    // Same admission ID with another subject.
    let mut reused_admission = proposal(14, &fixture.entropy);
    set_admission(&mut reused_admission, proposal_admission(&first).clone());

    for attempt in [conflicting, other_subject, reused_admission] {
      let commits_before = commit_calls(&fixture.reference);
      let error = commit_admission(
        &fixture.context,
        &provider_of(&fixture.keys),
        fixture.entropy.as_ref(),
        &attempt,
      )
      .await
      .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::Conflict, "attempt: {attempt:?}");
      assert_eq!(commit_calls(&fixture.reference), commits_before);
      match admission_state(&fixture.context, &first).await.unwrap() {
        AdmissionState::Consumed(_, existing) => assert_eq!(*existing, grant),
        AdmissionState::Aborted => panic!("original admission must survive"),
      }
    }
    assert_never_deleted(&fixture.keys);
  }

  #[tokio::test]
  async fn identity_records_admission_unknown_never_changes_subject() {
    for applied in [true, false] {
      let (reference, _factory) = fresh_reference();
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          if applied {
            CommitFault::UnknownApplied
          } else {
            CommitFault::UnknownNotApplied
          },
        ],
      );
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(17, &entropy);

      let result = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first).await;
      if applied {
        let grant = result.unwrap();
        grant.verify(context.identity().public_key()).unwrap();
        assert!(pending_keys(&reference).is_empty());
        // The same generation can never admit a second subject.
        let mut second = proposal(18, &entropy);
        set_generation(&mut second, proposal_generation(&first).clone());
        assert_eq!(
          commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &second)
            .await
            .unwrap_err()
            .kind(),
          ErrorKind::Conflict,
        );
        match admission_state(&context, &first).await.unwrap() {
          AdmissionState::Consumed(_, existing) => assert_eq!(*existing, grant),
          AdmissionState::Aborted => panic!("applied admission must be consumed"),
        }
      } else {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Conflict);
        assert!(matches!(
          admission_state(&context, &first).await.unwrap(),
          AdmissionState::Aborted
        ));
        let grant = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first)
          .await
          .unwrap();
        grant.verify(context.identity().public_key()).unwrap();
      }
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_admission_pending_journal_recovers_after_reopen() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::HangApplied,
      ],
    );
    faulting.pad_hooks(5);
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
    create_cluster(&context, &provider_of(&keys), entropy.as_ref())
      .await
      .unwrap();
    let first = proposal(19, &entropy);

    let task = tokio::spawn({
      let provider = provider_of(&keys);
      let entropy = Arc::clone(&entropy);
      let proposal = first.clone();
      async move { commit_admission(&context, &provider, entropy.as_ref(), &proposal).await }
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
    let grant = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first)
      .await
      .unwrap();
    grant.verify(context.identity().public_key()).unwrap();
    assert!(pending_keys(&reference).is_empty());
    match admission_state(&context, &first).await.unwrap() {
      AdmissionState::Consumed(_, existing) => assert_eq!(*existing, grant),
      AdmissionState::Aborted => panic!("recovered admission must be consumed"),
    }
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_admission_equivocated_outcomes_clean_pending_and_return_existing() {
    for fault in [CommitFault::Aborted, CommitFault::Conflict] {
      let (reference, _factory) = fresh_reference();
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
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
      create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(37, &entropy);

      let grant = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap();
      grant.verify(context.identity().public_key()).unwrap();
      assert!(pending_keys(&reference).is_empty());
      match admission_state(&context, &first).await.unwrap() {
        AdmissionState::Consumed(_, existing) => assert_eq!(*existing, grant),
        AdmissionState::Aborted => panic!("equivocated admission must be consumed"),
      }

      let commits_before = commit_calls(&reference);
      let replay = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap();
      assert_eq!(replay, grant);
      assert_eq!(commit_calls(&reference), commits_before);
      assert_never_deleted(&keys);
    }
  }

  #[tokio::test]
  async fn identity_records_admission_rejects_invalid_signature_and_untrusted_issuer() {
    let fixture = clustered().await;
    let attempt = proposal(23, &fixture.entropy);
    fixture.keys.push_sign_script(SignScript::InvalidBytes);
    let commits_before = commit_calls(&fixture.reference);
    assert_eq!(
      commit_admission(
        &fixture.context,
        &provider_of(&fixture.keys),
        fixture.entropy.as_ref(),
        &attempt,
      )
      .await
      .unwrap_err()
      .kind(),
      ErrorKind::AuthenticationFailed,
    );
    assert_eq!(commit_calls(&fixture.reference), commits_before);

    let (_reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let standalone = open_context(&factory, &keys, &entropy).await.unwrap();
    let attempt = proposal(29, &entropy);
    assert_eq!(
      commit_admission(&standalone, &provider_of(&keys), entropy.as_ref(), &attempt)
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::NotTrusted,
    );
    assert_never_deleted(&fixture.keys);
    assert_never_deleted(&keys);
  }

  #[tokio::test]
  async fn identity_records_admission_partial_state_fails_closed() {
    let fixture = clustered().await;
    let first = proposal(31, &fixture.entropy);
    commit_admission(
      &fixture.context,
      &provider_of(&fixture.keys),
      fixture.entropy.as_ref(),
      &first,
    )
    .await
    .unwrap();

    let (grant_namespace, grant_key) = admission_grant_key(proposal_admission(&first)).unwrap();
    remove_entry(&fixture.reference, &grant_namespace, &grant_key);
    assert_eq!(
      admission_state(&fixture.context, &first)
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::StorageCorrupt,
    );
    assert_never_deleted(&fixture.keys);
  }

  // ---- T-G03-03 atomic admission/reconciliation evidence ----

  /// SC-G03-P0-07: faulting every pre-commit boundary of the admission
  /// commit (genuine abort, genuine conflict, or crash before apply)
  /// leaves binding, use, and grant all absent and releases the
  /// still-valid credential generation for exactly one later attempt.
  #[tokio::test]
  async fn identity_records_admission_precommit_rejections_leave_all_absent_and_release_generation()
  {
    for fault in [
      CommitFault::PureAborted,
      CommitFault::PureConflict,
      CommitFault::UnknownNotApplied,
    ] {
      let (reference, _factory) = fresh_reference();
      // Positions: identity(3) + genesis(2) pass; the admission triple
      // commit at position six fails before applying.
      let faulting = FaultingFactory::new(
        &reference,
        vec![Pass; 5].into_iter().chain([fault]).collect(),
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(41, &entropy);

      let error = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first)
        .await
        .unwrap_err();
      assert_eq!(error.kind(), ErrorKind::Conflict, "fault: {fault:?}");
      assert!(
        matches!(
          admission_state(&context, &first).await.unwrap(),
          AdmissionState::Aborted
        ),
        "fault: {fault:?} must leave every record absent"
      );
      assert!(pending_keys(&reference).is_empty(), "fault: {fault:?}");
      assert_never_deleted(&keys);

      // One later attempt with the same generation (a fresh admission id)
      // commits exactly one subject.
      let mut later = proposal(43, &entropy);
      set_generation(&mut later, proposal_generation(&first).clone());
      let grant = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &later)
        .await
        .unwrap();
      grant.verify(context.identity().public_key()).unwrap();
      assert!(
        matches!(
          admission_state(&context, &later).await.unwrap(),
          AdmissionState::Consumed(..)
        ),
        "fault: {fault:?} later attempt must consume the generation"
      );

      // A second subject for the same generation is refused: one issuer
      // generation never commits two subjects.
      let mut another = proposal(47, &entropy);
      set_generation(&mut another, proposal_generation(&first).clone());
      assert_eq!(
        commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &another)
          .await
          .unwrap_err()
          .kind(),
        ErrorKind::Conflict,
        "fault: {fault:?}"
      );
      assert_never_deleted(&keys);
    }
  }

  /// SC-G03-P0-09: a crash after apply at every pre-admission commit
  /// boundary never yields a partial triple, and reopen resolves to
  /// exactly the applied admission (at most one subject per generation).
  #[tokio::test]
  async fn identity_records_admission_unknown_applied_schedule_reconciles_after_reopen() {
    for position in 1..=6_u32 {
      let (reference, _factory) = fresh_reference();
      let mut script = vec![Pass; (position - 1) as usize];
      script.push(CommitFault::UnknownApplied);
      let faulting = FaultingFactory::new(&reference, script);
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      create_cluster(&context, &provider_of(&keys), entropy.as_ref())
        .await
        .unwrap();
      let first = proposal(53, &entropy);
      let _ = commit_admission(&context, &provider_of(&keys), entropy.as_ref(), &first).await;

      // Authoritative reopen on the same provider reconciles the journal
      // to the exact outcome; a partial triple fails closed.
      drop(context);
      let reopened = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      match admission_state(&reopened, &first).await {
        Ok(AdmissionState::Consumed(_, grant)) => {
          grant.verify(reopened.identity().public_key()).unwrap();
        }
        Ok(AdmissionState::Aborted) => {
          // The admission never applied; the generation stays reusable.
          let grant = commit_admission(&reopened, &provider_of(&keys), entropy.as_ref(), &first)
            .await
            .unwrap();
          grant.verify(reopened.identity().public_key()).unwrap();
        }
        Err(error) => panic!("position {position}: partial admission after reopen: {error:?}"),
      }
      assert!(pending_keys(&reference).is_empty(), "position {position}");
      assert_never_deleted(&keys);
    }
  }

  fn proposal_subject(proposal: &AdmissionProposal) -> &crate::NodeId {
    &proposal.subject
  }

  fn proposal_generation(proposal: &AdmissionProposal) -> &GenerationId {
    &proposal.generation
  }

  fn proposal_admission(proposal: &AdmissionProposal) -> &AdmissionId {
    &proposal.admission
  }

  fn set_subject(proposal: &mut AdmissionProposal, subject: crate::NodeId) {
    proposal.subject = subject;
  }

  fn set_generation(proposal: &mut AdmissionProposal, generation: GenerationId) {
    proposal.generation = generation;
  }

  fn set_admission(proposal: &mut AdmissionProposal, admission: AdmissionId) {
    proposal.admission = admission;
  }
}

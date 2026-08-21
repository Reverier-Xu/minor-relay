use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use self::receipt::{HostWallClock, PreparedTransaction, WallClock};
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, ErrorKind, ProviderErrorContext, ProviderErrorKind,
  ReconcileOutcome, Result, StoreRequirements, TransactionId,
  provider::{Storage, StorageFactory, StoreSnapshot},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCommit {
  transaction: TransactionId,
  digest: Digest,
  journal_proven: bool,
}

#[derive(Debug)]
enum CommitState {
  Ready,
  Frozen {
    pending: PendingCommit,
    provider_call_active: bool,
  },
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct MetadataStore {
  provider: Box<dyn Storage>,
  state: Mutex<CommitState>,
  clock: Arc<dyn WallClock>,
  receipt_retention: Duration,
}

#[allow(dead_code)]
struct ProviderCall<'a> {
  state: &'a Mutex<CommitState>,
  active: bool,
}

#[allow(dead_code)]
impl ProviderCall<'_> {
  fn complete(mut self) {
    self.active = false;
  }
}

impl Drop for ProviderCall<'_> {
  fn drop(&mut self) {
    if !self.active {
      return;
    }
    if let Ok(mut state) = self.state.lock()
      && let CommitState::Frozen {
        provider_call_active,
        ..
      } = &mut *state
    {
      *provider_call_active = false;
    }
  }
}

#[allow(dead_code)]
impl MetadataStore {
  pub(crate) async fn open(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration,
  ) -> Result<Self> {
    Self::open_with_clock(factory, receipt_retention, Arc::new(HostWallClock)).await
  }

  pub(crate) async fn open_recovered(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, transaction: TransactionId,
    digest: Digest,
  ) -> Result<Self> {
    Self::open_recovered_with_clock(
      factory,
      receipt_retention,
      transaction,
      digest,
      Arc::new(HostWallClock),
    )
    .await
  }

  async fn open_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, clock: Arc<dyn WallClock>,
  ) -> Result<Self> {
    Self::open_with_state(factory, receipt_retention, clock, CommitState::Ready).await
  }

  async fn open_recovered_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, transaction: TransactionId,
    digest: Digest, clock: Arc<dyn WallClock>,
  ) -> Result<Self> {
    Self::open_with_state(
      factory,
      receipt_retention,
      clock,
      CommitState::Frozen {
        pending: PendingCommit {
          transaction,
          digest,
          journal_proven: false,
        },
        provider_call_active: false,
      },
    )
    .await
  }

  async fn open_with_state(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, clock: Arc<dyn WallClock>,
    state: CommitState,
  ) -> Result<Self> {
    let requirements = StoreRequirements::metadata();
    let provider = factory.open(requirements).await?;
    if !provider.capabilities().satisfies(&requirements) {
      return Err(Error::provider(
        ProviderErrorKind::UnsupportedCapability,
        ProviderErrorContext::StorageOpen,
      ));
    }
    Ok(Self {
      provider,
      state: Mutex::new(state),
      clock,
      receipt_retention,
    })
  }

  pub(crate) async fn snapshot(&self) -> Result<Box<dyn StoreSnapshot>> {
    self.provider.snapshot().await
  }

  pub(crate) async fn commit(&self, transaction: PreparedTransaction) -> Result<CommitOutcome> {
    let transaction = transaction.0;
    let pending = PendingCommit {
      transaction: transaction.id().clone(),
      digest: transaction.operation_digest().clone(),
      journal_proven: false,
    };
    let call = self.begin_commit(pending.clone())?;
    let result = self.provider.commit(transaction).await;

    match result {
      Ok(CommitOutcome::Committed(receipt)) => {
        self.validate_receipt(&pending, &receipt, ProviderErrorContext::StorageCommit)?;
        self.finish_ready(call)?;
        Ok(CommitOutcome::Committed(receipt))
      }
      Ok(CommitOutcome::Aborted) => {
        self.finish_ready(call)?;
        Ok(CommitOutcome::Aborted)
      }
      Ok(CommitOutcome::Conflict) => {
        self.finish_ready(call)?;
        Ok(CommitOutcome::Conflict)
      }
      Ok(CommitOutcome::Unknown {
        transaction,
        operation_digest,
      }) => {
        if transaction != pending.transaction || operation_digest != pending.digest {
          return Err(Error::provider(
            ProviderErrorKind::StorageCorrupt,
            ProviderErrorContext::StorageCommit,
          ));
        }
        self.finish_frozen(call)?;
        Ok(CommitOutcome::Unknown {
          transaction,
          operation_digest,
        })
      }
      Err(error) if error.kind() == ErrorKind::CommitUnknown => {
        self.finish_frozen(call)?;
        Err(error)
      }
      Err(error) => {
        self.finish_ready(call)?;
        Err(error)
      }
    }
  }

  pub(crate) async fn reconcile(&self) -> Result<ReconcileOutcome> {
    let (pending, call) = self.begin_reconcile()?;
    let outcome = self
      .provider
      .reconcile(&pending.transaction, &pending.digest)
      .await;
    match outcome {
      Ok(ReconcileOutcome::Committed(receipt)) => {
        self.validate_receipt(&pending, &receipt, ProviderErrorContext::StorageReconcile)?;
        self.finish_ready(call)?;
        Ok(ReconcileOutcome::Committed(receipt))
      }
      Ok(ReconcileOutcome::Aborted) => {
        if pending.journal_proven {
          // A recovered pending record proves the journaled transaction
          // committed atomically, so an aborted reconciliation contradicts
          // the durable journal and must fail closed.
          self.finish_frozen(call)?;
          return Err(Error::provider(
            ProviderErrorKind::StorageCorrupt,
            ProviderErrorContext::StorageReconcile,
          ));
        }
        self.finish_ready(call)?;
        Ok(ReconcileOutcome::Aborted)
      }
      Ok(ReconcileOutcome::DigestConflict) => {
        self.finish_frozen(call)?;
        Ok(ReconcileOutcome::DigestConflict)
      }
      Ok(ReconcileOutcome::Unknown) => {
        self.finish_frozen(call)?;
        Ok(ReconcileOutcome::Unknown)
      }
      Err(error) => {
        self.finish_frozen(call)?;
        Err(error)
      }
    }
  }

  fn begin_commit(&self, pending: PendingCommit) -> Result<ProviderCall<'_>> {
    let mut state = self.lock_state()?;
    if !matches!(*state, CommitState::Ready) {
      return Err(Error::not_ready("metadata storage commit"));
    }
    *state = CommitState::Frozen {
      pending,
      provider_call_active: true,
    };
    drop(state);
    Ok(ProviderCall {
      state: &self.state,
      active: true,
    })
  }

  fn begin_reconcile(&self) -> Result<(PendingCommit, ProviderCall<'_>)> {
    let mut state = self.lock_state()?;
    let pending = match &mut *state {
      CommitState::Ready => return Err(Error::not_ready("metadata storage reconcile")),
      CommitState::Frozen {
        pending,
        provider_call_active,
      } => {
        if *provider_call_active {
          return Err(Error::not_ready("metadata storage reconcile"));
        }
        *provider_call_active = true;
        pending.clone()
      }
    };
    drop(state);
    Ok((
      pending,
      ProviderCall {
        state: &self.state,
        active: true,
      },
    ))
  }

  fn finish_ready(&self, call: ProviderCall<'_>) -> Result<()> {
    *self.lock_state()? = CommitState::Ready;
    call.complete();
    Ok(())
  }

  fn finish_frozen(&self, call: ProviderCall<'_>) -> Result<()> {
    let mut state = self.lock_state()?;
    let CommitState::Frozen {
      provider_call_active,
      ..
    } = &mut *state
    else {
      return Err(Error::internal("metadata storage commit state"));
    };
    *provider_call_active = false;
    drop(state);
    call.complete();
    Ok(())
  }

  fn validate_receipt(
    &self, pending: &PendingCommit, receipt: &CommitReceipt, context: ProviderErrorContext,
  ) -> Result<()> {
    if receipt.transaction() != &pending.transaction
      || receipt.operation_digest() != &pending.digest
    {
      return Err(Error::provider(ProviderErrorKind::StorageCorrupt, context));
    }
    Ok(())
  }

  /// Freezes a ready store on a pending identity recovered from a durable
  /// journal by the caller.
  ///
  /// The journal record was committed atomically with the target
  /// transaction, so reconciliation must prove `Committed`. Recovering the
  /// same identity again is idempotent: an already frozen store keeps its
  /// pending identity and upgrades it to journal-proven so reconciliation
  /// can proceed after a healed provider.
  pub(crate) fn freeze_journaled(&self, identity: &receipt::ReceiptIdentity) -> Result<()> {
    let mut state = self.lock_state()?;
    match &mut *state {
      CommitState::Ready => {
        *state = CommitState::Frozen {
          pending: PendingCommit {
            transaction: identity.transaction().clone(),
            digest: identity.operation_digest().clone(),
            journal_proven: true,
          },
          provider_call_active: false,
        };
        Ok(())
      }
      CommitState::Frozen { pending, .. }
        if pending.transaction == *identity.transaction()
          && pending.digest == *identity.operation_digest() =>
      {
        pending.journal_proven = true;
        Ok(())
      }
      CommitState::Frozen { .. } => Err(Error::not_ready("metadata storage journal recovery")),
    }
  }

  /// Reconciles a frozen store back to ready, if it is frozen.
  ///
  /// A ready store is unchanged. A frozen store reconciles its exact pending
  /// identity once; `Committed` or `Aborted` clears the freeze while an
  /// unresolved or conflicting outcome keeps it and fails.
  pub(crate) async fn reconcile_if_frozen(&self) -> Result<()> {
    {
      let state = self.lock_state()?;
      if matches!(*state, CommitState::Ready) {
        return Ok(());
      }
    }
    match self.reconcile().await? {
      ReconcileOutcome::Committed(_) | ReconcileOutcome::Aborted => Ok(()),
      ReconcileOutcome::DigestConflict => Err(Error::provider(
        ProviderErrorKind::StorageCorrupt,
        ProviderErrorContext::StorageReconcile,
      )),
      ReconcileOutcome::Unknown => Err(Error::provider(
        ProviderErrorKind::CommitUnknown,
        ProviderErrorContext::StorageReconcile,
      )),
    }
  }

  /// Whether the store is frozen on an indeterminate outcome and the
  /// runtime must block new admission-sensitive operations (credential
  /// rotation, reuse, signing, and networking) until an authoritative
  /// reopen reconciles the exact transaction or proves absence.
  pub(crate) fn is_blocked(&self) -> Result<bool> {
    Ok(matches!(*self.lock_state()?, CommitState::Frozen { .. }))
  }

  fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, CommitState>> {
    self
      .state
      .lock()
      .map_err(|_| Error::internal("metadata storage commit state"))
  }
}

#[cfg(feature = "json")]
pub(crate) mod json;
#[allow(dead_code)]
pub(crate) mod pending;
#[allow(dead_code)]
pub(crate) mod receipt;

#[cfg(test)]
pub(crate) mod contract;

#[cfg(test)]
mod tests;

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

  async fn open_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, clock: Arc<dyn WallClock>,
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
      state: Mutex::new(CommitState::Ready),
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

  fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, CommitState>> {
    self
      .state
      .lock()
      .map_err(|_| Error::internal("metadata storage commit state"))
  }
}

#[allow(dead_code)]
mod receipt;

#[cfg(test)]
mod contract;

#[cfg(test)]
mod tests;

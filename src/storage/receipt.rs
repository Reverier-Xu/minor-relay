use std::{
  fmt,
  sync::Arc,
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::MetadataStore;
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, ProviderErrorContext, ProviderErrorKind,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRevision, StoreTransaction,
  StoreValue, TransactionId,
};

const INTERNAL_NAMESPACE: &str = "relay.woooo.tech/metadata/receipt-internal-v1";
const USED_ID_TAG: &[u8] = b"\x01used-id\0";
const REFERENCE_HEAD_TAG: &[u8] = b"\x02reference-head\0";
const REFERENCE_EDGE_TAG: &[u8] = b"\x03reference-edge\0";
const ELIGIBILITY_ANCHOR_TAG: &[u8] = b"\x04eligibility-anchor\0";
const EDGE_DELIMITER: u8 = 0;
const WALL_TIME_WIDTH: usize = 13;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

pub(super) trait WallClock: fmt::Debug + Send + Sync + 'static {
  fn now(&self) -> SystemTime;
}

#[derive(Debug)]
pub(super) struct HostWallClock;

impl WallClock for HostWallClock {
  fn now(&self) -> SystemTime {
    SystemTime::now()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedTransaction(pub(super) StoreTransaction);

impl PreparedTransaction {
  pub(super) fn id(&self) -> &TransactionId {
    self.0.id()
  }

  pub(super) fn operation_digest(&self) -> &Digest {
    self.0.operation_digest()
  }

  #[cfg(test)]
  pub(super) fn operations(&self) -> &[StoreOperation] {
    self.0.operations()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReceiptIdentity {
  transaction: TransactionId,
  operation_digest: Digest,
}

impl ReceiptIdentity {
  pub(super) fn from_receipt(receipt: &CommitReceipt) -> Self {
    Self {
      transaction: receipt.transaction().clone(),
      operation_digest: receipt.operation_digest().clone(),
    }
  }

  pub(super) fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  pub(super) fn operation_digest(&self) -> &Digest {
    &self.operation_digest
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReceiptReferenceToken(Digest);

impl ReceiptReferenceToken {
  #[cfg(test)]
  pub(super) const fn from_digest(digest: Digest) -> Self {
    Self(digest)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptReferenceOutcome {
  Applied(CommitReceipt),
  Aborted,
  Conflict,
  Unknown(ReceiptIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptCleanupOutcome {
  Referenced,
  Anchored(CommitReceipt),
  Retained,
  Forgotten(CommitReceipt),
  Aborted,
  Conflict,
  Unknown(ReceiptIdentity),
}

impl MetadataStore {
  pub(super) fn prepare_transaction(
    &self, id: TransactionId, base_revision: StoreRevision, caller_operations: Vec<StoreOperation>,
  ) -> crate::Result<PreparedTransaction> {
    if caller_operations
      .iter()
      .any(operation_uses_reserved_namespace)
    {
      return Err(Error::invalid_input("metadata storage reserved namespace"));
    }
    prepare_internal_transaction(id, base_revision, caller_operations)
  }

  pub(super) async fn add_receipt_reference(
    &self, target: &ReceiptIdentity, token: &ReceiptReferenceToken, operation_id: TransactionId,
  ) -> crate::Result<ReceiptReferenceOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    verify_used_marker(snapshot.as_ref(), &namespace, target.transaction()).await?;

    let head_key = reference_head_key(target.transaction())?;
    let edge_key = reference_edge_key(target.transaction(), token)?;
    let anchor_key = eligibility_anchor_key(target.transaction())?;
    let head = snapshot.get(&namespace, &head_key).await?;
    let edge = snapshot.get(&namespace, &edge_key).await?;
    let anchor = snapshot.get(&namespace, &anchor_key).await?;

    if edge.is_some() {
      let head = head.as_ref().ok_or_else(storage_corrupt)?;
      decode_reference_count(head)?;
      if anchor.is_some() {
        return Err(storage_corrupt());
      }
      return Ok(ReceiptReferenceOutcome::Conflict);
    }

    let (head_expectation, next_count) = match head.as_ref() {
      Some(value) => {
        let count = decode_reference_count(value)?;
        let next = count.checked_add(1).ok_or_else(storage_corrupt)?;
        (StoreExpectation::Exact(value.digest().clone()), next)
      }
      None => (StoreExpectation::Absent, 1),
    };

    let mut operations = Vec::new();
    operations
      .try_reserve_exact(2 + usize::from(anchor.is_some()))
      .map_err(|_| Error::resource_exhausted("receipt reference transaction"))?;
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: head_key,
      expected: head_expectation,
      value: encode_reference_count(next_count),
    });
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: edge_key,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([])),
    });
    if let Some(anchor) = anchor {
      decode_wall_time(anchor.as_bytes())?;
      operations.push(StoreOperation::Delete {
        namespace,
        key: anchor_key,
        expected: anchor.digest().clone(),
      });
    }

    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    map_reference_outcome(self.commit(prepared).await?)
  }

  pub(super) async fn remove_receipt_reference(
    &self, target: &ReceiptIdentity, token: &ReceiptReferenceToken, operation_id: TransactionId,
  ) -> crate::Result<ReceiptReferenceOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    verify_used_marker(snapshot.as_ref(), &namespace, target.transaction()).await?;

    let head_key = reference_head_key(target.transaction())?;
    let edge_key = reference_edge_key(target.transaction(), token)?;
    let anchor_key = eligibility_anchor_key(target.transaction())?;
    let head = snapshot.get(&namespace, &head_key).await?;
    let edge = snapshot.get(&namespace, &edge_key).await?;
    let anchor = snapshot.get(&namespace, &anchor_key).await?;

    let (head, edge) = match (head, edge) {
      (None, None) => return Ok(ReceiptReferenceOutcome::Conflict),
      (Some(head), None) => {
        decode_reference_count(&head)?;
        if anchor.is_some() {
          return Err(storage_corrupt());
        }
        return Ok(ReceiptReferenceOutcome::Conflict);
      }
      (None, Some(_)) => return Err(storage_corrupt()),
      (Some(head), Some(edge)) => (head, edge),
    };
    if anchor.is_some() {
      return Err(storage_corrupt());
    }
    let count = decode_reference_count(&head)?;

    let mut operations = Vec::new();
    operations
      .try_reserve_exact(2)
      .map_err(|_| Error::resource_exhausted("receipt reference transaction"))?;
    operations.push(StoreOperation::Delete {
      namespace: namespace.clone(),
      key: edge_key,
      expected: edge.digest().clone(),
    });
    if count == 1 {
      operations.push(StoreOperation::Delete {
        namespace,
        key: head_key,
        expected: head.digest().clone(),
      });
    } else {
      operations.push(StoreOperation::Put {
        namespace,
        key: head_key,
        expected: StoreExpectation::Exact(head.digest().clone()),
        value: encode_reference_count(count - 1),
      });
    }

    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    map_reference_outcome(self.commit(prepared).await?)
  }

  pub(super) async fn cleanup_receipt(
    &self, target: &ReceiptIdentity, operation_id: TransactionId,
  ) -> crate::Result<ReceiptCleanupOutcome> {
    let snapshot = self.snapshot().await?;
    let namespace = internal_namespace()?;
    verify_used_marker(snapshot.as_ref(), &namespace, target.transaction()).await?;

    let head_key = reference_head_key(target.transaction())?;
    let anchor_key = eligibility_anchor_key(target.transaction())?;
    let head = snapshot.get(&namespace, &head_key).await?;
    let anchor = snapshot.get(&namespace, &anchor_key).await?;

    if let Some(head) = head {
      decode_reference_count(&head)?;
      if anchor.is_some() {
        return Err(storage_corrupt());
      }
      return Ok(ReceiptCleanupOutcome::Referenced);
    }

    let now = self.clock.now();
    let operations = match anchor {
      None => vec![
        StoreOperation::Check {
          namespace: namespace.clone(),
          key: head_key,
          expected: StoreExpectation::Absent,
        },
        StoreOperation::Put {
          namespace,
          key: anchor_key,
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(encode_wall_time(now))),
        },
      ],
      Some(anchor) => {
        let anchored_at = decode_wall_time(anchor.as_bytes())?;
        let Some(deadline) = anchored_at.checked_add(self.receipt_retention) else {
          return Ok(ReceiptCleanupOutcome::Retained);
        };
        if now < deadline {
          return Ok(ReceiptCleanupOutcome::Retained);
        }
        vec![
          StoreOperation::Check {
            namespace: namespace.clone(),
            key: head_key,
            expected: StoreExpectation::Absent,
          },
          StoreOperation::Delete {
            namespace,
            key: anchor_key,
            expected: anchor.digest().clone(),
          },
          StoreOperation::ForgetReceipt {
            transaction: target.transaction().clone(),
            expected_operation_digest: target.operation_digest().clone(),
          },
        ]
      }
    };
    let anchoring = operations.len() == 2;
    let prepared =
      prepare_internal_transaction(operation_id, snapshot.revision().clone(), operations)?;
    match self.commit(prepared).await? {
      CommitOutcome::Committed(receipt) if anchoring => {
        Ok(ReceiptCleanupOutcome::Anchored(receipt))
      }
      CommitOutcome::Committed(receipt) => Ok(ReceiptCleanupOutcome::Forgotten(receipt)),
      CommitOutcome::Aborted => Ok(ReceiptCleanupOutcome::Aborted),
      CommitOutcome::Conflict => Ok(ReceiptCleanupOutcome::Conflict),
      CommitOutcome::Unknown {
        transaction,
        operation_digest,
      } => Ok(ReceiptCleanupOutcome::Unknown(ReceiptIdentity {
        transaction,
        operation_digest,
      })),
    }
  }
}

pub(super) fn prepare_internal_transaction(
  id: TransactionId, base_revision: StoreRevision, mut operations: Vec<StoreOperation>,
) -> crate::Result<PreparedTransaction> {
  operations
    .try_reserve_exact(1)
    .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
  operations.push(StoreOperation::Put {
    namespace: internal_namespace()?,
    key: used_id_key(&id)?,
    expected: StoreExpectation::Absent,
    value: StoreValue::new(Arc::from([])),
  });
  StoreTransaction::new(id, base_revision, operations).map(PreparedTransaction)
}

fn map_reference_outcome(outcome: CommitOutcome) -> crate::Result<ReceiptReferenceOutcome> {
  Ok(match outcome {
    CommitOutcome::Committed(receipt) => ReceiptReferenceOutcome::Applied(receipt),
    CommitOutcome::Aborted => ReceiptReferenceOutcome::Aborted,
    CommitOutcome::Conflict => ReceiptReferenceOutcome::Conflict,
    CommitOutcome::Unknown {
      transaction,
      operation_digest,
    } => ReceiptReferenceOutcome::Unknown(ReceiptIdentity {
      transaction,
      operation_digest,
    }),
  })
}

async fn verify_used_marker(
  snapshot: &dyn crate::provider::StoreSnapshot, namespace: &StoreNamespace,
  transaction: &TransactionId,
) -> crate::Result<()> {
  let marker = snapshot.get(namespace, &used_id_key(transaction)?).await?;
  match marker {
    Some(value) if value.as_bytes().is_empty() => Ok(()),
    _ => Err(storage_corrupt()),
  }
}

fn operation_uses_reserved_namespace(operation: &StoreOperation) -> bool {
  match operation {
    StoreOperation::Check { namespace, .. }
    | StoreOperation::Put { namespace, .. }
    | StoreOperation::Delete { namespace, .. } => namespace.as_str() == INTERNAL_NAMESPACE,
    StoreOperation::ForgetReceipt { .. } => true,
  }
}

pub(super) fn internal_namespace() -> crate::Result<StoreNamespace> {
  StoreNamespace::new(crate::QualifiedTag::parse(INTERNAL_NAMESPACE)?)
}

pub(super) fn used_id_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(USED_ID_TAG, transaction)
}

pub(super) fn reference_head_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(REFERENCE_HEAD_TAG, transaction)
}

pub(super) fn eligibility_anchor_key(transaction: &TransactionId) -> crate::Result<StoreKey> {
  tagged_transaction_key(ELIGIBILITY_ANCHOR_TAG, transaction)
}

fn tagged_transaction_key(tag: &[u8], transaction: &TransactionId) -> crate::Result<StoreKey> {
  let transaction = transaction.as_str().as_bytes();
  let capacity = tag
    .len()
    .checked_add(transaction.len())
    .ok_or_else(|| Error::resource_exhausted("receipt metadata key"))?;
  let mut key = Vec::new();
  key
    .try_reserve_exact(capacity)
    .map_err(|_| Error::resource_exhausted("receipt metadata key"))?;
  key.extend_from_slice(tag);
  key.extend_from_slice(transaction);
  Ok(StoreKey::new(Arc::from(key)))
}

pub(super) fn reference_edge_key(
  transaction: &TransactionId, token: &ReceiptReferenceToken,
) -> crate::Result<StoreKey> {
  let transaction = transaction.as_str().as_bytes();
  let transaction_length = u16::try_from(transaction.len())
    .map_err(|_| Error::resource_exhausted("receipt reference key"))?;
  let capacity = REFERENCE_EDGE_TAG
    .len()
    .checked_add(2)
    .and_then(|value| value.checked_add(transaction.len()))
    .and_then(|value| value.checked_add(1))
    .and_then(|value| value.checked_add(token.0.as_bytes().len()))
    .ok_or_else(|| Error::resource_exhausted("receipt reference key"))?;
  let mut key = Vec::new();
  key
    .try_reserve_exact(capacity)
    .map_err(|_| Error::resource_exhausted("receipt reference key"))?;
  key.extend_from_slice(REFERENCE_EDGE_TAG);
  key.extend_from_slice(&transaction_length.to_be_bytes());
  key.extend_from_slice(transaction);
  key.push(EDGE_DELIMITER);
  key.extend_from_slice(token.0.as_bytes());
  Ok(StoreKey::new(Arc::from(key)))
}

fn encode_reference_count(count: u64) -> StoreValue {
  StoreValue::new(Arc::from(count.to_be_bytes()))
}

fn decode_reference_count(value: &StoreValue) -> crate::Result<u64> {
  let bytes: [u8; 8] = value.as_bytes().try_into().map_err(|_| storage_corrupt())?;
  let count = u64::from_be_bytes(bytes);
  if count == 0 {
    return Err(storage_corrupt());
  }
  Ok(count)
}

pub(super) fn encode_wall_time(value: SystemTime) -> [u8; WALL_TIME_WIDTH] {
  let (sign, duration) = match value.duration_since(UNIX_EPOCH) {
    Ok(duration) => (0, duration),
    Err(error) => (1, error.duration()),
  };
  let mut encoded = [0; WALL_TIME_WIDTH];
  encoded[0] = sign;
  encoded[1..9].copy_from_slice(&duration.as_secs().to_be_bytes());
  encoded[9..13].copy_from_slice(&duration.subsec_nanos().to_be_bytes());
  encoded
}

pub(super) fn decode_wall_time(encoded: &[u8]) -> crate::Result<SystemTime> {
  if encoded.len() != WALL_TIME_WIDTH {
    return Err(storage_corrupt());
  }
  let sign = encoded[0];
  let seconds = u64::from_be_bytes(encoded[1..9].try_into().map_err(|_| storage_corrupt())?);
  let nanos = u32::from_be_bytes(encoded[9..13].try_into().map_err(|_| storage_corrupt())?);
  if nanos >= NANOS_PER_SECOND || (sign == 1 && seconds == 0 && nanos == 0) {
    return Err(storage_corrupt());
  }
  let duration = Duration::new(seconds, nanos);
  match sign {
    0 => UNIX_EPOCH.checked_add(duration).ok_or_else(storage_corrupt),
    1 => UNIX_EPOCH.checked_sub(duration).ok_or_else(storage_corrupt),
    _ => Err(storage_corrupt()),
  }
}

fn storage_corrupt() -> Error {
  Error::provider(
    ProviderErrorKind::StorageCorrupt,
    ProviderErrorContext::StorageSnapshot,
  )
}

//! Shared value-construction helpers for storage test lanes.
//!
//! The JSON adapter lane (`json/helpers.rs`) and the backend-neutral
//! contract suite (`contract.rs`) previously declared their own copies of
//! these constructors; a single definition prevents them from drifting.

use std::sync::Arc;

use crate::{QualifiedTag, StoreKey, StoreNamespace, StoreValue, TransactionId};

pub(crate) fn namespace(name: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(&format!("relay.woooo.tech/metadata/{name}")).unwrap())
    .unwrap()
}

pub(crate) fn key(bytes: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(bytes))
}

pub(crate) fn value(bytes: &[u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

#[cfg_attr(not(feature = "json"), allow(dead_code))]
pub(crate) fn transaction_id(index: u64) -> TransactionId {
  TransactionId::parse(&format!("txn_{index:021}")).unwrap()
}

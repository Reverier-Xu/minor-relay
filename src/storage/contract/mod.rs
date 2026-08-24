//! Backend-neutral storage contract suite and its reference provider.
//!
//! Split into one module per responsibility: [`reference`] holds the
//! in-memory reference provider (the oracle), [`runner`] owns the reusable
//! contract runner, [`engine`]/[`unknown`] cover the engine state machine
//! and fault recovery lanes, [`receipt_refs`] the identity receipt
//! references, [`journal`] the journaled pending transactions, and
//! [`helpers`] the shared test fixtures.

pub(crate) mod engine;
pub(crate) mod helpers;
pub(crate) mod journal;
pub(crate) mod receipt_refs;
pub(crate) mod reference;
pub(crate) mod runner;
pub(crate) mod unknown;

pub(crate) use helpers::required_capabilities;
pub(crate) use reference::ReferenceFactory;
// The contract runner is exercised by Unix-gated adapter lanes and the
// engine closure; on platforms where those lanes compile out, the
// re-export stays intentionally available for cross-platform callers.
#[allow(unused_imports)]
pub(crate) use reference::run_storage_contract;

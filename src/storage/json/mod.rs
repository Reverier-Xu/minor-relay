//! Test-only immutable JSON generation storage adapter.
//!
//! Enabled by the default `json` feature. The adapter is never selected
//! implicitly; callers construct it explicitly through
//! [`crate::adapters::json_store`]. Production consumers requiring
//! `OsCrashDurable` reject it wherever the platform directory barrier is
//! unavailable.

mod document;
mod store;

pub(crate) use store::JsonStoreFactory;

#[cfg(test)]
mod crash;
#[cfg(test)]
mod helpers;
#[cfg(test)]
mod tests;

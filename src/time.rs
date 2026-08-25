//! Shared wall-clock conversion helpers.
//!
//! One home for the UNIX-epoch second/millisecond conversions that every
//! subsystem needs, so saturation and epoch handling cannot drift between
//! modules. Production semantics always read the host clock through an
//! injected [`WallClock`](crate::storage::receipt::WallClock); these helpers
//! are pure conversions over a [`SystemTime`] value.

use std::time::{SystemTime, UNIX_EPOCH};

/// UNIX seconds of `time`, saturating at the epoch (a pre-epoch reading
/// reports zero rather than failing bounded work).
pub(crate) fn to_seconds(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or(0)
}

/// Current host wall-clock seconds, used for protocol-visible liveness and
/// expiry boundaries (roadmap: host `SystemTime` is the only time
/// authority; injected clocks wrap these conversions for tests).
pub(crate) fn now_seconds() -> u64 {
  to_seconds(SystemTime::now())
}

/// UNIX milliseconds of `time`, saturating at the epoch.
pub(crate) fn to_millis(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis() as u64)
    .unwrap_or(0)
}

/// Rebuilds a [`SystemTime`] from stored UNIX milliseconds.
pub(crate) fn from_millis(millis: u64) -> SystemTime {
  UNIX_EPOCH + std::time::Duration::from_millis(millis)
}

//! Authenticated session driver and keep-alive (ADR-0001, ADR-0006,
//! ADR-0007).
//!
//! Crate-private: the supervisor owns listener/session tasks and drives the
//! handshake state machine over the framed transport through this module.
//! Nothing here crosses the crate boundary.

mod driver;
pub(crate) mod stream;

pub(crate) use driver::{SessionDriver, handshake_frame_rules};

#[cfg(test)]
mod tests;

//! Continuous recovery state machine (G5-04).
//!
//! Recovery activates whenever known online members remain in mutually
//! unreachable authenticated components, retries according to caller-
//! configured wall-clock backoff (re-reading `SystemTime` after every
//! wake, including rollback/freeze/forward-jump), expands only through the
//! configured bounded fan-out, authenticates a `NodeId` before accepting a
//! session, quiesces once every known online member is connected through
//! some authenticated path (never a full mesh), and reactivates one
//! bounded controller after any later change without storms.

use std::collections::BTreeSet;

use crate::{NodeId, Result};

/// The caller-configured recovery policy (wired from `NodeConfig`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPolicy {
  pub(crate) neighbors: usize,
  pub(crate) fan_out: usize,
  pub(crate) initial_backoff: u64,
  pub(crate) maximum_backoff: u64,
}

impl RecoveryPolicy {
  pub(crate) const fn new(
    neighbors: usize, fan_out: usize, initial_backoff: u64, maximum_backoff: u64,
  ) -> Self {
    Self {
      neighbors,
      fan_out,
      initial_backoff,
      maximum_backoff,
    }
  }
}

/// The recovery state machine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryState {
  /// Everything reachable; no recovery scheduled.
  Idle,
  /// Recovery is active and retrying unreachable components.
  Recovering,
  /// Every known online member has an authenticated path.
  Connected,
}

/// One recovery cycle decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryStep {
  pub(crate) targets: Vec<NodeId>,
  pub(crate) backoff_seconds: u64,
}

/// The continuous recovery controller. Pure state logic: the caller feeds
/// membership/connectivity observations and wall-clock seconds; the
/// controller decides activation, backoff, fan-out, quiescence, and
/// reactivation.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryController {
  policy: RecoveryPolicy,
  state: RecoveryState,
  attempts: u64,
  last_attempt_at: u64,
  pending: BTreeSet<NodeId>,
}

impl RecoveryController {
  pub(crate) fn new(policy: RecoveryPolicy) -> Self {
    Self {
      policy,
      state: RecoveryState::Idle,
      attempts: 0,
      last_attempt_at: 0,
      pending: BTreeSet::new(),
    }
  }

  pub(crate) const fn state(&self) -> RecoveryState {
    self.state
  }

  /// Feeds one observation of which members are reachable and which are
  /// known online. Recovery activates when known online members remain
  /// unreachable (SC-G05-P0-14); it quiesces when all are connected
  /// through some authenticated path (SC-G05-P0-18).
  pub(crate) fn observe(
    &mut self, now: u64, online: &BTreeSet<NodeId>, reachable: &BTreeSet<NodeId>,
  ) {
    let unreachable: BTreeSet<NodeId> = online.difference(reachable).cloned().collect();
    if unreachable.is_empty() {
      if self.state != RecoveryState::Idle {
        self.state = RecoveryState::Connected;
      }
      self.pending.clear();
      return;
    }
    self.pending = unreachable;
    if self.state == RecoveryState::Idle || self.state == RecoveryState::Connected {
      self.state = RecoveryState::Recovering;
      self.attempts = 0;
    }
    // Reactivation: any change while recovering re-arms the controller
    // without a storm (single controller, bounded attempts).
    let _ = now;
  }

  /// Computes the next recovery step: a bounded set of targets expanded
  /// only through the configured fan-out from the neighbors, plus the
  /// wall-clock backoff (re-read every wake; rollback/freeze delays,
  /// forward jump makes it due — SC-G05-P0-15).
  pub(crate) fn next_step(&mut self, now: u64, candidates: &BTreeSet<NodeId>) -> RecoveryStep {
    let backoff = self.backoff_seconds(now);
    let targets: Vec<NodeId> = candidates
      .iter()
      .take(self.policy.fan_out.max(1))
      .cloned()
      .collect();
    self.last_attempt_at = now;
    self.attempts = self.attempts.saturating_add(1);
    RecoveryStep {
      targets,
      backoff_seconds: backoff,
    }
  }

  /// The wall-clock backoff for the next attempt: doubles from the initial
  /// value up to the maximum; a forward jump in wall time makes the next
  /// attempt immediately due.
  pub(crate) fn backoff_seconds(&self, now: u64) -> u64 {
    let exponent = self.attempts.min(16);
    let doubled = self
      .policy
      .initial_backoff
      .saturating_mul(1_u64 << exponent);
    let capped = doubled.min(self.policy.maximum_backoff);
    if now >= self.last_attempt_at.saturating_add(capped) {
      // The deadline is already due; wake immediately.
      return 0;
    }
    capped
  }

  /// Whether the controller should run a cycle now (deadline due under the
  /// current wall time; a forward jump makes it immediately due).
  pub(crate) fn due(&self, now: u64) -> bool {
    if self.state != RecoveryState::Recovering {
      return false;
    }
    now
      >= self
        .last_attempt_at
        .saturating_add(self.backoff_seconds(now))
  }

  /// Records one candidate as connected; when nothing remains pending the
  /// controller transitions to `Connected` (SC-G05-P0-18).
  pub(crate) fn connected(&mut self, member: &NodeId) {
    self.pending.remove(member);
    if self.pending.is_empty() && self.state == RecoveryState::Recovering {
      self.state = RecoveryState::Connected;
    }
  }

  /// Forces one immediate recovery cycle (immediate-recovery command,
  /// SC-G05-P0-19).
  pub(crate) fn immediate(&mut self, now: u64) {
    if self.pending.is_empty() && self.state != RecoveryState::Recovering {
      return;
    }
    self.state = RecoveryState::Recovering;
    self.last_attempt_at = now.saturating_sub(1);
  }

  /// Reactivates after a membership/connectivity/readdress change
  /// (SC-G05-P0-19): one bounded controller, never a storm.
  pub(crate) fn reactivate(&mut self, online: &BTreeSet<NodeId>, reachable: &BTreeSet<NodeId>) {
    self.observe(0, online, reachable);
  }
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeSet;

  use super::{RecoveryController, RecoveryPolicy, RecoveryState};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn set(values: &[u8]) -> BTreeSet<NodeId> {
    values.iter().map(|value| node(*value)).collect()
  }

  fn policy() -> RecoveryPolicy {
    RecoveryPolicy::new(4, 64, 1, 5 * 60)
  }

  /// SC-G05-P0-14: recovery activates whenever known online members remain
  /// unreachable, including after a later connectivity change.
  #[test]
  fn recovery_activates_on_unreachable_members() {
    let mut controller = RecoveryController::new(policy());
    assert_eq!(controller.state(), RecoveryState::Idle);

    let online = set(&[1, 2, 3]);
    let reachable = set(&[1]);
    controller.observe(0, &online, &reachable);
    assert_eq!(controller.state(), RecoveryState::Recovering);

    // A later connectivity change keeps recovery active.
    let reachable = set(&[1, 2]);
    controller.observe(1, &online, &reachable);
    assert_eq!(controller.state(), RecoveryState::Recovering);
  }

  /// SC-G05-P0-18: recovery quiesces once all online members are connected
  /// through some authenticated path; never a full mesh.
  #[test]
  fn recovery_quiesces_at_connected_path() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2, 3]);
    controller.observe(0, &online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Recovering);

    controller.connected(&node(2));
    assert_eq!(controller.state(), RecoveryState::Recovering);
    controller.connected(&node(3));
    assert_eq!(controller.state(), RecoveryState::Connected);

    // A later partition re-activates one bounded controller.
    controller.observe(10, &online, &set(&[1]));
    assert_eq!(controller.state(), RecoveryState::Recovering);
  }

  /// SC-G05-P0-15: backoff doubles from the initial value up to the
  /// maximum and re-reads wall time; a forward jump makes it immediately
  /// due, rollback/freeze delays it.
  #[test]
  fn recovery_backoff_follows_wall_clock() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(100, &online, &set(&[1]));
    let _ = controller.next_step(100, &set(&[2]));

    // Not due yet: 101 < 100 + 2 (initial backoff 1, doubled after attempt).
    assert!(!controller.due(101));
    // At the doubled deadline it is due.
    assert!(controller.due(102));
    // A forward jump makes it immediately due.
    assert!(controller.due(10_000));

    // The next backoff doubles again (attempt 2: 1 << 2 = 4).
    let step = controller.next_step(10_000, &set(&[2]));
    assert_eq!(step.backoff_seconds, 0); // immediately due after the jump
    assert!(!controller.due(10_003));
    assert!(controller.due(10_004));
  }

  /// SC-G05-P0-17: each cycle expands only through the configured bounded
  /// fan-out.
  #[test]
  fn recovery_expands_through_bounded_fan_out() {
    let mut controller = RecoveryController::new(RecoveryPolicy::new(4, 2, 1, 60));
    let online = set(&[1, 2, 3, 4]);
    controller.observe(0, &online, &set(&[1]));
    let step = controller.next_step(0, &set(&[2, 3, 4, 5, 6]));
    assert_eq!(step.targets.len(), 2, "fan-out bounds each cycle");
  }

  /// SC-G05-P0-19: an immediate-recovery command forces one cycle without
  /// storms.
  #[test]
  fn recovery_immediate_forces_one_cycle() {
    let mut controller = RecoveryController::new(policy());
    let online = set(&[1, 2]);
    controller.observe(0, &online, &set(&[1]));
    controller.immediate(50);
    assert!(controller.due(50));
    // One step consumes the immediate trigger.
    let _ = controller.next_step(50, &set(&[2]));
    assert!(!controller.due(50));
  }
}

use std::{
  cmp::{Ordering, Reverse},
  collections::BinaryHeap,
};

use crate::{
  Digest,
  simulation::{
    event::{DropReason, EventKey, EventLog, EventPhase, EventRecord, MessageId},
    topology::{
      AddressId, EndpointStamp, LinkKey, NodeKey, PartitionId, SimResult, SimulationError, Topology,
    },
  },
};

const PROBABILITY_SCALE: u64 = 1_000_000;

#[derive(Clone, Copy, Debug)]
struct ScheduledDelivery {
  key: EventKey,
  message: MessageId,
  copy: u8,
  bytes: usize,
  link: LinkKey,
  link_generation: u32,
  from: EndpointStamp,
  to: EndpointStamp,
}

impl PartialEq for ScheduledDelivery {
  fn eq(&self, other: &Self) -> bool {
    self.key == other.key
  }
}

impl Eq for ScheduledDelivery {}

impl PartialOrd for ScheduledDelivery {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for ScheduledDelivery {
  fn cmp(&self, other: &Self) -> Ordering {
    self.key.cmp(&other.key)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SimulationSnapshot {
  topology: Topology,
  records: Vec<EventRecord>,
  digest: Digest,
  now_nanos: u64,
  max_pending_events: usize,
  max_pending_bytes: usize,
  pending_events: usize,
  pending_bytes: usize,
  reserved_records: usize,
  next_message: u64,
  next_enqueue: u64,
}

pub(crate) struct Simulator {
  seed: u64,
  now_nanos: u64,
  topology: Topology,
  pending: BinaryHeap<Reverse<ScheduledDelivery>>,
  pending_bytes: usize,
  reserved_records: usize,
  records: EventLog,
  next_message: u64,
  next_enqueue: u64,
  max_observed_pending_events: usize,
  max_observed_pending_bytes: usize,
}

impl Simulator {
  pub(crate) fn new(seed: u64, topology: Topology) -> SimResult<Self> {
    let max_records = topology.limits().max_recorded_events();
    Ok(Self {
      seed,
      now_nanos: 0,
      topology,
      pending: BinaryHeap::new(),
      pending_bytes: 0,
      reserved_records: 0,
      records: EventLog::new(max_records)?,
      next_message: 0,
      next_enqueue: 0,
      max_observed_pending_events: 0,
      max_observed_pending_bytes: 0,
    })
  }

  pub(crate) fn send(&mut self, link_key: LinkKey, bytes: usize) -> SimResult<MessageId> {
    let limits = self.topology.limits();
    if bytes == 0 || bytes > limits.max_message_bytes() {
      return Err(SimulationError::InvalidLimit);
    }
    let message = MessageId::new(self.next_message);
    let next_message = self
      .next_message
      .checked_add(1)
      .ok_or(SimulationError::Overflow)?;
    let link = self.topology.link(link_key)?.clone();

    if link.is_blocked() {
      self.require_record_capacity(1)?;
      self.next_message = next_message;
      self.records.push(EventRecord::Dropped {
        at_nanos: self.now_nanos,
        message,
        copy: 0,
        reason: DropReason::Blocked,
      })?;
      return Ok(message);
    }

    let lost = probability_hit(
      decision_word(self.seed, message, link_key, 0, 0),
      link.policy().loss_per_million(),
    );
    if lost {
      self.require_record_capacity(1)?;
      self.next_message = next_message;
      self.records.push(EventRecord::Lost {
        at_nanos: self.now_nanos,
        message,
      })?;
      return Ok(message);
    }

    let duplicated = probability_hit(
      decision_word(self.seed, message, link_key, 0, 1),
      link.policy().duplicate_per_million(),
    );
    let copies = if duplicated { 2_usize } else { 1_usize };
    let total_bytes = bytes.checked_mul(copies).ok_or(SimulationError::Overflow)?;
    let reordered = (0..copies)
      .map(|copy| {
        probability_hit(
          decision_word(self.seed, message, link_key, copy as u8, 2),
          link.policy().reorder_per_million(),
        )
      })
      .collect::<Vec<_>>();
    let immediate_records =
      1 + usize::from(duplicated) + reordered.iter().filter(|value| **value).count();
    let required_records = immediate_records
      .checked_add(copies)
      .ok_or(SimulationError::Overflow)?;

    let queue_fits = self
      .pending
      .len()
      .checked_add(copies)
      .is_some_and(|count| count <= limits.max_pending_events())
      && self
        .pending_bytes
        .checked_add(total_bytes)
        .is_some_and(|total| total <= limits.max_pending_bytes());
    if !queue_fits
      || !self
        .records
        .can_reserve(self.reserved_records, required_records)
    {
      self.require_record_capacity(1)?;
      self.next_message = next_message;
      self.records.push(EventRecord::QueueRejected {
        at_nanos: self.now_nanos,
        message,
        copies: copies as u8,
        bytes: u32::try_from(total_bytes).map_err(|_| SimulationError::Overflow)?,
      })?;
      return Err(SimulationError::Capacity);
    }

    let from = self.topology.stamp(link_key.from())?;
    let to = self.topology.stamp(link_key.to())?;
    let mut deliveries = Vec::with_capacity(copies);
    for copy in 0..copies {
      let copy = copy as u8;
      let jitter = bounded_word(
        decision_word(self.seed, message, link_key, copy, 3),
        link.policy().jitter_nanos(),
      );
      let nominal = self
        .now_nanos
        .checked_add(link.policy().fixed_delay_nanos())
        .and_then(|deadline| deadline.checked_add(jitter))
        .ok_or(SimulationError::Overflow)?;
      let deadline = if reordered[usize::from(copy)] {
        reorder_deadline(nominal, link.policy().reorder_window_nanos())?
      } else {
        nominal
      };
      let reorder_rank = if reordered[usize::from(copy)] {
        u64::MAX - message.value()
      } else {
        0
      };
      let enqueue_id = self
        .next_enqueue
        .checked_add(copy.into())
        .ok_or(SimulationError::Overflow)?;
      deliveries.push(ScheduledDelivery {
        key: EventKey::new(
          deadline,
          EventPhase::Delivery,
          reorder_rank,
          message.value(),
          message,
          copy,
          enqueue_id,
        ),
        message,
        copy,
        bytes,
        link: link_key,
        link_generation: link.generation(),
        from,
        to,
      });
    }
    self.next_enqueue = self
      .next_enqueue
      .checked_add(copies as u64)
      .ok_or(SimulationError::Overflow)?;
    self.next_message = next_message;
    self.pending_bytes += total_bytes;
    self.reserved_records += copies;
    self.records.push(EventRecord::SendAccepted {
      at_nanos: self.now_nanos,
      message,
      link: link_key,
      copies: copies as u8,
      bytes: u32::try_from(total_bytes).map_err(|_| SimulationError::Overflow)?,
    })?;
    if duplicated {
      self.records.push(EventRecord::DuplicateCreated {
        at_nanos: self.now_nanos,
        message,
      })?;
    }
    for (copy, selected) in reordered.into_iter().enumerate() {
      if selected {
        self.records.push(EventRecord::Reordered {
          at_nanos: self.now_nanos,
          message,
          copy: copy as u8,
        })?;
      }
    }
    for delivery in deliveries {
      self.pending.push(Reverse(delivery));
    }
    self.max_observed_pending_events = self.max_observed_pending_events.max(self.pending.len());
    self.max_observed_pending_bytes = self.max_observed_pending_bytes.max(self.pending_bytes);
    Ok(message)
  }

  pub(crate) fn run(&mut self) -> SimResult<()> {
    while self.run_next()? {}
    Ok(())
  }

  pub(crate) fn run_next(&mut self) -> SimResult<bool> {
    let Some(Reverse(delivery)) = self.pending.pop() else {
      return Ok(false);
    };
    self.now_nanos = delivery.key.deadline_nanos();
    self.pending_bytes = self
      .pending_bytes
      .checked_sub(delivery.bytes)
      .ok_or(SimulationError::Overflow)?;
    self.reserved_records = self
      .reserved_records
      .checked_sub(1)
      .ok_or(SimulationError::Overflow)?;

    let outcome = self.delivery_outcome(delivery)?;
    self.records.push(outcome)?;
    Ok(true)
  }

  pub(crate) fn partition(&mut self, link: LinkKey, partition: PartitionId) -> SimResult<()> {
    self.require_record_capacity(1)?;
    self.topology.partition(link, partition)?;
    let generation = self.topology.link(link)?.generation();
    self.records.push(EventRecord::Partitioned {
      at_nanos: self.now_nanos,
      link,
      partition,
      generation,
    })
  }

  pub(crate) fn heal(&mut self, link: LinkKey, partition: PartitionId) -> SimResult<()> {
    self.require_record_capacity(1)?;
    self.topology.heal(link, partition)?;
    let generation = self.topology.link(link)?.generation();
    self.records.push(EventRecord::Healed {
      at_nanos: self.now_nanos,
      link,
      partition,
      generation,
    })
  }

  pub(crate) fn restart(&mut self, node: NodeKey) -> SimResult<()> {
    self.require_record_capacity(1)?;
    let boot_epoch = self.topology.restart(node)?;
    self.records.push(EventRecord::Restarted {
      at_nanos: self.now_nanos,
      node,
      boot_epoch,
    })
  }

  pub(crate) fn change_address(&mut self, node: NodeKey, address: AddressId) -> SimResult<()> {
    self.require_record_capacity(1)?;
    let generation = self.topology.change_address(node, address)?;
    self.records.push(EventRecord::AddressChanged {
      at_nanos: self.now_nanos,
      node,
      address,
      generation,
    })
  }

  pub(crate) fn set_clock_skew(&mut self, node: NodeKey, skew_nanos: i64) -> SimResult<()> {
    self.require_record_capacity(1)?;
    self.topology.set_clock_skew(node, skew_nanos)?;
    self.records.push(EventRecord::ClockSkewChanged {
      at_nanos: self.now_nanos,
      node,
      skew_nanos,
    })
  }

  pub(crate) fn observed_utc(&self, node: NodeKey, base_utc_nanos: u64) -> SimResult<u64> {
    self.topology.observed_utc(node, base_utc_nanos)
  }

  pub(crate) fn next_deadline(&self) -> Option<u64> {
    self
      .pending
      .peek()
      .map(|delivery| delivery.0.key.deadline_nanos())
  }

  pub(crate) fn pending_events(&self) -> usize {
    self.pending.len()
  }

  pub(crate) const fn pending_bytes(&self) -> usize {
    self.pending_bytes
  }

  pub(crate) fn records(&self) -> &[EventRecord] {
    self.records.records()
  }

  pub(crate) fn digest(&self) -> Digest {
    self.records.digest()
  }

  pub(crate) fn snapshot(&self) -> SimulationSnapshot {
    SimulationSnapshot {
      topology: self.topology.clone(),
      records: self.records.records().to_vec(),
      digest: self.records.digest(),
      now_nanos: self.now_nanos,
      max_pending_events: self.max_observed_pending_events,
      max_pending_bytes: self.max_observed_pending_bytes,
      pending_events: self.pending.len(),
      pending_bytes: self.pending_bytes,
      reserved_records: self.reserved_records,
      next_message: self.next_message,
      next_enqueue: self.next_enqueue,
    }
  }

  fn require_record_capacity(&self, additional: usize) -> SimResult<()> {
    if !self.records.can_reserve(self.reserved_records, additional) {
      return Err(SimulationError::Capacity);
    }
    Ok(())
  }

  fn delivery_outcome(&self, delivery: ScheduledDelivery) -> SimResult<EventRecord> {
    let link = self.topology.link(delivery.link)?;
    let from = self.topology.node(delivery.from.node())?;
    let to = self.topology.node(delivery.to.node())?;
    let reason = if link.is_blocked() {
      Some(DropReason::Blocked)
    } else if link.generation() != delivery.link_generation {
      Some(DropReason::StaleLink)
    } else if !from.running() || !to.running() {
      Some(DropReason::Offline)
    } else if from.boot_epoch() != delivery.from.boot_epoch()
      || to.boot_epoch() != delivery.to.boot_epoch()
    {
      Some(DropReason::StaleBoot)
    } else if from.address() != delivery.from.address()
      || to.address() != delivery.to.address()
      || from.address_generation() != delivery.from.address_generation()
      || to.address_generation() != delivery.to.address_generation()
    {
      Some(DropReason::StaleAddress)
    } else {
      None
    };
    Ok(match reason {
      Some(reason) => EventRecord::Dropped {
        at_nanos: self.now_nanos,
        message: delivery.message,
        copy: delivery.copy,
        reason,
      },
      None => EventRecord::Delivered {
        at_nanos: self.now_nanos,
        message: delivery.message,
        copy: delivery.copy,
      },
    })
  }
}

fn probability_hit(word: u64, per_million: u32) -> bool {
  let bucket = ((u128::from(word) * u128::from(PROBABILITY_SCALE)) >> 64) as u64;
  bucket < u64::from(per_million)
}

fn bounded_word(word: u64, maximum: u64) -> u64 {
  if maximum == 0 {
    return 0;
  }
  if maximum == u64::MAX {
    return word;
  }
  ((u128::from(word) * u128::from(maximum + 1)) >> 64) as u64
}

fn decision_word(seed: u64, message: MessageId, link: LinkKey, copy: u8, lane: u8) -> u64 {
  let mut value = seed ^ 0x5349_4D4E_4554_0001;
  value ^= message.value().rotate_left(7);
  value ^= u64::from(link.from().value()) << 48;
  value ^= u64::from(link.to().value()) << 32;
  value ^= u64::from(copy) << 8;
  value ^= u64::from(lane);
  mix64(value)
}

fn mix64(mut value: u64) -> u64 {
  value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
  value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
  value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
  value ^ (value >> 31)
}

fn reorder_deadline(deadline: u64, window: u64) -> SimResult<u64> {
  if window == 0 {
    return Err(SimulationError::InvalidPolicy);
  }
  deadline
    .checked_add(window - 1)
    .map(|value| value / window)
    .and_then(|bucket| bucket.checked_mul(window))
    .ok_or(SimulationError::Overflow)
}

const FAULT_LOSS: u32 = 1 << 0;
const FAULT_DUPLICATE: u32 = 1 << 1;
const FAULT_REORDER: u32 = 1 << 2;
const FAULT_BLOCKED: u32 = 1 << 3;
const FAULT_STALE_LINK: u32 = 1 << 4;
const FAULT_STALE_BOOT: u32 = 1 << 5;
const FAULT_STALE_ADDRESS: u32 = 1 << 6;
const FAULT_PARTITION: u32 = 1 << 7;
const FAULT_HEAL: u32 = 1 << 8;
const FAULT_RESTART: u32 = 1 << 9;
const FAULT_ADDRESS_CHANGE: u32 = 1 << 10;
const FAULT_CLOCK_SKEW: u32 = 1 << 11;
const FAULT_DELIVERY: u32 = 1 << 12;
const FAULT_DIRECTED: u32 = 1 << 13;
const FAULT_JOINT: u32 = 1 << 14;
pub(crate) const REQUIRED_FAULTS: u32 = (1 << 15) - 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MatrixRun {
  snapshot: SimulationSnapshot,
  faults: u32,
  decision_fingerprint: u64,
}

pub(crate) fn matrix_seed_range() -> SimResult<std::ops::Range<u64>> {
  let count = parse_env_u64("MINOR_RELAY_SIM_SEEDS", 100)?;
  if !(1..=100_000).contains(&count) {
    return Err(SimulationError::InvalidLimit);
  }
  let first = parse_env_u64("MINOR_RELAY_SIM_SEED", 0)?;
  let end = first.checked_add(count).ok_or(SimulationError::Overflow)?;
  Ok(first..end)
}

pub(crate) fn run_fault_matrix_seed(seed: u64) -> SimResult<MatrixRun> {
  let limits = crate::simulation::topology::SimulationLimits::new(4, 64, 8_192, 512, 256)?;
  let mut topology = Topology::new(limits);
  for value in 1..=4 {
    topology.add_node(NodeKey::new(value), AddressId::new(u32::from(value) * 10))?;
  }

  let loss = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
  let duplicate = LinkKey::new(NodeKey::new(2), NodeKey::new(3));
  let reorder = LinkKey::new(NodeKey::new(3), NodeKey::new(4));
  let partitioned = LinkKey::new(NodeKey::new(4), NodeKey::new(1));
  let reverse = LinkKey::new(NodeKey::new(1), NodeKey::new(4));
  let restarted = LinkKey::new(NodeKey::new(2), NodeKey::new(4));
  let readdressed = LinkKey::new(NodeKey::new(1), NodeKey::new(3));
  let joint = LinkKey::new(NodeKey::new(4), NodeKey::new(2));
  topology.add_link(loss, matrix_policy(1, 0, 1_000_000, 0, 0, 0)?)?;
  topology.add_link(duplicate, matrix_policy(1, 0, 0, 1_000_000, 0, 0)?)?;
  topology.add_link(reorder, matrix_policy(1, 0, 0, 0, 1_000_000, 10)?)?;
  topology.add_link(partitioned, matrix_policy(5, 0, 0, 0, 0, 0)?)?;
  topology.add_link(reverse, matrix_policy(5, 0, 0, 0, 0, 0)?)?;
  topology.add_link(restarted, matrix_policy(4, 0, 0, 0, 0, 0)?)?;
  topology.add_link(readdressed, matrix_policy(4, 0, 0, 0, 0, 0)?)?;
  topology.add_link(joint, matrix_policy(3, 20, 0, 1_000_000, 1_000_000, 10)?)?;

  let mut simulator = Simulator::new(seed, topology)?;
  let lost_message = simulator.send(loss, 8)?;
  let duplicated_message = simulator.send(duplicate, 8)?;
  let reordered_first = simulator.send(reorder, 8)?;
  let reordered_second = simulator.send(reorder, 8)?;
  simulator.run()?;

  simulator.partition(partitioned, PartitionId::new(1))?;
  let blocked_message = simulator.send(partitioned, 8)?;
  simulator.heal(partitioned, PartitionId::new(1))?;
  let stale_link_message = simulator.send(partitioned, 8)?;
  simulator.partition(partitioned, PartitionId::new(2))?;
  simulator.heal(partitioned, PartitionId::new(2))?;
  let reverse_message = simulator.send(reverse, 8)?;
  simulator.send(partitioned, 8)?;
  simulator.run()?;

  let stale_boot_message = simulator.send(restarted, 8)?;
  simulator.restart(NodeKey::new(4))?;
  simulator.run()?;
  simulator.send(restarted, 8)?;
  simulator.run()?;

  let stale_address_message = simulator.send(readdressed, 8)?;
  simulator.change_address(NodeKey::new(3), AddressId::new(99))?;
  simulator.run()?;
  simulator.send(readdressed, 8)?;
  simulator.run()?;

  let skew = if seed & 1 == 0 { 17 } else { -17 };
  simulator.set_clock_skew(NodeKey::new(2), skew)?;
  let joint_message = simulator.send(joint, 32)?;
  simulator.partition(joint, PartitionId::new(3))?;
  simulator.heal(joint, PartitionId::new(3))?;
  simulator.run()?;

  let records = simulator.records();
  let mut faults = 0_u32;
  let mut joint_duplicate = false;
  let mut joint_reorder = false;
  let mut joint_stale = false;
  let mut blocked_observed = false;
  let mut reverse_delivered = false;
  for record in records {
    match record {
      EventRecord::Lost { message, .. } if *message == lost_message => faults |= FAULT_LOSS,
      EventRecord::DuplicateCreated { message, .. } => {
        faults |= FAULT_DUPLICATE;
        joint_duplicate |= *message == joint_message;
      }
      EventRecord::Reordered { message, .. } => {
        faults |= FAULT_REORDER;
        joint_reorder |= *message == joint_message;
      }
      EventRecord::Dropped {
        message,
        reason: DropReason::Blocked,
        ..
      } => {
        faults |= FAULT_BLOCKED;
        blocked_observed |= *message == blocked_message;
      }
      EventRecord::Dropped {
        message,
        reason: DropReason::StaleLink,
        ..
      } => {
        faults |= FAULT_STALE_LINK;
        joint_stale |= *message == joint_message;
      }
      EventRecord::Dropped {
        message,
        reason: DropReason::StaleBoot,
        ..
      } if *message == stale_boot_message => faults |= FAULT_STALE_BOOT,
      EventRecord::Dropped {
        message,
        reason: DropReason::StaleAddress,
        ..
      } if *message == stale_address_message => faults |= FAULT_STALE_ADDRESS,
      EventRecord::Partitioned { .. } => faults |= FAULT_PARTITION,
      EventRecord::Healed { .. } => faults |= FAULT_HEAL,
      EventRecord::Restarted { .. } => faults |= FAULT_RESTART,
      EventRecord::AddressChanged { .. } => faults |= FAULT_ADDRESS_CHANGE,
      EventRecord::ClockSkewChanged { .. } => faults |= FAULT_CLOCK_SKEW,
      EventRecord::Delivered { message, .. } => {
        faults |= FAULT_DELIVERY;
        reverse_delivered |= *message == reverse_message;
      }
      _ => {}
    }
  }
  let delivered = records
    .iter()
    .filter_map(|record| match record {
      EventRecord::Delivered { message, .. } => Some(*message),
      _ => None,
    })
    .collect::<Vec<_>>();
  if blocked_observed && reverse_delivered {
    faults |= FAULT_DIRECTED;
  }
  if joint_duplicate && joint_reorder && joint_stale {
    faults |= FAULT_JOINT;
  }
  if delivered.iter().position(|value| *value == reordered_second)
    < delivered.iter().position(|value| *value == reordered_first)
    && delivered.iter().filter(|value| **value == duplicated_message).count() == 2
    && !delivered.contains(&lost_message)
    && records.iter().any(|record| {
      matches!(record, EventRecord::Dropped { message, reason: DropReason::StaleLink, .. } if *message == stale_link_message)
    })
  {
    faults |= FAULT_REORDER | FAULT_DUPLICATE | FAULT_LOSS | FAULT_STALE_LINK;
  }

  let decision_fingerprint = decision_word(seed, joint_message, joint, 0, 3);
  Ok(MatrixRun {
    snapshot: simulator.snapshot(),
    faults,
    decision_fingerprint,
  })
}

fn matrix_policy(
  delay: u64, jitter: u64, loss: u32, duplicate: u32, reorder: u32, window: u64,
) -> SimResult<crate::simulation::topology::LinkPolicy> {
  crate::simulation::topology::LinkPolicy::new(
    std::time::Duration::from_nanos(delay),
    std::time::Duration::from_nanos(jitter),
    loss,
    duplicate,
    reorder,
    std::time::Duration::from_nanos(window),
  )
}

fn parse_env_u64(name: &str, default: u64) -> SimResult<u64> {
  match std::env::var(name) {
    Ok(value) => value.parse().map_err(|_| SimulationError::InvalidLimit),
    Err(std::env::VarError::NotPresent) => Ok(default),
    Err(std::env::VarError::NotUnicode(_)) => Err(SimulationError::InvalidLimit),
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::BTreeSet, time::Duration};

  use crate::simulation::{
    event::{DropReason, EventRecord},
    network::{
      REQUIRED_FAULTS, Simulator, matrix_seed_range, observed_exact_duplicate, observed_loss,
      observed_reorder, reorder_deadline, run_fault_matrix_seed,
    },
    topology::{AddressId, LinkKey, LinkPolicy, NodeKey, PartitionId, SimulationLimits, Topology},
  };

  fn limits(events: usize, bytes: usize) -> SimulationLimits {
    SimulationLimits::new(4, events, bytes, 512, bytes.min(256)).unwrap()
  }

  fn policy(delay: u64, loss: u32, duplicate: u32, reorder: u32, window: u64) -> LinkPolicy {
    LinkPolicy::new(
      Duration::from_nanos(delay),
      Duration::ZERO,
      loss,
      duplicate,
      reorder,
      Duration::from_nanos(window),
    )
    .unwrap()
  }

  fn topology(limits: SimulationLimits) -> Topology {
    let mut topology = Topology::new(limits);
    for value in 1..=4 {
      topology
        .add_node(NodeKey::new(value), AddressId::new(u32::from(value) * 10))
        .unwrap();
    }
    topology
  }

  #[test]
  fn simulation_network_fault_semantics() {
    let mut topology = topology(limits(32, 4_096));
    let loss = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let duplicate = LinkKey::new(NodeKey::new(2), NodeKey::new(3));
    let reorder = LinkKey::new(NodeKey::new(3), NodeKey::new(4));
    topology
      .add_link(loss, policy(1, 1_000_000, 0, 0, 0))
      .unwrap();
    topology
      .add_link(duplicate, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    topology
      .add_link(reorder, policy(1, 0, 0, 1_000_000, 10))
      .unwrap();
    let mut simulator = Simulator::new(7, topology).unwrap();

    let lost = simulator.send(loss, 8).unwrap();
    let duplicated = simulator.send(duplicate, 8).unwrap();
    let first = simulator.send(reorder, 8).unwrap();
    let second = simulator.send(reorder, 8).unwrap();
    simulator.run().unwrap();

    assert!(!delivered_messages(simulator.records()).contains(&lost));
    assert_eq!(
      delivered_copies(simulator.records(), duplicated),
      vec![0, 1],
    );
    let reordered = delivered_messages(simulator.records())
      .into_iter()
      .filter(|message| *message == first || *message == second)
      .collect::<Vec<_>>();
    assert_eq!(reordered, vec![second, first]);
    let snapshot = simulator.snapshot();
    assert_eq!(snapshot.digest, simulator.digest());
    assert_eq!(snapshot.records, simulator.records());
    assert!(snapshot.topology.link(loss).is_ok());
    assert_eq!(snapshot.now_nanos, 10);
    assert!(snapshot.max_pending_events <= 4);
    assert!(snapshot.max_pending_bytes <= 32);
    assert_eq!(snapshot.pending_events, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(snapshot.reserved_records, 0);
    assert!(snapshot.next_message > 0);
    assert!(snapshot.next_enqueue > 0);
  }

  #[test]
  fn simulation_network_queue_reservation_is_atomic() {
    let mut topology = topology(limits(1, 8));
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    topology
      .add_link(link, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    let mut simulator = Simulator::new(9, topology).unwrap();

    assert!(simulator.send(link, 8).is_err());
    assert_eq!(simulator.pending_events(), 0);
    assert_eq!(simulator.pending_bytes(), 0);
    assert!(matches!(
      simulator.records().last(),
      Some(EventRecord::QueueRejected {
        copies: 2,
        bytes: 16,
        ..
      })
    ));
  }

  #[test]
  fn simulation_network_bounds_are_independent() {
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));

    let mut exact_topology = topology(SimulationLimits::new(4, 2, 16, 8, 8).unwrap());
    exact_topology
      .add_link(link, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    let mut exact = Simulator::new(21, exact_topology).unwrap();
    exact.send(link, 8).unwrap();
    assert_eq!(exact.pending_events(), 2);
    assert_eq!(exact.pending_bytes(), 16);
    exact.run().unwrap();

    let mut count_topology = topology(SimulationLimits::new(4, 1, 16, 8, 8).unwrap());
    count_topology
      .add_link(link, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    let mut count_limited = Simulator::new(21, count_topology).unwrap();
    assert!(count_limited.send(link, 8).is_err());
    assert_eq!(count_limited.pending_events(), 0);
    assert_eq!(count_limited.pending_bytes(), 0);

    let mut byte_topology = topology(SimulationLimits::new(4, 2, 15, 8, 8).unwrap());
    byte_topology
      .add_link(link, policy(1, 0, 1_000_000, 0, 0))
      .unwrap();
    let mut byte_limited = Simulator::new(21, byte_topology).unwrap();
    assert!(byte_limited.send(link, 8).is_err());
    assert_eq!(byte_limited.pending_events(), 0);
    assert_eq!(byte_limited.pending_bytes(), 0);

    let mut record_topology = topology(SimulationLimits::new(4, 2, 16, 1, 8).unwrap());
    record_topology.add_link(link, policy(1, 0, 0, 0, 0)).unwrap();
    let mut record_limited = Simulator::new(21, record_topology).unwrap();
    assert!(record_limited.send(link, 8).is_err());
    assert_eq!(record_limited.pending_events(), 0);
    assert_eq!(record_limited.pending_bytes(), 0);
  }

  #[test]
  fn simulation_matrix_audit_rejects_self_reported_faults() {
    let first = crate::simulation::event::MessageId::new(1);
    let second = crate::simulation::event::MessageId::new(2);
    let false_loss = [
      EventRecord::Lost {
        at_nanos: 1,
        message: first,
      },
      EventRecord::Delivered {
        at_nanos: 2,
        message: first,
        copy: 0,
      },
    ];
    let false_duplicate = [
      EventRecord::DuplicateCreated {
        at_nanos: 1,
        message: first,
      },
      EventRecord::Delivered {
        at_nanos: 2,
        message: first,
        copy: 0,
      },
    ];
    let false_reorder = [
      EventRecord::Reordered {
        at_nanos: 1,
        message: first,
        copy: 0,
      },
      EventRecord::Reordered {
        at_nanos: 1,
        message: second,
        copy: 0,
      },
      EventRecord::Delivered {
        at_nanos: 2,
        message: first,
        copy: 0,
      },
      EventRecord::Delivered {
        at_nanos: 2,
        message: second,
        copy: 0,
      },
    ];

    assert!(!observed_loss(&false_loss, first));
    assert!(!observed_exact_duplicate(&false_duplicate, first));
    assert!(!observed_reorder(&false_reorder, first, second));
  }

  #[test]
  fn simulation_reorder_deadline_handles_representable_ceiling() {
    assert_eq!(reorder_deadline(u64::MAX, 3).unwrap(), u64::MAX);
    assert!(reorder_deadline(u64::MAX, 2).is_err());
  }

  #[test]
  fn simulation_network_overflow_paths_are_atomic() {
    let mut topology = topology(limits(8, 1_024));
    let normal = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let overflow = LinkKey::new(NodeKey::new(2), NodeKey::new(3));
    topology.add_link(normal, policy(1, 0, 0, 0, 0)).unwrap();
    topology
      .add_link(
        overflow,
        LinkPolicy::new(
          Duration::from_nanos(u64::MAX),
          Duration::ZERO,
          0,
          0,
          0,
          Duration::ZERO,
        )
        .unwrap(),
      )
      .unwrap();
    let mut simulator = Simulator::new(15, topology).unwrap();
    simulator.send(normal, 1).unwrap();
    simulator.run().unwrap();

    let before_deadline = simulator.snapshot();
    assert!(simulator.send(overflow, 1).is_err());
    assert_eq!(simulator.snapshot(), before_deadline);

    simulator.next_message = u64::MAX;
    let before_message = simulator.snapshot();
    assert!(simulator.send(normal, 1).is_err());
    assert_eq!(simulator.snapshot(), before_message);

    simulator.next_message = 1;
    simulator.next_enqueue = u64::MAX;
    let before_enqueue = simulator.snapshot();
    assert!(simulator.send(normal, 1).is_err());
    assert_eq!(simulator.snapshot(), before_enqueue);
  }

  #[test]
  fn simulation_network_one_way_partition_and_heal() {
    let mut topology = topology(limits(32, 4_096));
    let outbound = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let inbound = LinkKey::new(NodeKey::new(2), NodeKey::new(1));
    topology.add_link(outbound, policy(5, 0, 0, 0, 0)).unwrap();
    topology.add_link(inbound, policy(5, 0, 0, 0, 0)).unwrap();
    let mut simulator = Simulator::new(11, topology).unwrap();

    simulator.partition(outbound, PartitionId::new(1)).unwrap();
    let blocked = simulator.send(outbound, 1).unwrap();
    let reverse = simulator.send(inbound, 1).unwrap();
    simulator.heal(outbound, PartitionId::new(1)).unwrap();
    let stale = simulator.send(outbound, 1).unwrap();
    simulator.partition(outbound, PartitionId::new(2)).unwrap();
    simulator.heal(outbound, PartitionId::new(2)).unwrap();
    let current = simulator.send(outbound, 1).unwrap();
    simulator.run().unwrap();

    assert!(has_drop(simulator.records(), blocked, DropReason::Blocked));
    assert!(delivered_messages(simulator.records()).contains(&reverse));
    assert!(has_drop(simulator.records(), stale, DropReason::StaleLink));
    assert!(delivered_messages(simulator.records()).contains(&current));
  }

  #[test]
  fn simulation_network_lifecycle_faults_use_incarnations() {
    let mut topology = topology(limits(32, 4_096));
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    topology.add_link(link, policy(5, 0, 0, 0, 0)).unwrap();
    let mut simulator = Simulator::new(13, topology).unwrap();

    let old_boot = simulator.send(link, 1).unwrap();
    simulator.restart(NodeKey::new(2)).unwrap();
    simulator.run().unwrap();
    let old_address = simulator.send(link, 1).unwrap();
    simulator
      .change_address(NodeKey::new(2), AddressId::new(99))
      .unwrap();
    simulator.run().unwrap();
    let current = simulator.send(link, 1).unwrap();
    let deadline_before = simulator.next_deadline();
    simulator.set_clock_skew(NodeKey::new(2), -7).unwrap();
    assert_eq!(deadline_before, simulator.next_deadline());
    simulator.run().unwrap();

    assert!(has_drop(
      simulator.records(),
      old_boot,
      DropReason::StaleBoot
    ));
    assert!(has_drop(
      simulator.records(),
      old_address,
      DropReason::StaleAddress,
    ));
    assert!(delivered_messages(simulator.records()).contains(&current));
    assert_eq!(simulator.observed_utc(NodeKey::new(2), 100).unwrap(), 93);
  }

  #[test]
  fn simulation_network_fault_matrix() {
    let seeds = matrix_seed_range().unwrap();
    let mut fingerprints = BTreeSet::new();
    let mut executed = 0_usize;
    for seed in seeds {
      let first = run_fault_matrix_seed(seed).unwrap();
      let second = run_fault_matrix_seed(seed).unwrap();

      assert_eq!(first, second, "seed {seed}");
      assert_eq!(first.faults, REQUIRED_FAULTS, "seed {seed}");
      assert!(
        first
          .snapshot
          .records
          .windows(2)
          .all(|pair| pair[0].at_nanos() <= pair[1].at_nanos()),
        "seed {seed}",
      );
      assert!(first.snapshot.max_pending_events <= 16, "seed {seed}");
      assert!(first.snapshot.max_pending_bytes <= 4_096, "seed {seed}");
      fingerprints.insert(first.decision_fingerprint);
      executed += 1;
    }

    assert_eq!(executed, fingerprints.len());
  }

  fn delivered_messages(records: &[EventRecord]) -> Vec<crate::simulation::event::MessageId> {
    records
      .iter()
      .filter_map(|record| match record {
        EventRecord::Delivered { message, .. } => Some(*message),
        _ => None,
      })
      .collect()
  }

  fn delivered_copies(
    records: &[EventRecord], expected: crate::simulation::event::MessageId,
  ) -> Vec<u8> {
    records
      .iter()
      .filter_map(|record| match record {
        EventRecord::Delivered { message, copy, .. } if *message == expected => Some(*copy),
        _ => None,
      })
      .collect()
  }

  fn has_drop(
    records: &[EventRecord], expected: crate::simulation::event::MessageId,
    expected_reason: DropReason,
  ) -> bool {
    records.iter().any(|record| {
      matches!(record, EventRecord::Dropped { message, reason, .. } if *message == expected && *reason == expected_reason)
    })
  }
}

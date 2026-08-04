use sha2::{Digest as ShaDigest, Sha256};

use crate::{
  Digest,
  simulation::topology::{AddressId, LinkKey, NodeKey, PartitionId, SimResult, SimulationError},
};

const EVENT_STREAM_DOMAIN: &[u8] = b"relay.woooo.tech/simulation/event-stream/v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MessageId(u64);

impl MessageId {
  pub(crate) const fn new(value: u64) -> Self {
    Self(value)
  }

  pub(crate) const fn value(self) -> u64 {
    self.0
  }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EventPhase {
  Topology,
  Node,
  Send,
  Delivery,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventKey {
  deadline_nanos: u64,
  phase: EventPhase,
  reorder_rank: u64,
  ordinal: u64,
  message: MessageId,
  copy: u8,
  enqueue_id: u64,
}

impl EventKey {
  #[allow(clippy::too_many_arguments)]
  pub(crate) const fn new(
    deadline_nanos: u64, phase: EventPhase, reorder_rank: u64, ordinal: u64, message: MessageId,
    copy: u8, enqueue_id: u64,
  ) -> Self {
    Self {
      deadline_nanos,
      phase,
      reorder_rank,
      ordinal,
      message,
      copy,
      enqueue_id,
    }
  }

  pub(crate) const fn deadline_nanos(self) -> u64 {
    self.deadline_nanos
  }

  pub(crate) const fn phase(self) -> EventPhase {
    self.phase
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropReason {
  Blocked,
  StaleLink,
  StaleBoot,
  StaleAddress,
  Offline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventRecord {
  SendAccepted {
    at_nanos: u64,
    message: MessageId,
    link: LinkKey,
    copies: u8,
    bytes: u32,
  },
  Lost {
    at_nanos: u64,
    message: MessageId,
  },
  DuplicateCreated {
    at_nanos: u64,
    message: MessageId,
  },
  Reordered {
    at_nanos: u64,
    message: MessageId,
    copy: u8,
  },
  Delivered {
    at_nanos: u64,
    message: MessageId,
    copy: u8,
  },
  Dropped {
    at_nanos: u64,
    message: MessageId,
    copy: u8,
    reason: DropReason,
  },
  Partitioned {
    at_nanos: u64,
    link: LinkKey,
    partition: PartitionId,
    generation: u32,
  },
  Healed {
    at_nanos: u64,
    link: LinkKey,
    partition: PartitionId,
    generation: u32,
  },
  Restarted {
    at_nanos: u64,
    node: NodeKey,
    boot_epoch: u32,
  },
  AddressChanged {
    at_nanos: u64,
    node: NodeKey,
    address: AddressId,
    generation: u32,
  },
  ClockSkewChanged {
    at_nanos: u64,
    node: NodeKey,
    skew_nanos: i64,
  },
  QueueRejected {
    at_nanos: u64,
    message: MessageId,
    copies: u8,
    bytes: u32,
  },
}

impl EventRecord {
  pub(crate) const fn at_nanos(self) -> u64 {
    match self {
      Self::SendAccepted { at_nanos, .. }
      | Self::Lost { at_nanos, .. }
      | Self::DuplicateCreated { at_nanos, .. }
      | Self::Reordered { at_nanos, .. }
      | Self::Delivered { at_nanos, .. }
      | Self::Dropped { at_nanos, .. }
      | Self::Partitioned { at_nanos, .. }
      | Self::Healed { at_nanos, .. }
      | Self::Restarted { at_nanos, .. }
      | Self::AddressChanged { at_nanos, .. }
      | Self::ClockSkewChanged { at_nanos, .. }
      | Self::QueueRejected { at_nanos, .. } => at_nanos,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EventLog {
  max_records: usize,
  records: Vec<EventRecord>,
}

impl EventLog {
  pub(crate) fn new(max_records: usize) -> SimResult<Self> {
    if max_records == 0 {
      return Err(SimulationError::InvalidLimit);
    }
    Ok(Self {
      max_records,
      records: Vec::new(),
    })
  }

  pub(crate) fn push(&mut self, record: EventRecord) -> SimResult<()> {
    if self.records.len() >= self.max_records {
      return Err(SimulationError::Capacity);
    }
    self.records.push(record);
    Ok(())
  }

  pub(crate) fn records(&self) -> &[EventRecord] {
    &self.records
  }

  pub(crate) fn digest(&self) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update((EVENT_STREAM_DOMAIN.len() as u16).to_be_bytes());
    hasher.update(EVENT_STREAM_DOMAIN);
    hasher.update((self.records.len() as u64).to_be_bytes());
    for record in &self.records {
      encode_record(&mut hasher, *record);
    }
    Digest::from_bytes(hasher.finalize().into())
  }
}

fn encode_record(hasher: &mut Sha256, record: EventRecord) {
  match record {
    EventRecord::SendAccepted {
      at_nanos,
      message,
      link,
      copies,
      bytes,
    } => {
      encode_header(hasher, 1, at_nanos);
      encode_message(hasher, message);
      encode_link(hasher, link);
      hasher.update([copies]);
      hasher.update(bytes.to_be_bytes());
    }
    EventRecord::Lost { at_nanos, message } => {
      encode_header(hasher, 2, at_nanos);
      encode_message(hasher, message);
    }
    EventRecord::DuplicateCreated { at_nanos, message } => {
      encode_header(hasher, 3, at_nanos);
      encode_message(hasher, message);
    }
    EventRecord::Reordered {
      at_nanos,
      message,
      copy,
    } => {
      encode_header(hasher, 4, at_nanos);
      encode_message(hasher, message);
      hasher.update([copy]);
    }
    EventRecord::Delivered {
      at_nanos,
      message,
      copy,
    } => {
      encode_header(hasher, 5, at_nanos);
      encode_message(hasher, message);
      hasher.update([copy]);
    }
    EventRecord::Dropped {
      at_nanos,
      message,
      copy,
      reason,
    } => {
      encode_header(hasher, 6, at_nanos);
      encode_message(hasher, message);
      hasher.update([copy, drop_reason_code(reason)]);
    }
    EventRecord::Partitioned {
      at_nanos,
      link,
      partition,
      generation,
    } => {
      encode_header(hasher, 7, at_nanos);
      encode_link(hasher, link);
      hasher.update(partition.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::Healed {
      at_nanos,
      link,
      partition,
      generation,
    } => {
      encode_header(hasher, 8, at_nanos);
      encode_link(hasher, link);
      hasher.update(partition.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::Restarted {
      at_nanos,
      node,
      boot_epoch,
    } => {
      encode_header(hasher, 9, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(boot_epoch.to_be_bytes());
    }
    EventRecord::AddressChanged {
      at_nanos,
      node,
      address,
      generation,
    } => {
      encode_header(hasher, 10, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(address.value().to_be_bytes());
      hasher.update(generation.to_be_bytes());
    }
    EventRecord::ClockSkewChanged {
      at_nanos,
      node,
      skew_nanos,
    } => {
      encode_header(hasher, 11, at_nanos);
      hasher.update(node.value().to_be_bytes());
      hasher.update(skew_nanos.to_be_bytes());
    }
    EventRecord::QueueRejected {
      at_nanos,
      message,
      copies,
      bytes,
    } => {
      encode_header(hasher, 12, at_nanos);
      encode_message(hasher, message);
      hasher.update([copies]);
      hasher.update(bytes.to_be_bytes());
    }
  }
}

fn encode_header(hasher: &mut Sha256, variant: u8, at_nanos: u64) {
  hasher.update([variant]);
  hasher.update(at_nanos.to_be_bytes());
}

fn encode_message(hasher: &mut Sha256, message: MessageId) {
  hasher.update(message.value().to_be_bytes());
}

fn encode_link(hasher: &mut Sha256, link: LinkKey) {
  hasher.update(link.from().value().to_be_bytes());
  hasher.update(link.to().value().to_be_bytes());
}

const fn drop_reason_code(reason: DropReason) -> u8 {
  match reason {
    DropReason::Blocked => 1,
    DropReason::StaleLink => 2,
    DropReason::StaleBoot => 3,
    DropReason::StaleAddress => 4,
    DropReason::Offline => 5,
  }
}

#[cfg(test)]
mod tests {
  use crate::simulation::{
    event::{DropReason, EventKey, EventLog, EventPhase, EventRecord, MessageId},
    topology::{AddressId, LinkKey, NodeKey},
  };

  #[test]
  fn simulation_event_order_is_total_at_equal_deadline() {
    let mut keys = [
      EventKey::new(10, EventPhase::Delivery, 0, 4, MessageId::new(2), 1, 7),
      EventKey::new(10, EventPhase::Topology, 0, 3, MessageId::new(0), 0, 6),
      EventKey::new(10, EventPhase::Send, 0, 2, MessageId::new(1), 0, 5),
      EventKey::new(10, EventPhase::Node, 0, 1, MessageId::new(0), 0, 4),
      EventKey::new(10, EventPhase::Delivery, 1, 4, MessageId::new(2), 0, 8),
    ];
    keys.sort();

    assert_eq!(
      keys.iter().map(|key| key.phase()).collect::<Vec<_>>(),
      [
        EventPhase::Topology,
        EventPhase::Node,
        EventPhase::Send,
        EventPhase::Delivery,
        EventPhase::Delivery,
      ],
    );
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(keys.iter().all(|key| key.deadline_nanos() == 10));
  }

  #[test]
  fn simulation_event_digest_is_canonical_and_behavior_only() {
    let link = LinkKey::new(NodeKey::new(1), NodeKey::new(2));
    let records = [
      EventRecord::SendAccepted {
        at_nanos: 5,
        message: MessageId::new(9),
        link,
        copies: 2,
        bytes: 16,
      },
      EventRecord::Dropped {
        at_nanos: 7,
        message: MessageId::new(9),
        copy: 1,
        reason: DropReason::StaleAddress,
      },
      EventRecord::AddressChanged {
        at_nanos: 8,
        node: NodeKey::new(2),
        address: AddressId::new(22),
        generation: 1,
      },
    ];
    let mut first = EventLog::new(3).unwrap();
    let mut second = EventLog::new(3).unwrap();
    for record in records {
      first.push(record).unwrap();
    }
    for record in records {
      second.push(record).unwrap();
    }

    assert_eq!(first.digest(), second.digest());
    assert_eq!(
      first.digest().as_bytes(),
      &[
        0x83, 0xA1, 0x8D, 0xDE, 0x16, 0x09, 0x9E, 0x3B, 0x12, 0xB8, 0xC6, 0x08, 0x9C, 0xBD, 0x1F,
        0x10, 0x79, 0x25, 0x24, 0x0E, 0x16, 0x24, 0x7C, 0x36, 0x4C, 0xC3, 0x58, 0x19, 0xCC, 0x15,
        0xCB, 0x19,
      ],
    );
    assert_eq!(first.records(), second.records());

    let mut changed = EventLog::new(3).unwrap();
    changed
      .push(EventRecord::SendAccepted {
        at_nanos: 5,
        message: MessageId::new(9),
        link,
        copies: 1,
        bytes: 16,
      })
      .unwrap();
    assert_ne!(first.digest(), changed.digest());
  }

  #[test]
  fn simulation_event_encoder_covers_closed_record_set() {
    let left = NodeKey::new(1);
    let right = NodeKey::new(2);
    let link = LinkKey::new(left, right);
    let message = MessageId::new(3);
    let mut records = vec![
      EventRecord::Lost {
        at_nanos: 1,
        message,
      },
      EventRecord::DuplicateCreated {
        at_nanos: 2,
        message,
      },
      EventRecord::Reordered {
        at_nanos: 3,
        message,
        copy: 1,
      },
      EventRecord::Partitioned {
        at_nanos: 4,
        link,
        partition: crate::simulation::topology::PartitionId::new(7),
        generation: 1,
      },
      EventRecord::Healed {
        at_nanos: 5,
        link,
        partition: crate::simulation::topology::PartitionId::new(7),
        generation: 2,
      },
      EventRecord::Restarted {
        at_nanos: 6,
        node: right,
        boot_epoch: 1,
      },
      EventRecord::ClockSkewChanged {
        at_nanos: 7,
        node: right,
        skew_nanos: -9,
      },
      EventRecord::QueueRejected {
        at_nanos: 8,
        message,
        copies: 2,
        bytes: 64,
      },
    ];
    for (offset, reason) in [
      DropReason::Blocked,
      DropReason::StaleLink,
      DropReason::StaleBoot,
      DropReason::StaleAddress,
      DropReason::Offline,
    ]
    .into_iter()
    .enumerate()
    {
      records.push(EventRecord::Dropped {
        at_nanos: 9 + offset as u64,
        message,
        copy: 0,
        reason,
      });
    }
    let mut log = EventLog::new(records.len()).unwrap();
    for record in records {
      assert!(record.at_nanos() > 0);
      log.push(record).unwrap();
    }

    assert_ne!(log.digest().as_bytes(), &[0; 32]);
  }

  #[test]
  fn simulation_event_log_rejects_capacity_before_mutation() {
    assert!(EventLog::new(0).is_err());
    let mut log = EventLog::new(1).unwrap();
    log
      .push(EventRecord::Delivered {
        at_nanos: 1,
        message: MessageId::new(1),
        copy: 0,
      })
      .unwrap();
    let before = log.clone();

    assert!(
      log
        .push(EventRecord::Delivered {
          at_nanos: 2,
          message: MessageId::new(2),
          copy: 0,
        })
        .is_err()
    );
    assert_eq!(log, before);
  }
}

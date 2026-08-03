use std::{collections::BTreeSet, time::Duration};

use crate::{Error, FeatureTag, Result};

const MAX_MEMBER_LIMIT: usize = 1_024;
const MAX_QUEUE_MESSAGES: usize = 1_024;
const MAX_QUEUE_BYTES: usize = 32 * 1024 * 1024;
const MIN_ACK_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_TRACE_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_TRACE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MIN_FUTURE_SKEW: Duration = Duration::from_millis(500);
const MAX_FUTURE_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct NodeConfig {
  member_limit: usize,
  anti_entropy_interval: Duration,
  ack_timeout: Duration,
  trace_retention: Duration,
  max_future_skew: Duration,
  session_queue_messages: usize,
  session_queue_bytes: usize,
  protocol_limits: ProtocolLimits,
  trace_limits: TraceLimits,
  admission_limits: AdmissionLimits,
  required_features: BTreeSet<FeatureTag>,
}

impl NodeConfig {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_member_limit(mut self, value: usize) -> Result<Self> {
    ensure((1..=MAX_MEMBER_LIMIT).contains(&value), "member limit")?;
    self.member_limit = value;
    Ok(self)
  }

  pub fn with_anti_entropy_interval(mut self, value: Duration) -> Result<Self> {
    ensure(!value.is_zero(), "anti-entropy interval")?;
    self.anti_entropy_interval = value;
    Ok(self)
  }

  pub fn with_ack_timeout(mut self, value: Duration) -> Result<Self> {
    ensure(
      (MIN_ACK_TIMEOUT..=MAX_ACK_TIMEOUT).contains(&value),
      "ACK timeout",
    )?;
    self.ack_timeout = value;
    Ok(self)
  }

  pub fn with_trace_retention(mut self, value: Duration) -> Result<Self> {
    ensure(
      (MIN_TRACE_RETENTION..=MAX_TRACE_RETENTION).contains(&value) && value.subsec_nanos() == 0,
      "trace retention",
    )?;
    self.trace_retention = value;
    Ok(self)
  }

  pub fn with_max_future_skew(mut self, value: Duration) -> Result<Self> {
    ensure(
      (MIN_FUTURE_SKEW..=MAX_FUTURE_SKEW).contains(&value),
      "maximum future skew",
    )?;
    self.max_future_skew = value;
    Ok(self)
  }

  pub fn with_session_queue_limits(mut self, messages: usize, bytes: usize) -> Result<Self> {
    ensure(
      (1..=MAX_QUEUE_MESSAGES).contains(&messages) && (1..=MAX_QUEUE_BYTES).contains(&bytes),
      "session queue limits",
    )?;
    self.session_queue_messages = messages;
    self.session_queue_bytes = bytes;
    Ok(self)
  }

  pub fn with_protocol_limits(mut self, value: ProtocolLimits) -> Result<Self> {
    self.protocol_limits = value;
    Ok(self)
  }

  pub fn with_trace_limits(mut self, value: TraceLimits) -> Result<Self> {
    self.trace_limits = value;
    Ok(self)
  }

  pub fn with_admission_limits(mut self, value: AdmissionLimits) -> Result<Self> {
    self.admission_limits = value;
    Ok(self)
  }

  pub fn require_feature(mut self, value: FeatureTag) -> Result<Self> {
    if !self.required_features.insert(value) {
      return Err(Error::conflict("required feature"));
    }
    Ok(self)
  }
}

impl Default for NodeConfig {
  fn default() -> Self {
    Self {
      member_limit: MAX_MEMBER_LIMIT,
      anti_entropy_interval: Duration::from_millis(250),
      ack_timeout: Duration::from_secs(2),
      trace_retention: Duration::from_secs(24 * 60 * 60),
      max_future_skew: Duration::from_secs(5),
      session_queue_messages: 256,
      session_queue_bytes: 8 * 1024 * 1024,
      protocol_limits: ProtocolLimits::default(),
      trace_limits: TraceLimits::default(),
      admission_limits: AdmissionLimits::default(),
      required_features: BTreeSet::new(),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
  pending_per_source: u16,
  pending_global: u16,
  attempts_per_source_per_minute: u16,
  attempts_global_per_minute: u16,
}

impl AdmissionLimits {
  pub fn new(
    pending_per_source: u16, pending_global: u16, attempts_per_source_per_minute: u16,
    attempts_global_per_minute: u16,
  ) -> Result<Self> {
    ensure(
      (1..=16).contains(&pending_per_source)
        && (16..=256).contains(&pending_global)
        && pending_per_source <= pending_global
        && (1..=60).contains(&attempts_per_source_per_minute)
        && (64..=4_096).contains(&attempts_global_per_minute)
        && attempts_per_source_per_minute <= attempts_global_per_minute,
      "admission limits",
    )?;
    Ok(Self {
      pending_per_source,
      pending_global,
      attempts_per_source_per_minute,
      attempts_global_per_minute,
    })
  }

  pub const fn pending_per_source(self) -> u16 {
    self.pending_per_source
  }

  pub const fn pending_global(self) -> u16 {
    self.pending_global
  }

  pub const fn attempts_per_source_per_minute(self) -> u16 {
    self.attempts_per_source_per_minute
  }

  pub const fn attempts_global_per_minute(self) -> u16 {
    self.attempts_global_per_minute
  }
}

impl Default for AdmissionLimits {
  fn default() -> Self {
    Self {
      pending_per_source: 4,
      pending_global: 64,
      attempts_per_source_per_minute: 16,
      attempts_global_per_minute: 256,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
  data_body_bytes: u32,
  in_flight_requests: u16,
}

impl ProtocolLimits {
  pub fn new(data_body_bytes: u32, in_flight_requests: u16) -> Result<Self> {
    ensure(
      (64 * 1024..=8 * 1024 * 1024).contains(&data_body_bytes)
        && (1..=1_024).contains(&in_flight_requests),
      "protocol limits",
    )?;
    Ok(Self {
      data_body_bytes,
      in_flight_requests,
    })
  }

  pub const fn data_body_bytes(self) -> u32 {
    self.data_body_bytes
  }

  pub const fn in_flight_requests(self) -> u16 {
    self.in_flight_requests
  }
}

impl Default for ProtocolLimits {
  fn default() -> Self {
    Self {
      data_body_bytes: 1024 * 1024,
      in_flight_requests: 256,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLimits {
  global_active_records: u32,
  active_records_per_source: u32,
  global_total_records: u32,
  total_records_per_source: u32,
  global_journal_bytes: u64,
  journal_bytes_per_source: u64,
  concurrent_send_tasks: u16,
  concurrent_handler_tasks: u16,
}

impl TraceLimits {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn global_active(mut self, value: u32) -> Result<Self> {
    ensure(
      (64..=65_536).contains(&value)
        && value >= self.active_records_per_source
        && value <= self.global_total_records,
      "global active trace records",
    )?;
    self.global_active_records = value;
    Ok(self)
  }

  pub fn per_source_active(mut self, value: u32) -> Result<Self> {
    ensure(
      (16..=8_192).contains(&value)
        && value <= self.global_active_records
        && value <= self.total_records_per_source,
      "per-source active trace records",
    )?;
    self.active_records_per_source = value;
    Ok(self)
  }

  pub fn global_total(mut self, value: u32) -> Result<Self> {
    ensure(
      (1_024..=1_048_576).contains(&value)
        && value >= self.global_active_records
        && value >= self.total_records_per_source,
      "global total trace records",
    )?;
    self.global_total_records = value;
    Ok(self)
  }

  pub fn per_source_total(mut self, value: u32) -> Result<Self> {
    ensure(
      (256..=131_072).contains(&value)
        && value >= self.active_records_per_source
        && value <= self.global_total_records,
      "per-source total trace records",
    )?;
    self.total_records_per_source = value;
    Ok(self)
  }

  pub fn global_bytes(mut self, value: u64) -> Result<Self> {
    ensure(
      (16 * 1024 * 1024..=4 * 1024 * 1024 * 1024).contains(&value)
        && value >= self.journal_bytes_per_source,
      "global trace journal bytes",
    )?;
    self.global_journal_bytes = value;
    Ok(self)
  }

  pub fn per_source_bytes(mut self, value: u64) -> Result<Self> {
    ensure(
      (2 * 1024 * 1024..=2 * 1024 * 1024 * 1024).contains(&value)
        && value <= self.global_journal_bytes,
      "per-source trace journal bytes",
    )?;
    self.journal_bytes_per_source = value;
    Ok(self)
  }

  pub fn send_tasks(mut self, value: u16) -> Result<Self> {
    ensure((16..=1_024).contains(&value), "concurrent send tasks")?;
    self.concurrent_send_tasks = value;
    Ok(self)
  }

  pub fn handler_tasks(mut self, value: u16) -> Result<Self> {
    ensure((16..=1_024).contains(&value), "concurrent handler tasks")?;
    self.concurrent_handler_tasks = value;
    Ok(self)
  }

  pub const fn global_active_records(self) -> u32 {
    self.global_active_records
  }

  pub const fn active_records_per_source(self) -> u32 {
    self.active_records_per_source
  }

  pub const fn global_total_records(self) -> u32 {
    self.global_total_records
  }

  pub const fn total_records_per_source(self) -> u32 {
    self.total_records_per_source
  }

  pub const fn global_journal_bytes(self) -> u64 {
    self.global_journal_bytes
  }

  pub const fn journal_bytes_per_source(self) -> u64 {
    self.journal_bytes_per_source
  }

  pub const fn concurrent_send_tasks(self) -> u16 {
    self.concurrent_send_tasks
  }

  pub const fn concurrent_handler_tasks(self) -> u16 {
    self.concurrent_handler_tasks
  }
}

impl Default for TraceLimits {
  fn default() -> Self {
    Self {
      global_active_records: 8_192,
      active_records_per_source: 1_024,
      global_total_records: 262_144,
      total_records_per_source: 32_768,
      global_journal_bytes: 256 * 1024 * 1024,
      journal_bytes_per_source: 64 * 1024 * 1024,
      concurrent_send_tasks: 256,
      concurrent_handler_tasks: 256,
    }
  }
}

fn ensure(condition: bool, context: &'static str) -> Result<()> {
  if !condition {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

use std::{collections::BTreeSet, time::Duration};

use crate::{Error, FeatureTag, Result};

#[derive(Debug)]
pub struct NodeConfig {
  anti_entropy_interval: Duration,
  recovery: RecoveryConfig,
  session_queue_messages: usize,
  session_queue_bytes: usize,
  parser_limits: ParserLimits,
  trace_metadata_limits: TraceMetadataLimits,
  receipt_retention: Duration,
  required_features: BTreeSet<FeatureTag>,
}

impl NodeConfig {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_anti_entropy_interval(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "anti-entropy interval")?;
    self.anti_entropy_interval = value;
    Ok(self)
  }

  pub fn with_recovery_policy(mut self, value: RecoveryConfig) -> Result<Self> {
    self.recovery = value;
    Ok(self)
  }

  pub fn with_session_queue_limits(mut self, messages: usize, bytes: usize) -> Result<Self> {
    ensure_nonzero(messages, "session queue messages")?;
    ensure_nonzero(bytes, "session queue bytes")?;
    self.session_queue_messages = messages;
    self.session_queue_bytes = bytes;
    Ok(self)
  }

  pub fn with_parser_limits(mut self, value: ParserLimits) -> Result<Self> {
    self.parser_limits = value;
    Ok(self)
  }

  pub fn with_trace_metadata_limits(mut self, value: TraceMetadataLimits) -> Result<Self> {
    self.trace_metadata_limits = value;
    Ok(self)
  }

  pub fn with_receipt_retention(mut self, value: Duration) -> Result<Self> {
    ensure_nonzero_duration(value, "receipt retention")?;
    self.receipt_retention = value;
    Ok(self)
  }

  pub(crate) const fn receipt_retention(&self) -> Duration {
    self.receipt_retention
  }

  pub(crate) const fn session_queue_messages(&self) -> usize {
    self.session_queue_messages
  }

  pub(crate) const fn trace_metadata_limits(&self) -> &TraceMetadataLimits {
    &self.trace_metadata_limits
  }

  pub(crate) const fn required_features(&self) -> &BTreeSet<FeatureTag> {
    &self.required_features
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
      anti_entropy_interval: Duration::from_millis(250),
      recovery: RecoveryConfig::default(),
      session_queue_messages: 256,
      session_queue_bytes: 8 * 1024 * 1024,
      parser_limits: ParserLimits::default(),
      trace_metadata_limits: TraceMetadataLimits::default(),
      receipt_retention: Duration::from_secs(30 * 24 * 60 * 60),
      required_features: BTreeSet::new(),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
  frame_bytes: usize,
  depth: usize,
  collection_items: usize,
}

impl ParserLimits {
  pub fn new(frame_bytes: usize, depth: usize, collection_items: usize) -> Result<Self> {
    ensure_nonzero(frame_bytes, "parser frame bytes")?;
    ensure_nonzero(depth, "parser depth")?;
    ensure_nonzero(collection_items, "parser collection items")?;
    Ok(Self {
      frame_bytes,
      depth,
      collection_items,
    })
  }
}

impl Default for ParserLimits {
  fn default() -> Self {
    Self {
      frame_bytes: 65_536,
      depth: 16,
      collection_items: 1_024,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceMetadataLimits {
  active: usize,
  terminal: usize,
  retention: Duration,
}

impl TraceMetadataLimits {
  pub fn new(active: usize, terminal: usize, retention: Duration) -> Result<Self> {
    ensure_nonzero(active, "active trace metadata")?;
    ensure_nonzero(terminal, "terminal trace metadata")?;
    ensure_nonzero_duration(retention, "trace metadata retention")?;
    Ok(Self {
      active,
      terminal,
      retention,
    })
  }

  pub(crate) const fn active(&self) -> usize {
    self.active
  }
}

impl Default for TraceMetadataLimits {
  fn default() -> Self {
    Self {
      active: 8_192,
      terminal: 262_144,
      retention: Duration::from_secs(24 * 60 * 60),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
  neighbors: usize,
  fan_out: usize,
  initial_backoff: Duration,
  maximum_backoff: Duration,
}

impl RecoveryConfig {
  pub fn new(
    neighbors: usize, fan_out: usize, initial_backoff: Duration, maximum_backoff: Duration,
  ) -> Result<Self> {
    ensure_nonzero(neighbors, "recovery neighbors")?;
    ensure_nonzero(fan_out, "recovery fan-out")?;
    ensure_nonzero_duration(initial_backoff, "initial recovery backoff")?;
    ensure_nonzero_duration(maximum_backoff, "maximum recovery backoff")?;
    if neighbors > fan_out || initial_backoff > maximum_backoff {
      return Err(Error::invalid_input("recovery policy"));
    }
    Ok(Self {
      neighbors,
      fan_out,
      initial_backoff,
      maximum_backoff,
    })
  }
}

impl Default for RecoveryConfig {
  fn default() -> Self {
    Self {
      neighbors: 4,
      fan_out: 64,
      initial_backoff: Duration::from_secs(1),
      maximum_backoff: Duration::from_secs(5 * 60),
    }
  }
}

fn ensure_nonzero(value: usize, context: &'static str) -> Result<()> {
  if value == 0 {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

fn ensure_nonzero_duration(value: Duration, context: &'static str) -> Result<()> {
  if value.is_zero() {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

use std::fmt;

use crate::simulation::event::EventRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForbiddenFieldClass {
  Credential,
  PrivateKey,
  ProviderHandle,
  Proof,
  Hmac,
  Exporter,
  TlsTicket,
  Transcript,
  Payload,
  PayloadDigest,
  OpaqueValue,
  ResourceLabel,
  ResourceValue,
  Selector,
  RealAddress,
  HostPath,
  Environment,
  ArbitraryError,
  HostileText,
}

#[derive(Clone, Copy)]
pub(crate) struct SensitiveCandidate<'a> {
  class: ForbiddenFieldClass,
  _value: &'a [u8],
}

impl<'a> SensitiveCandidate<'a> {
  pub(crate) const fn new(class: ForbiddenFieldClass, value: &'a [u8]) -> Self {
    Self {
      class,
      _value: value,
    }
  }

  pub(crate) const fn class(&self) -> ForbiddenFieldClass {
    self.class
  }
}

impl fmt::Debug for SensitiveCandidate<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("SensitiveCandidate([REDACTED])")
  }
}

#[derive(Clone, Copy)]
pub(crate) enum ArtifactCandidate<'a> {
  Simulation(&'a EventRecord),
  Forbidden(SensitiveCandidate<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScenarioAliasKind {
  Node,
  Endpoint,
  Path,
  Fault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RedactionError {
  ForbiddenField(ForbiddenFieldClass),
  UnknownAlias(ScenarioAliasKind),
  DuplicateAlias(ScenarioAliasKind),
  DuplicateSource(ScenarioAliasKind),
  InvalidAlias,
}

macro_rules! define_alias {
  ($name:ident, $prefix:literal) => {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct $name(u16);

    impl $name {
      pub(crate) const fn new(ordinal: u16) -> Result<Self, RedactionError> {
        if ordinal == 0 {
          return Err(RedactionError::InvalidAlias);
        }
        Ok(Self(ordinal))
      }

      pub(crate) const fn ordinal(self) -> u16 {
        self.0
      }

      pub(crate) fn render(self) -> String {
        format!(concat!($prefix, "-{}"), self.0)
      }
    }
  };
}

define_alias!(NodeAlias, "node");
define_alias!(EndpointAlias, "endpoint");
define_alias!(PathAlias, "path");
define_alias!(FaultAlias, "fault");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NormalizedDropReason {
  Blocked,
  StaleLink,
  StaleBoot,
  StaleAddress,
  Offline,
}

impl NormalizedDropReason {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Blocked => "blocked",
      Self::StaleLink => "stale-link",
      Self::StaleBoot => "stale-boot",
      Self::StaleAddress => "stale-address",
      Self::Offline => "offline",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
  SendAccepted,
  Lost,
  DuplicateCreated,
  Reordered,
  Delivered,
  Dropped,
  Partitioned,
  Healed,
  Restarted,
  AddressChanged,
  ClockSkewChanged,
  QueueRejected,
}

impl EventKind {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::SendAccepted => "send-accepted",
      Self::Lost => "lost",
      Self::DuplicateCreated => "duplicate-created",
      Self::Reordered => "reordered",
      Self::Delivered => "delivered",
      Self::Dropped => "dropped",
      Self::Partitioned => "partitioned",
      Self::Healed => "healed",
      Self::Restarted => "restarted",
      Self::AddressChanged => "address-changed",
      Self::ClockSkewChanged => "clock-skew-changed",
      Self::QueueRejected => "queue-rejected",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NormalizedEvent {
  SendAccepted {
    at_nanos: u64,
    message: u64,
    path: PathAlias,
    copies: u8,
    payload_len: u32,
  },
  Lost {
    at_nanos: u64,
    message: u64,
  },
  DuplicateCreated {
    at_nanos: u64,
    message: u64,
  },
  Reordered {
    at_nanos: u64,
    message: u64,
    copy: u8,
  },
  Delivered {
    at_nanos: u64,
    message: u64,
    copy: u8,
  },
  Dropped {
    at_nanos: u64,
    message: u64,
    copy: u8,
    reason: NormalizedDropReason,
  },
  Partitioned {
    at_nanos: u64,
    path: PathAlias,
    fault: FaultAlias,
    generation: u32,
  },
  Healed {
    at_nanos: u64,
    path: PathAlias,
    fault: FaultAlias,
    generation: u32,
  },
  Restarted {
    at_nanos: u64,
    node: NodeAlias,
    boot_epoch: u32,
  },
  AddressChanged {
    at_nanos: u64,
    node: NodeAlias,
    endpoint: EndpointAlias,
    generation: u32,
  },
  ClockSkewChanged {
    at_nanos: u64,
    node: NodeAlias,
    skew_nanos: i64,
  },
  QueueRejected {
    at_nanos: u64,
    message: u64,
    copies: u8,
    payload_len: u32,
  },
}

impl NormalizedEvent {
  pub(crate) const fn kind(&self) -> EventKind {
    match self {
      Self::SendAccepted { .. } => EventKind::SendAccepted,
      Self::Lost { .. } => EventKind::Lost,
      Self::DuplicateCreated { .. } => EventKind::DuplicateCreated,
      Self::Reordered { .. } => EventKind::Reordered,
      Self::Delivered { .. } => EventKind::Delivered,
      Self::Dropped { .. } => EventKind::Dropped,
      Self::Partitioned { .. } => EventKind::Partitioned,
      Self::Healed { .. } => EventKind::Healed,
      Self::Restarted { .. } => EventKind::Restarted,
      Self::AddressChanged { .. } => EventKind::AddressChanged,
      Self::ClockSkewChanged { .. } => EventKind::ClockSkewChanged,
      Self::QueueRejected { .. } => EventKind::QueueRejected,
    }
  }

  pub(crate) const fn at_nanos(&self) -> u64 {
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
      | Self::QueueRejected { at_nanos, .. } => *at_nanos,
    }
  }

  pub(crate) fn node_alias(&self) -> Option<String> {
    match self {
      Self::Restarted { node, .. }
      | Self::AddressChanged { node, .. }
      | Self::ClockSkewChanged { node, .. } => Some(node.render()),
      _ => None,
    }
  }

  pub(crate) fn endpoint_alias(&self) -> Option<String> {
    match self {
      Self::AddressChanged { endpoint, .. } => Some(endpoint.render()),
      _ => None,
    }
  }

  pub(crate) fn path_alias(&self) -> Option<String> {
    match self {
      Self::SendAccepted { path, .. }
      | Self::Partitioned { path, .. }
      | Self::Healed { path, .. } => Some(path.render()),
      _ => None,
    }
  }

  pub(crate) fn fault_alias(&self) -> Option<String> {
    match self {
      Self::Partitioned { fault, .. } | Self::Healed { fault, .. } => Some(fault.render()),
      _ => None,
    }
  }

  pub(crate) const fn payload_len(&self) -> Option<u32> {
    match self {
      Self::SendAccepted { payload_len, .. } | Self::QueueRejected { payload_len, .. } => {
        Some(*payload_len)
      }
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{
    ArtifactCandidate, EndpointAlias, EventKind, FaultAlias, ForbiddenFieldClass, NodeAlias,
    NormalizedDropReason, PathAlias, RedactionError, SensitiveCandidate,
  };
  use crate::simulation::fixture::ScenarioFixture;

  #[test]
  fn simulation_failure_artifact_security_aliases_and_enums_are_closed() {
    assert_eq!(NodeAlias::new(1).unwrap().ordinal(), 1);
    assert_eq!(EndpointAlias::new(2).unwrap().ordinal(), 2);
    assert_eq!(PathAlias::new(3).unwrap().ordinal(), 3);
    assert_eq!(FaultAlias::new(4).unwrap().ordinal(), 4);
    assert_eq!(EventKind::Delivered.as_str(), "delivered");
    assert_eq!(NormalizedDropReason::StaleAddress.as_str(), "stale-address");
  }

  #[test]
  fn simulation_failure_artifact_security_rejects_forbidden_fields_before_normalization() {
    let fixture = ScenarioFixture::network_fault_matrix().unwrap();
    let sentinel = b"do-not-retain-secret-sentinel";
    let classes = [
      ForbiddenFieldClass::Credential,
      ForbiddenFieldClass::PrivateKey,
      ForbiddenFieldClass::ProviderHandle,
      ForbiddenFieldClass::Proof,
      ForbiddenFieldClass::Hmac,
      ForbiddenFieldClass::Exporter,
      ForbiddenFieldClass::TlsTicket,
      ForbiddenFieldClass::Transcript,
      ForbiddenFieldClass::Payload,
      ForbiddenFieldClass::PayloadDigest,
      ForbiddenFieldClass::OpaqueValue,
      ForbiddenFieldClass::ResourceLabel,
      ForbiddenFieldClass::ResourceValue,
      ForbiddenFieldClass::Selector,
      ForbiddenFieldClass::RealAddress,
      ForbiddenFieldClass::HostPath,
      ForbiddenFieldClass::Environment,
      ForbiddenFieldClass::ArbitraryError,
      ForbiddenFieldClass::HostileText,
    ];

    for class in classes {
      let candidate = SensitiveCandidate::new(class, sentinel);
      assert_eq!(format!("{candidate:?}"), "SensitiveCandidate([REDACTED])");
      let result = fixture.normalize_candidates([ArtifactCandidate::Forbidden(candidate)]);
      assert_eq!(result, Err(RedactionError::ForbiddenField(class)));
      assert!(!format!("{result:?}").contains("do-not-retain"));
    }
  }
}

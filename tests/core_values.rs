use std::{str::FromStr, time::Duration};

use minor_relay::{
  AdmissionLimits, ClusterId, Digest, DiscoveryTag, Error, ErrorKind, EventTag, FeatureTag,
  NodeConfig, NodeId, ProtocolLimits, ProtocolTag, ProviderErrorContext, ProviderErrorKind,
  PublicKey, QualifiedTag, ResourceTag, SchemaTag, Signature, TraceId, TraceLimits, TransportTag,
};
use proptest::prelude::*;

#[test]
fn g1_core_ids_round_trip_canonical_forms() {
  let node = NodeId::parse("node_0123456789abcdefghijk").unwrap();
  let cluster = ClusterId::from_str("cluster_ZYXWVUTSRQPONMLKJIHGF").unwrap();
  let trace = TraceId::parse("trace_0123456789ABCDEFGHIJK").unwrap();

  assert_eq!(node.as_str(), "node_0123456789abcdefghijk");
  assert_eq!(cluster.to_string(), "cluster_ZYXWVUTSRQPONMLKJIHGF");
  assert_eq!(trace.as_str(), "trace_0123456789ABCDEFGHIJK");
}

#[test]
fn g1_core_ids_reject_noncanonical_forms() {
  for value in [
    "node_0123456789abcdefghij",
    "node_0123456789abcdefghijkl",
    "node_0123456789abcdefghij-",
    "node_0123456789abcdefghij_",
    "node_0123456789abcdefghié",
    " node_0123456789abcdefghijk",
    "node_0123456789abcdefghijk ",
    "Node_0123456789abcdefghijk",
    "trace_0123456789abcdefghijk",
  ] {
    let error = NodeId::parse(value).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "accepted {value:?}");
  }

  assert!(ClusterId::parse("clstr_0123456789abcdefghijk").is_err());
  assert!(TraceId::parse("trace/0123456789abcdefghijk").is_err());
}

#[test]
fn g1_core_tags_parse_canonical_namespaces_and_categories() {
  let tag = QualifiedTag::parse("relay.woooo.tech/features/session-core").unwrap();
  assert_eq!(tag.domain(), "relay.woooo.tech");
  assert_eq!(tag.category(), "features");
  assert_eq!(tag.name(), "session-core");
  assert_eq!(tag.to_string(), "relay.woooo.tech/features/session-core");

  FeatureTag::parse("relay.woooo.tech/features/session-core").unwrap();
  ProtocolTag::parse("example.com/protocols/work").unwrap();
  SchemaTag::parse("example.com/schemas/work").unwrap();
  TransportTag::parse("example.com/transports/quic").unwrap();
  DiscoveryTag::parse("example.com/discovery/local").unwrap();
  ResourceTag::parse("example.com/resources/capacity").unwrap();
  EventTag::parse("example.com/events/changed").unwrap();
  QualifiedTag::parse("example.com/crypto/custom-purpose").unwrap();

  assert!(FeatureTag::parse("example.com/protocols/work").is_err());
}

#[test]
fn g1_core_tags_reject_noncanonical_namespaces() {
  let too_long_name = "a".repeat(64);
  let too_long_tag = format!("example.com/features/{too_long_name}");
  for value in [
    "Example.com/features/work",
    "example.com./features/work",
    ".example.com/features/work",
    "example..com/features/work",
    "-example.com/features/work",
    "example-.com/features/work",
    "example.com/Features/work",
    "example.com/1features/work",
    "example.com/features/-work",
    "example.com/features/work-",
    "example.com/features/work/extra",
    "example.com//work",
    "example.com/features/wörk",
    "relay.woooo.tech/crypto/admission-grant-v1",
    too_long_tag.as_str(),
  ] {
    assert!(QualifiedTag::parse(value).is_err(), "accepted {value:?}");
  }
}

#[test]
fn g1_core_config_enforces_member_ceiling() {
  NodeConfig::new().with_member_limit(1).unwrap();
  NodeConfig::new().with_member_limit(1_024).unwrap();

  assert_eq!(
    NodeConfig::new().with_member_limit(0).unwrap_err().kind(),
    ErrorKind::InvalidInput,
  );
  assert_eq!(
    NodeConfig::new()
      .with_member_limit(1_025)
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidInput,
  );
}

#[test]
fn g1_core_provider_errors_use_closed_context() {
  let error = Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy);

  assert_eq!(error.kind(), ErrorKind::Io);
  assert_eq!(error.context(), "entropy");
  assert!(!error.to_string().contains("secret"));
}

#[test]
fn g1_core_byte_wrappers_require_explicit_access() {
  let digest = Digest::from_bytes([7; 32]);
  let public_key = PublicKey::from_bytes([8; 32]);
  let signature = Signature::from_bytes([9; 64]);

  assert_eq!(digest.as_bytes(), &[7; 32]);
  assert_eq!(public_key.as_bytes(), &[8; 32]);
  assert_eq!(signature.as_bytes(), &[9; 64]);
  assert_eq!(format!("{digest:?}"), "Digest(..)");
  assert_eq!(format!("{public_key:?}"), "PublicKey(..)");
  assert_eq!(format!("{signature:?}"), "Signature(..)");
}

#[test]
fn g1_core_limit_types_enforce_frozen_ranges() {
  let admission = AdmissionLimits::default();
  assert_eq!(admission.pending_per_source(), 4);
  assert_eq!(admission.pending_global(), 64);
  assert_eq!(admission.attempts_per_source_per_minute(), 16);
  assert_eq!(admission.attempts_global_per_minute(), 256);
  assert!(AdmissionLimits::new(0, 64, 16, 256).is_err());
  assert!(AdmissionLimits::new(4, 3, 16, 256).is_err());
  assert!(AdmissionLimits::new(4, 64, 60, 59).is_err());

  let protocol = ProtocolLimits::default();
  assert_eq!(protocol.data_body_bytes(), 1_048_576);
  assert_eq!(protocol.in_flight_requests(), 256);
  assert!(ProtocolLimits::new(65_535, 256).is_err());
  assert!(ProtocolLimits::new(8_388_609, 256).is_err());
  assert!(ProtocolLimits::new(1_048_576, 0).is_err());
  assert!(ProtocolLimits::new(1_048_576, 1_025).is_err());

  let trace = TraceLimits::default();
  assert_eq!(trace.global_active_records(), 8_192);
  assert_eq!(trace.active_records_per_source(), 1_024);
  assert_eq!(trace.global_total_records(), 262_144);
  assert_eq!(trace.total_records_per_source(), 32_768);
  assert_eq!(trace.global_journal_bytes(), 268_435_456);
  assert_eq!(trace.journal_bytes_per_source(), 67_108_864);
  assert_eq!(trace.concurrent_send_tasks(), 256);
  assert_eq!(trace.concurrent_handler_tasks(), 256);
  assert!(TraceLimits::new().global_active(63).is_err());
  assert!(TraceLimits::new().send_tasks(1_025).is_err());
}

#[test]
fn g1_core_node_config_validates_all_owned_knobs() {
  let required = FeatureTag::parse("example.com/features/work").unwrap();
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(250))
    .unwrap()
    .with_ack_timeout(Duration::from_millis(250))
    .unwrap()
    .with_trace_retention(Duration::from_secs(600))
    .unwrap()
    .with_max_future_skew(Duration::from_millis(500))
    .unwrap()
    .with_session_queue_limits(1_024, 33_554_432)
    .unwrap()
    .with_protocol_limits(ProtocolLimits::default())
    .unwrap()
    .with_trace_limits(TraceLimits::default())
    .unwrap()
    .with_admission_limits(AdmissionLimits::default())
    .unwrap()
    .require_feature(required.clone())
    .unwrap();

  assert!(config.require_feature(required).is_err());
  assert!(
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::ZERO)
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_ack_timeout(Duration::from_millis(249))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_trace_retention(Duration::from_secs(599))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_trace_retention(Duration::from_millis(600_001))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_max_future_skew(Duration::from_millis(499))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_session_queue_limits(1_025, 1)
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_session_queue_limits(1, 33_554_433)
      .is_err()
  );
}

#[test]
fn g1_core_admission_and_protocol_boundaries_are_closed() {
  AdmissionLimits::new(1, 16, 1, 64).unwrap();
  AdmissionLimits::new(16, 256, 60, 4_096).unwrap();
  for values in [
    (0, 16, 1, 64),
    (17, 256, 1, 64),
    (1, 15, 1, 64),
    (1, 257, 1, 64),
    (1, 16, 0, 64),
    (1, 16, 61, 64),
    (1, 16, 1, 63),
    (1, 16, 1, 4_097),
  ] {
    assert!(AdmissionLimits::new(values.0, values.1, values.2, values.3).is_err());
  }

  ProtocolLimits::new(65_536, 1).unwrap();
  ProtocolLimits::new(8_388_608, 1_024).unwrap();
  assert!(ProtocolLimits::new(65_535, 1).is_err());
  assert!(ProtocolLimits::new(8_388_609, 1).is_err());
  assert!(ProtocolLimits::new(65_536, 0).is_err());
  assert!(ProtocolLimits::new(65_536, 1_025).is_err());
}

#[test]
fn g1_core_trace_limit_boundaries_are_closed() {
  TraceLimits::new()
    .per_source_active(16)
    .unwrap()
    .global_active(64)
    .unwrap();
  TraceLimits::new().global_active(65_536).unwrap();
  assert!(TraceLimits::new().global_active(65_537).is_err());
  assert!(TraceLimits::new().per_source_active(15).is_err());
  TraceLimits::new().per_source_active(8_192).unwrap();
  assert!(TraceLimits::new().per_source_active(8_193).is_err());

  TraceLimits::new()
    .per_source_active(16)
    .unwrap()
    .global_active(64)
    .unwrap()
    .per_source_total(256)
    .unwrap()
    .global_total(1_024)
    .unwrap();
  TraceLimits::new().global_total(1_048_576).unwrap();
  assert!(TraceLimits::new().global_total(1_048_577).is_err());
  assert!(TraceLimits::new().per_source_total(255).is_err());
  TraceLimits::new().per_source_total(131_072).unwrap();
  assert!(TraceLimits::new().per_source_total(131_073).is_err());

  TraceLimits::new()
    .per_source_bytes(2_097_152)
    .unwrap()
    .global_bytes(16_777_216)
    .unwrap();
  TraceLimits::new().global_bytes(4_294_967_296).unwrap();
  assert!(TraceLimits::new().global_bytes(4_294_967_297).is_err());
  assert!(TraceLimits::new().per_source_bytes(2_097_151).is_err());
  TraceLimits::new()
    .global_bytes(4_294_967_296)
    .unwrap()
    .per_source_bytes(2_147_483_648)
    .unwrap();
  assert!(TraceLimits::new().per_source_bytes(2_147_483_649).is_err());

  TraceLimits::new()
    .send_tasks(16)
    .unwrap()
    .send_tasks(1_024)
    .unwrap();
  assert!(TraceLimits::new().send_tasks(15).is_err());
  assert!(TraceLimits::new().send_tasks(1_025).is_err());
  TraceLimits::new()
    .handler_tasks(16)
    .unwrap()
    .handler_tasks(1_024)
    .unwrap();
  assert!(TraceLimits::new().handler_tasks(15).is_err());
  assert!(TraceLimits::new().handler_tasks(1_025).is_err());
}

#[test]
fn g1_core_trace_limits_reject_cross_field_inversions() {
  let small = TraceLimits::new()
    .per_source_active(16)
    .unwrap()
    .global_active(64)
    .unwrap()
    .per_source_total(256)
    .unwrap()
    .global_total(1_024)
    .unwrap()
    .per_source_bytes(2_097_152)
    .unwrap()
    .global_bytes(16_777_216)
    .unwrap();

  assert!(small.global_active(15).is_err());
  assert!(small.per_source_active(65).is_err());
  assert!(small.global_active(1_025).is_err());
  assert!(small.per_source_active(257).is_err());
  assert!(small.global_total(255).is_err());
  assert!(small.per_source_total(1_025).is_err());
  assert!(small.global_bytes(2_097_151).is_err());
  assert!(small.per_source_bytes(16_777_217).is_err());
}

#[test]
fn g1_core_node_duration_and_queue_boundaries_are_closed() {
  NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_nanos(1))
    .unwrap();
  assert!(
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::ZERO)
      .is_err()
  );

  NodeConfig::new()
    .with_ack_timeout(Duration::from_millis(250))
    .unwrap();
  NodeConfig::new()
    .with_ack_timeout(Duration::from_secs(30))
    .unwrap();
  assert!(
    NodeConfig::new()
      .with_ack_timeout(Duration::from_millis(249))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_ack_timeout(Duration::from_millis(30_001))
      .is_err()
  );

  NodeConfig::new()
    .with_trace_retention(Duration::from_secs(600))
    .unwrap();
  NodeConfig::new()
    .with_trace_retention(Duration::from_secs(2_592_000))
    .unwrap();
  assert!(
    NodeConfig::new()
      .with_trace_retention(Duration::from_secs(599))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_trace_retention(Duration::from_secs(2_592_001))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_trace_retention(Duration::from_millis(600_001))
      .is_err()
  );

  NodeConfig::new()
    .with_max_future_skew(Duration::from_millis(500))
    .unwrap();
  NodeConfig::new()
    .with_max_future_skew(Duration::from_secs(60))
    .unwrap();
  assert!(
    NodeConfig::new()
      .with_max_future_skew(Duration::from_millis(499))
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_max_future_skew(Duration::from_millis(60_001))
      .is_err()
  );

  NodeConfig::new().with_session_queue_limits(1, 1).unwrap();
  NodeConfig::new()
    .with_session_queue_limits(1_024, 33_554_432)
    .unwrap();
  assert!(NodeConfig::new().with_session_queue_limits(0, 1).is_err());
  assert!(NodeConfig::new().with_session_queue_limits(1, 0).is_err());
  assert!(
    NodeConfig::new()
      .with_session_queue_limits(1_025, 1)
      .is_err()
  );
  assert!(
    NodeConfig::new()
      .with_session_queue_limits(1, 33_554_433)
      .is_err()
  );
}

proptest! {
  #[test]
  fn g1_core_generated_ids_round_trip(suffix in "[0-9a-zA-Z]{21}") {
    let node = format!("node_{suffix}");
    let cluster = format!("cluster_{suffix}");
    let trace = format!("trace_{suffix}");

    let parsed_node = NodeId::parse(&node).unwrap();
    let parsed_cluster = ClusterId::parse(&cluster).unwrap();
    let parsed_trace = TraceId::parse(&trace).unwrap();
    prop_assert_eq!(parsed_node.as_str(), node.as_str());
    prop_assert_eq!(parsed_cluster.as_str(), cluster.as_str());
    prop_assert_eq!(parsed_trace.as_str(), trace.as_str());
  }

  #[test]
  fn g1_core_generated_tags_round_trip(
    owner in "[a-z][a-z0-9]{0,7}",
    label in "[a-z][a-z0-9]{0,7}",
    name in "[a-z][a-z0-9-]{0,15}[a-z0-9]",
  ) {
    let value = format!("{owner}.{label}/features/{name}");
    let tag = QualifiedTag::parse(&value).unwrap();

    prop_assert_eq!(tag.as_str(), value.as_str());
    prop_assert!(FeatureTag::parse(&value).is_ok());
  }

  #[test]
  fn g1_core_generated_ids_and_tags_reject_mutations(
    suffix in "[0-9a-zA-Z]{21}",
    owner in "[a-z]{1,8}",
    name in "[a-z]{1,8}",
  ) {
    let invalid_id = format!("node_{}!", suffix);
    let invalid_tag = format!("{}.com/features/{}", owner.to_uppercase(), name);
    prop_assert!(NodeId::parse(&invalid_id).is_err());
    prop_assert!(QualifiedTag::parse(&invalid_tag).is_err());
  }
}

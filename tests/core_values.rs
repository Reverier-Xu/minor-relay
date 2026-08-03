use std::str::FromStr;

use minor_relay::{
  ClusterId, DiscoveryTag, Error, ErrorKind, EventTag, FeatureTag, NodeConfig, NodeId,
  ProtocolTag, ProviderErrorContext, ProviderErrorKind, QualifiedTag, ResourceTag, SchemaTag,
  TraceId, TransportTag,
};

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

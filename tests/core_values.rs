use std::str::FromStr;

use minor_relay::{ClusterId, ErrorKind, NodeId, TraceId};

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

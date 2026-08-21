//! Packet-stream wire frames under base schema `0x0001` (ADR-0002,
//! ADR-0007).
//!
//! Four deterministic-CBOR bodies ride the closed kind registry's packet
//! kinds (`0x0010..=0x0013`): open carries the trace ID, both
//! session-authenticated endpoints, the protocol tag, and the bounded
//! canonical metadata map; chunk carries an ordered sequence number and up
//! to [`MAX_CHUNK_BYTES`] payload bytes; end terminates a stream; ack
//! reports current-process admission or a typed rejection. Every decoder
//! re-encodes and byte-compares so noncanonical encodings fail closed.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::{MAX_CHUNK_BYTES, PacketMetadata};
use crate::{
  Error, NodeId, ProtocolTag, Result, TraceId,
  protocol::{CborLimits, decode_canonical, encode_canonical, offer::OFFER_CBOR_LIMITS},
};

/// Packet frames share the authentication phase's frame budget: one frame
/// never exceeds the 64 KiB handshake control limit.
const PACKET_CBOR_LIMITS: CborLimits = OFFER_CBOR_LIMITS;

/// The wire admission outcome of one open frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckStatus {
  /// Admitted to the destination's bounded incoming stream.
  Admitted,
  /// Rejected before admission: protocol tag or owning feature unknown.
  Unsupported,
  /// Rejected before admission: the bounded incoming queue is saturated.
  Overloaded,
}

impl AckStatus {
  const fn code(self) -> u8 {
    match self {
      Self::Admitted => 0,
      Self::Unsupported => 1,
      Self::Overloaded => 2,
    }
  }

  fn from_code(code: u8) -> Option<Self> {
    match code {
      0 => Some(Self::Admitted),
      1 => Some(Self::Unsupported),
      2 => Some(Self::Overloaded),
      _ => None,
    }
  }
}

/// A decoded packet-open frame.
#[derive(Clone, Debug)]
pub(crate) struct OpenFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) source: NodeId,
  pub(crate) destination: NodeId,
  pub(crate) protocol: ProtocolTag,
  pub(crate) metadata: PacketMetadata,
}

/// A decoded packet-ack frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AckFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) status: AckStatus,
  /// Milliseconds since the Unix epoch at the destination's admission.
  pub(crate) admitted_at_millis: u64,
}

/// A decoded packet-chunk frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) sequence: u64,
  pub(crate) bytes: ByteVec,
}

/// A decoded packet-end frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndFrame {
  pub(crate) trace_id: TraceId,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct OpenWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  source: String,
  #[n(2)]
  destination: String,
  #[n(3)]
  protocol: String,
  /// Canonical metadata: key/value pairs sorted by key text, unique keys.
  #[n(4)]
  metadata: Vec<(String, ByteVec)>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ChunkWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  sequence: u64,
  #[n(2)]
  bytes: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct EndWire {
  #[n(0)]
  trace_id: String,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct AckWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  outcome: u8,
  #[n(2)]
  admitted_at_millis: u64,
}

/// Encodes one packet-open frame body.
pub(crate) fn encode_open(frame: &OpenFrame) -> Result<Vec<u8>> {
  let metadata = frame
    .metadata
    .entries()
    .map(|(key, value)| (key.as_str().to_owned(), ByteVec::from(value.to_vec())))
    .collect();
  encode_canonical(
    &OpenWire {
      trace_id: frame.trace_id.to_string(),
      source: frame.source.to_string(),
      destination: frame.destination.to_string(),
      protocol: frame.protocol.to_string(),
      metadata,
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-open frame body, enforcing canonical encoding,
/// canonical metadata ordering, and the bounded metadata map.
pub(crate) fn decode_open(body: &[u8]) -> Result<OpenFrame> {
  let wire: OpenWire = decode_checked(body)?;
  if !wire.metadata.windows(2).all(|pair| pair[0].0 < pair[1].0) {
    return Err(Error::invalid_input("packet metadata order"));
  }
  let mut metadata = PacketMetadata::new();
  for (key, value) in wire.metadata {
    metadata = metadata.insert(key.parse()?, Arc::from(value.as_slice()))?;
  }
  Ok(OpenFrame {
    trace_id: wire.trace_id.parse()?,
    source: wire.source.parse()?,
    destination: wire.destination.parse()?,
    protocol: wire.protocol.parse()?,
    metadata,
  })
}

/// Encodes one packet-chunk frame body. Chunks above the streaming quantum
/// are rejected before encoding.
pub(crate) fn encode_chunk(frame: &ChunkFrame) -> Result<Vec<u8>> {
  if frame.bytes.len() > MAX_CHUNK_BYTES {
    return Err(Error::invalid_input("packet chunk"));
  }
  encode_canonical(
    &ChunkWire {
      trace_id: frame.trace_id.to_string(),
      sequence: frame.sequence,
      bytes: frame.bytes.clone(),
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-chunk frame body, enforcing the streaming quantum.
pub(crate) fn decode_chunk(body: &[u8]) -> Result<ChunkFrame> {
  let wire: ChunkWire = decode_checked(body)?;
  if wire.bytes.len() > MAX_CHUNK_BYTES {
    return Err(Error::invalid_input("packet chunk"));
  }
  Ok(ChunkFrame {
    trace_id: wire.trace_id.parse()?,
    sequence: wire.sequence,
    bytes: wire.bytes,
  })
}

/// Encodes one packet-end frame body.
pub(crate) fn encode_end(frame: &EndFrame) -> Result<Vec<u8>> {
  encode_canonical(
    &EndWire {
      trace_id: frame.trace_id.to_string(),
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-end frame body.
pub(crate) fn decode_end(body: &[u8]) -> Result<EndFrame> {
  let wire: EndWire = decode_checked(body)?;
  Ok(EndFrame {
    trace_id: wire.trace_id.parse()?,
  })
}

/// Encodes one packet-ack frame body.
pub(crate) fn encode_ack(frame: &AckFrame) -> Result<Vec<u8>> {
  encode_canonical(
    &AckWire {
      trace_id: frame.trace_id.to_string(),
      outcome: frame.status.code(),
      admitted_at_millis: frame.admitted_at_millis,
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-ack frame body. Unknown outcome codes fail closed.
pub(crate) fn decode_ack(body: &[u8]) -> Result<AckFrame> {
  let wire: AckWire = decode_checked(body)?;
  let status =
    AckStatus::from_code(wire.outcome).ok_or_else(|| Error::invalid_input("packet ack outcome"))?;
  Ok(AckFrame {
    trace_id: wire.trace_id.parse()?,
    status,
    admitted_at_millis: wire.admitted_at_millis,
  })
}

/// Decodes and re-encodes one frame body; any deviation from the
/// deterministic canonical encoding is rejected.
fn decode_checked<'a, T>(body: &'a [u8]) -> Result<T>
where
  T: Decode<'a, ()> + Encode<()>, {
  let wire: T = decode_canonical(body, PACKET_CBOR_LIMITS)?;
  if encode_canonical(&wire, PACKET_CBOR_LIMITS)? != body {
    return Err(Error::invalid_input("packet frame canonical"));
  }
  Ok(wire)
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use minicbor::bytes::ByteVec;

  use super::{
    AckFrame, AckStatus, ChunkFrame, EndFrame, MAX_CHUNK_BYTES, OpenFrame, decode_ack,
    decode_chunk, decode_end, decode_open, encode_ack, encode_chunk, encode_end, encode_open,
  };
  use crate::{
    ErrorKind, NodeId, PacketMetadata, ProtocolTag, TraceId,
    protocol::{encode_canonical, offer::OFFER_CBOR_LIMITS},
  };

  fn ids() -> (TraceId, NodeId, NodeId) {
    (
      TraceId::parse("trace_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000002").unwrap(),
    )
  }

  fn open_frame() -> OpenFrame {
    let (trace_id, source, destination) = ids();
    let metadata = PacketMetadata::new()
      .insert(
        "relay.woooo.tech/labels/alpha".parse().unwrap(),
        Arc::from(&b"one"[..]),
      )
      .unwrap()
      .insert(
        "relay.woooo.tech/labels/beta".parse().unwrap(),
        Arc::from(&b"two"[..]),
      )
      .unwrap();
    OpenFrame {
      trace_id,
      source,
      destination,
      protocol: ProtocolTag::parse("relay.woooo.tech/protocols/test-packets").unwrap(),
      metadata,
    }
  }

  #[test]
  fn tls_transport_packet_open_frame_round_trips_canonically() {
    let frame = open_frame();
    let body = encode_open(&frame).unwrap();
    let decoded = decode_open(&body).unwrap();
    assert_eq!(decoded.trace_id, frame.trace_id);
    assert_eq!(decoded.source, frame.source);
    assert_eq!(decoded.destination, frame.destination);
    assert_eq!(decoded.protocol, frame.protocol);
    assert_eq!(decoded.metadata, frame.metadata);
    assert_eq!(encode_open(&decoded).unwrap(), body);
  }

  #[test]
  fn tls_transport_packet_open_frame_rejects_unordered_metadata() {
    let (trace_id, source, destination) = ids();
    let wire = super::OpenWire {
      trace_id: trace_id.to_string(),
      source: source.to_string(),
      destination: destination.to_string(),
      protocol: "relay.woooo.tech/protocols/test-packets".to_owned(),
      metadata: vec![
        (
          "relay.woooo.tech/labels/zeta".to_owned(),
          ByteVec::from(b"1".to_vec()),
        ),
        (
          "relay.woooo.tech/labels/alpha".to_owned(),
          ByteVec::from(b"2".to_vec()),
        ),
      ],
    };
    let body = encode_canonical(&wire, OFFER_CBOR_LIMITS).unwrap();
    let error = decode_open(&body).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_packet_open_frame_rejects_noncanonical_padding() {
    let body = encode_open(&open_frame()).unwrap();
    let mut padded = body.clone();
    padded.push(0);
    assert!(decode_open(&padded).is_err());
    let mut truncated = body;
    truncated.pop();
    assert!(decode_open(&truncated).is_err());
  }

  #[test]
  fn tls_transport_packet_chunk_frame_round_trips_and_enforces_quantum() {
    let (trace_id, ..) = ids();
    let frame = ChunkFrame {
      trace_id: trace_id.clone(),
      sequence: 7,
      bytes: ByteVec::from(vec![0xAB; 1_024]),
    };
    let body = encode_chunk(&frame).unwrap();
    let decoded = decode_chunk(&body).unwrap();
    assert_eq!(decoded, frame);

    let oversize = ChunkFrame {
      trace_id: trace_id.clone(),
      sequence: 8,
      bytes: ByteVec::from(vec![0xAB; MAX_CHUNK_BYTES + 1]),
    };
    let error = encode_chunk(&oversize).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    // A hand-encoded oversize chunk (bypassing the encoder) is rejected at
    // decode as well.
    let wire = super::ChunkWire {
      trace_id: trace_id.to_string(),
      sequence: 9,
      bytes: ByteVec::from(vec![0xAB; MAX_CHUNK_BYTES + 1]),
    };
    let body = encode_canonical(&wire, OFFER_CBOR_LIMITS).unwrap();
    let error = decode_chunk(&body).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_packet_end_and_ack_frames_round_trip() {
    let (trace_id, ..) = ids();
    let end = EndFrame {
      trace_id: trace_id.clone(),
    };
    let decoded = decode_end(&encode_end(&end).unwrap()).unwrap();
    assert_eq!(decoded, end);

    for status in [
      AckStatus::Admitted,
      AckStatus::Unsupported,
      AckStatus::Overloaded,
    ] {
      let ack = AckFrame {
        trace_id: trace_id.clone(),
        status,
        admitted_at_millis: 1_700_000_000_000,
      };
      let decoded = decode_ack(&encode_ack(&ack).unwrap()).unwrap();
      assert_eq!(decoded, ack);
    }
  }

  #[test]
  fn tls_transport_packet_ack_rejects_unknown_outcome() {
    let (trace_id, ..) = ids();
    let wire = super::AckWire {
      trace_id: trace_id.to_string(),
      outcome: 9,
      admitted_at_millis: 0,
    };
    let body = encode_canonical(&wire, OFFER_CBOR_LIMITS).unwrap();
    let error = decode_ack(&body).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_packet_frames_reject_malformed_ids() {
    let wire = super::EndWire {
      trace_id: "trace_NOT-CANONICAL".to_owned(),
    };
    let body = encode_canonical(&wire, OFFER_CBOR_LIMITS).unwrap();
    let error = decode_end(&body).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let wire = super::OpenWire {
      trace_id: "trace_000000000000000000001".to_owned(),
      source: "node_000000000000000000001".to_owned(),
      destination: "node_000000000000000000002".to_owned(),
      protocol: "relay.woooo.tech/features/not-a-protocol".to_owned(),
      metadata: Vec::new(),
    };
    let body = encode_canonical(&wire, OFFER_CBOR_LIMITS).unwrap();
    let error = decode_open(&body).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_decode_checked_rejects_wrong_type() {
    // A chunk body is not a valid end frame even though both are arrays.
    let (trace_id, ..) = ids();
    let chunk = ChunkFrame {
      trace_id,
      sequence: 0,
      bytes: ByteVec::from(b"payload".to_vec()),
    };
    let body = encode_chunk(&chunk).unwrap();
    assert!(decode_end(&body).is_err());
  }
}

//! Closed wire kind registry for base schema `0x0001` (ADR-0002).
//!
//! A `kind_id` identifies one exact message schema in the deterministic-CBOR
//! base decoder. IDs are immutable and never reused once published. The
//! registry is closed and correctness-critical: unknown kinds and duplicate
//! IDs are rejected before body dispatch, and golden fixtures pin every
//! published schema/kind pair.
//!
//! This phase publishes the six authentication handshake kinds. Positions
//! one through five are the strict lockstep authentication exchange;
//! position six is the join-only post-authentication admission grant
//! delivery. The four packet-stream kinds carry the ADR-0007 opaque packet
//! data plane over an established authenticated session: open (trace,
//! endpoints, protocol tag, metadata), ordered chunks, end, and the
//! current-process admission acknowledgement.

/// The deterministic-CBOR base schema ID (ADR-0002).
pub(crate) const BASE_SCHEMA_ID: u16 = 0x0001;

/// One published handshake message kind of base schema `0x0001`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeKind {
  /// Position 1 (initiator): mode, generation, cluster, identity hello.
  InitiatorHello,
  /// Position 2 (responder): identity hello answering position 1.
  ResponderHello,
  /// Position 3 (responder): credential proof and identity signature.
  ResponderProof,
  /// Position 4 (initiator): credential proof and identity signature.
  InitiatorProof,
  /// Position 5 (responder): exact selection bytes; completes authentication.
  SelectionConfirmation,
  /// Position 6 (responder, join mode only): post-authentication admission
  /// grant delivery. Never part of the authentication transcript.
  AdmissionGrantDelivery,
}

impl HandshakeKind {
  /// Every published handshake kind, in protocol position order.
  pub(crate) const ALL: [Self; 6] = [
    Self::InitiatorHello,
    Self::ResponderHello,
    Self::ResponderProof,
    Self::InitiatorProof,
    Self::SelectionConfirmation,
    Self::AdmissionGrantDelivery,
  ];

  /// The immutable kind ID under base schema `0x0001`.
  pub(crate) const fn kind_id(self) -> u16 {
    match self {
      Self::InitiatorHello => 0x0001,
      Self::ResponderHello => 0x0002,
      Self::ResponderProof => 0x0003,
      Self::InitiatorProof => 0x0004,
      Self::SelectionConfirmation => 0x0005,
      Self::AdmissionGrantDelivery => 0x0006,
    }
  }
}

/// One published packet-stream message kind of base schema `0x0001`
/// (ADR-0007).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketKind {
  /// Opens one directed packet stream: trace ID, authenticated endpoints,
  /// protocol tag, and bounded metadata.
  Open,
  /// One ordered body chunk of an open stream.
  Chunk,
  /// Terminates an open stream after its final chunk.
  End,
  /// Current-process admission acknowledgement (or typed rejection) for an
  /// open stream. Never a durable-retention claim.
  Ack,
}

impl PacketKind {
  /// Every published packet-stream kind, in wire order.
  pub(crate) const ALL: [Self; 4] = [Self::Open, Self::Chunk, Self::End, Self::Ack];

  /// The immutable kind ID under base schema `0x0001`.
  pub(crate) const fn kind_id(self) -> u16 {
    match self {
      Self::Open => 0x0010,
      Self::Chunk => 0x0011,
      Self::End => 0x0012,
      Self::Ack => 0x0013,
    }
  }
}

/// Resolves one prelude `(schema_id, kind_id)` pair to a published handshake
/// kind. Unknown schemas and unknown kinds return `None`, which the
/// transport must reject before body dispatch.
pub(crate) fn lookup(schema_id: u16, kind_id: u16) -> Option<HandshakeKind> {
  if schema_id != BASE_SCHEMA_ID {
    return None;
  }
  HandshakeKind::ALL
    .into_iter()
    .find(|kind| kind.kind_id() == kind_id)
}

/// Resolves one prelude `(schema_id, kind_id)` pair to a published
/// packet-stream kind.
pub(crate) fn lookup_packet(schema_id: u16, kind_id: u16) -> Option<PacketKind> {
  if schema_id != BASE_SCHEMA_ID {
    return None;
  }
  PacketKind::ALL
    .into_iter()
    .find(|kind| kind.kind_id() == kind_id)
}

/// The closed-registry declaration check for every published kind of the
/// base schema, handshake and packet stream alike.
pub(crate) fn is_declared(schema_id: u16, kind_id: u16) -> bool {
  lookup(schema_id, kind_id).is_some() || lookup_packet(schema_id, kind_id).is_some()
}

#[cfg(test)]
mod tests {
  use super::{BASE_SCHEMA_ID, HandshakeKind, PacketKind, is_declared, lookup, lookup_packet};

  const GOLDEN: [(u16, HandshakeKind); 6] = [
    (0x0001, HandshakeKind::InitiatorHello),
    (0x0002, HandshakeKind::ResponderHello),
    (0x0003, HandshakeKind::ResponderProof),
    (0x0004, HandshakeKind::InitiatorProof),
    (0x0005, HandshakeKind::SelectionConfirmation),
    (0x0006, HandshakeKind::AdmissionGrantDelivery),
  ];

  #[test]
  fn tls_transport_wire_kind_registry_golden_mapping_is_exact() {
    assert_eq!(BASE_SCHEMA_ID, 0x0001);
    assert_eq!(HandshakeKind::ALL.len(), GOLDEN.len());
    for (kind_id, kind) in GOLDEN {
      assert_eq!(kind.kind_id(), kind_id, "kind: {kind:?}");
      assert_eq!(lookup(BASE_SCHEMA_ID, kind_id), Some(kind));
    }
  }

  #[test]
  fn tls_transport_wire_kind_registry_has_no_duplicate_ids() {
    for (index, kind) in HandshakeKind::ALL.into_iter().enumerate() {
      assert!(
        HandshakeKind::ALL[..index]
          .iter()
          .all(|other| other.kind_id() != kind.kind_id()),
        "duplicate kind id: {kind:?}"
      );
    }
    // Every lookup resolves to exactly the kind that published the ID.
    for kind in HandshakeKind::ALL {
      assert_eq!(lookup(BASE_SCHEMA_ID, kind.kind_id()), Some(kind));
    }
  }

  #[test]
  fn tls_transport_wire_kind_registry_rejects_unknown_kinds_and_schemas() {
    for kind_id in [0x0000, 0x0007, 0x00FF, 0xFFFF] {
      assert_eq!(
        lookup(BASE_SCHEMA_ID, kind_id),
        None,
        "kind: {kind_id:#06x}"
      );
    }
    for schema_id in [0x0000, 0x0002, 0xFFFF] {
      assert_eq!(lookup(schema_id, 0x0001), None, "schema: {schema_id:#06x}");
    }
  }

  const PACKET_GOLDEN: [(u16, PacketKind); 4] = [
    (0x0010, PacketKind::Open),
    (0x0011, PacketKind::Chunk),
    (0x0012, PacketKind::End),
    (0x0013, PacketKind::Ack),
  ];

  #[test]
  fn tls_transport_wire_packet_kind_registry_golden_mapping_is_exact() {
    assert_eq!(PacketKind::ALL.len(), PACKET_GOLDEN.len());
    for (kind_id, kind) in PACKET_GOLDEN {
      assert_eq!(kind.kind_id(), kind_id, "kind: {kind:?}");
      assert_eq!(lookup_packet(BASE_SCHEMA_ID, kind_id), Some(kind));
      assert!(is_declared(BASE_SCHEMA_ID, kind_id), "kind: {kind_id:#06x}");
    }
  }

  #[test]
  fn tls_transport_wire_packet_kinds_do_not_collide_with_handshake_kinds() {
    for packet in PacketKind::ALL {
      assert!(
        HandshakeKind::ALL
          .iter()
          .all(|kind| kind.kind_id() != packet.kind_id()),
        "collision: {packet:?}"
      );
    }
    for kind_id in [0x0000, 0x0007, 0x000F, 0x0014, 0x00FF, 0xFFFF] {
      assert_eq!(lookup_packet(BASE_SCHEMA_ID, kind_id), None);
      assert!(
        !is_declared(BASE_SCHEMA_ID, kind_id),
        "kind: {kind_id:#06x}"
      );
    }
    assert!(!is_declared(0x0000, 0x0010));
    assert!(!is_declared(0x0002, 0x0010));
  }
}

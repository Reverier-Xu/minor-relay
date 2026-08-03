#[cfg(test)]
mod tests {
  use proptest::prelude::*;

  use super::{
    CborLimits, Prelude, decode_canonical, encode_canonical, split_message,
  };

  const LIMITS: CborLimits = CborLimits::new(8, 16, 1_024);

  #[derive(Debug, Eq, PartialEq, minicbor::Decode, minicbor::Encode)]
  #[cbor(map)]
  struct TestBody {
    #[n(0)]
    sequence: u64,
    #[n(1)]
    payload: Vec<u8>,
  }

  #[test]
  fn g1_core_prelude_uses_exact_network_order_bytes() {
    let encoded = Prelude::new(0x0001, 0x0203, 0x0004, 5).encode();

    assert_eq!(
      encoded,
      [
        b'M', b'R', b'L', b'Y', 0x00, 0x01, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05,
      ],
    );
  }

  proptest! {
    #[test]
    fn g1_core_prelude_round_trips_without_copying_body(
      schema in any::<u16>(),
      kind in any::<u16>(),
      flags in 0_u16..=0x000f,
      body in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
      let mut message = Vec::from(Prelude::new(schema, kind, flags, body.len() as u32).encode());
      message.extend_from_slice(&body);

      let (decoded, decoded_body) = split_message(&message, 0x000f, 256, 512).unwrap();
      prop_assert_eq!(decoded.schema_id(), schema);
      prop_assert_eq!(decoded.kind_id(), kind);
      prop_assert_eq!(decoded.flags(), flags);
      prop_assert_eq!(decoded_body.as_ptr(), message[16..].as_ptr());
      prop_assert_eq!(decoded_body, body);
    }
  }

  #[test]
  fn g1_core_prelude_rejects_malformed_and_over_limit_messages() {
    let canonical = message(0, &[0x01]);
    assert!(split_message(&canonical[..15], 0, 8, 8).is_err());

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] = b'X';
    assert!(split_message(&wrong_magic, 0, 8, 8).is_err());

    let mut unknown_flags = canonical.clone();
    unknown_flags[9] = 1;
    assert!(split_message(&unknown_flags, 0, 8, 8).is_err());

    let mut reserved = canonical.clone();
    reserved[11] = 1;
    assert!(split_message(&reserved, 0, 8, 8).is_err());

    let mut wrong_length = canonical.clone();
    wrong_length[15] = 2;
    assert!(split_message(&wrong_length, 0, 8, 8).is_err());

    assert!(split_message(&canonical, 0, 0, 8).is_err());
    assert!(split_message(&canonical, 0, 8, 0).is_err());
  }

  #[test]
  fn g1_core_cbor_encodes_and_decodes_exact_canonical_bytes() {
    let body = TestBody {
      sequence: 1,
      payload: b"ok".to_vec(),
    };

    let encoded = encode_canonical(&body, LIMITS).unwrap();
    assert_eq!(encoded, [0xa2, 0x00, 0x01, 0x01, 0x42, b'o', b'k']);
    assert_eq!(decode_canonical::<TestBody>(&encoded, LIMITS).unwrap(), body);
  }

  #[test]
  fn g1_core_cbor_rejects_noncanonical_or_unsupported_forms() {
    for bytes in [
      &[0x18, 0x01][..],
      &[0x9f, 0xff],
      &[0xa2, 0x00, 0x01, 0x00, 0x02],
      &[0xa2, 0x01, 0x01, 0x00, 0x02],
      &[0xc0, 0x00],
      &[0xf9, 0x00, 0x00],
      &[0x00, 0x00],
    ] {
      assert!(decode_canonical::<minicbor::data::Value>(bytes, LIMITS).is_err());
    }
  }

  #[test]
  fn g1_core_cbor_enforces_depth_collection_and_body_limits() {
    assert!(decode_canonical::<minicbor::data::Value>(&[0x81, 0x81, 0x00], CborLimits::new(1, 8, 8)).is_err());
    assert!(decode_canonical::<minicbor::data::Value>(&[0x83, 0x00, 0x01, 0x02], CborLimits::new(4, 2, 8)).is_err());
    assert!(decode_canonical::<minicbor::data::Value>(&[0x00], CborLimits::new(4, 2, 0)).is_err());
  }

  fn message(flags: u16, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::from(Prelude::new(1, 1, flags, body.len() as u32).encode());
    message.extend_from_slice(body);
    message
  }
}

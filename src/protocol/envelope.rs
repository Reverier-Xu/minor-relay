use minicbor::{Decode, Decoder, Encode, Encoder, data::Type, encode::Write};

use crate::{Error, Result};

const MAGIC: [u8; 4] = *b"MRLY";
const PRELUDE_LEN: usize = 16;
const MAX_CBOR_DEPTH: usize = 32;
const MAX_CBOR_COLLECTION_ITEMS: u64 = 4_096;
const MAX_CBOR_BODY_LEN: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Prelude {
  schema_id: u16,
  kind_id: u16,
  flags: u16,
  body_len: u32,
}

impl Prelude {
  const fn new(schema_id: u16, kind_id: u16, flags: u16, body_len: u32) -> Self {
    Self {
      schema_id,
      kind_id,
      flags,
      body_len,
    }
  }

  const fn schema_id(self) -> u16 {
    self.schema_id
  }

  const fn kind_id(self) -> u16 {
    self.kind_id
  }

  const fn flags(self) -> u16 {
    self.flags
  }

  fn encode(self) -> [u8; PRELUDE_LEN] {
    let schema = self.schema_id.to_be_bytes();
    let kind = self.kind_id.to_be_bytes();
    let flags = self.flags.to_be_bytes();
    let body_len = self.body_len.to_be_bytes();
    [
      MAGIC[0],
      MAGIC[1],
      MAGIC[2],
      MAGIC[3],
      schema[0],
      schema[1],
      kind[0],
      kind[1],
      flags[0],
      flags[1],
      0,
      0,
      body_len[0],
      body_len[1],
      body_len[2],
      body_len[3],
    ]
  }

  fn decode(bytes: &[u8]) -> Result<Self> {
    if bytes.len() < PRELUDE_LEN || bytes[..4] != MAGIC {
      return Err(Error::invalid_input("wire prelude"));
    }
    if bytes[10] != 0 || bytes[11] != 0 {
      return Err(Error::invalid_input("wire reserved bits"));
    }

    Ok(Self {
      schema_id: u16::from_be_bytes([bytes[4], bytes[5]]),
      kind_id: u16::from_be_bytes([bytes[6], bytes[7]]),
      flags: u16::from_be_bytes([bytes[8], bytes[9]]),
      body_len: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    })
  }
}

fn split_message<IsDeclared>(
  message: &[u8], allowed_flags: u16, message_limit: u32, receive_limit: u32,
  is_declared: IsDeclared,
) -> Result<(Prelude, &[u8])>
where
  IsDeclared: FnOnce(u16, u16) -> bool, {
  let prelude = Prelude::decode(message)?;
  if !is_declared(prelude.schema_id, prelude.kind_id)
    || prelude.flags & !allowed_flags != 0
    || prelude.body_len > message_limit
    || prelude.body_len > receive_limit
  {
    return Err(Error::invalid_input("wire limits"));
  }

  let body_len =
    usize::try_from(prelude.body_len).map_err(|_| Error::invalid_input("wire body length"))?;
  let expected_len = PRELUDE_LEN
    .checked_add(body_len)
    .ok_or_else(|| Error::invalid_input("wire body length"))?;
  if message.len() != expected_len {
    return Err(Error::invalid_input("wire body length"));
  }

  Ok((prelude, &message[PRELUDE_LEN..]))
}

#[derive(Clone, Copy)]
struct CborLimits {
  max_depth: usize,
  max_collection_items: u64,
  max_body_len: usize,
}

impl CborLimits {
  const fn new(max_depth: usize, max_collection_items: u64, max_body_len: usize) -> Self {
    Self {
      max_depth: if max_depth > MAX_CBOR_DEPTH {
        MAX_CBOR_DEPTH
      } else {
        max_depth
      },
      max_collection_items: if max_collection_items > MAX_CBOR_COLLECTION_ITEMS {
        MAX_CBOR_COLLECTION_ITEMS
      } else {
        max_collection_items
      },
      max_body_len: if max_body_len > MAX_CBOR_BODY_LEN {
        MAX_CBOR_BODY_LEN
      } else {
        max_body_len
      },
    }
  }
}

#[derive(Debug)]
enum LimitedWriteError {
  LimitExceeded,
}

struct LimitedWriter {
  bytes: Vec<u8>,
  position: usize,
}

impl LimitedWriter {
  fn new(limit: usize) -> Result<Self> {
    let mut bytes = Vec::new();
    bytes
      .try_reserve_exact(limit)
      .map_err(|_| Error::invalid_input("CBOR output allocation"))?;
    bytes.resize(limit, 0);
    Ok(Self { bytes, position: 0 })
  }

  fn into_bytes(mut self) -> Vec<u8> {
    self.bytes.truncate(self.position);
    self.bytes
  }
}

impl Write for LimitedWriter {
  type Error = LimitedWriteError;

  fn write_all(&mut self, buffer: &[u8]) -> core::result::Result<(), Self::Error> {
    let end = self
      .position
      .checked_add(buffer.len())
      .ok_or(LimitedWriteError::LimitExceeded)?;
    let output = self
      .bytes
      .get_mut(self.position..end)
      .ok_or(LimitedWriteError::LimitExceeded)?;
    output.copy_from_slice(buffer);
    self.position = end;
    Ok(())
  }
}

fn encode_canonical<T>(value: &T, limits: CborLimits) -> Result<Vec<u8>>
where
  T: Encode<()>, {
  let writer = LimitedWriter::new(limits.max_body_len)?;
  let mut encoder = Encoder::new(writer);
  value
    .encode(&mut encoder, &mut ())
    .map_err(|_| Error::invalid_input("CBOR encode"))?;
  let bytes = encoder.into_writer().into_bytes();
  validate_canonical(&bytes, limits)?;
  Ok(bytes)
}

fn decode_canonical<'bytes, T>(bytes: &'bytes [u8], limits: CborLimits) -> Result<T>
where
  T: Decode<'bytes, ()>, {
  validate_canonical(bytes, limits)?;
  let mut decoder = Decoder::new(bytes);
  let value = T::decode(&mut decoder, &mut ()).map_err(|_| Error::invalid_input("CBOR decode"))?;
  if decoder.position() != bytes.len() {
    return Err(Error::invalid_input("CBOR trailing data"));
  }
  Ok(value)
}

fn validate_canonical(bytes: &[u8], limits: CborLimits) -> Result<()> {
  if bytes.is_empty() || bytes.len() > limits.max_body_len {
    return Err(Error::invalid_input("CBOR body length"));
  }

  let mut decoder = Decoder::new(bytes);
  validate_item(&mut decoder, bytes, limits, 0)?;
  if decoder.position() != bytes.len() {
    return Err(Error::invalid_input("CBOR trailing data"));
  }
  Ok(())
}

fn validate_item(
  decoder: &mut Decoder<'_>, bytes: &[u8], limits: CborLimits, depth: usize,
) -> Result<()> {
  let start = decoder.position();
  let data_type = decoder
    .datatype()
    .map_err(|_| Error::invalid_input("CBOR type"))?;
  match data_type {
    Type::U8
    | Type::U16
    | Type::U32
    | Type::U64
    | Type::I8
    | Type::I16
    | Type::I32
    | Type::I64
    | Type::Int => {
      let (_, header_len) = canonical_argument(bytes, start)?;
      decoder
        .skip()
        .map_err(|_| Error::invalid_input("CBOR integer"))?;
      if decoder.position() - start != header_len {
        return Err(Error::invalid_input("CBOR integer"));
      }
    }
    Type::Bytes => {
      let (length, header_len) = canonical_argument(bytes, start)?;
      decoder
        .bytes()
        .map_err(|_| Error::invalid_input("CBOR bytes"))?;
      validate_sized_item(start, decoder.position(), header_len, length)?;
    }
    Type::String => {
      let (length, header_len) = canonical_argument(bytes, start)?;
      decoder
        .str()
        .map_err(|_| Error::invalid_input("CBOR string"))?;
      validate_sized_item(start, decoder.position(), header_len, length)?;
    }
    Type::Array => {
      validate_container_depth(depth, limits)?;
      let (length, _) = canonical_argument(bytes, start)?;
      let decoded_length = decoder
        .array()
        .map_err(|_| Error::invalid_input("CBOR array"))?
        .ok_or_else(|| Error::invalid_input("CBOR indefinite array"))?;
      if decoded_length != length || length > limits.max_collection_items {
        return Err(Error::invalid_input("CBOR array length"));
      }
      for _ in 0..length {
        validate_item(decoder, bytes, limits, depth + 1)?;
      }
    }
    Type::Map => {
      validate_container_depth(depth, limits)?;
      let (length, _) = canonical_argument(bytes, start)?;
      let decoded_length = decoder
        .map()
        .map_err(|_| Error::invalid_input("CBOR map"))?
        .ok_or_else(|| Error::invalid_input("CBOR indefinite map"))?;
      if decoded_length != length || length > limits.max_collection_items {
        return Err(Error::invalid_input("CBOR map length"));
      }
      let mut previous_key: Option<&[u8]> = None;
      for _ in 0..length {
        let key_start = decoder.position();
        validate_item(decoder, bytes, limits, depth + 1)?;
        let key = &bytes[key_start..decoder.position()];
        if previous_key.is_some_and(|previous| previous >= key) {
          return Err(Error::invalid_input("CBOR map key order"));
        }
        previous_key = Some(key);
        validate_item(decoder, bytes, limits, depth + 1)?;
      }
    }
    Type::Bool => {
      decoder
        .bool()
        .map_err(|_| Error::invalid_input("CBOR bool"))?;
    }
    Type::Null => {
      decoder
        .null()
        .map_err(|_| Error::invalid_input("CBOR null"))?;
    }
    Type::Undefined
    | Type::F16
    | Type::F32
    | Type::F64
    | Type::Simple
    | Type::BytesIndef
    | Type::StringIndef
    | Type::ArrayIndef
    | Type::MapIndef
    | Type::Tag
    | Type::Break
    | Type::Unknown(_) => return Err(Error::invalid_input("CBOR unsupported type")),
  }
  Ok(())
}

fn validate_container_depth(depth: usize, limits: CborLimits) -> Result<()> {
  if depth >= limits.max_depth {
    return Err(Error::invalid_input("CBOR nesting depth"));
  }
  Ok(())
}

fn validate_sized_item(start: usize, end: usize, header_len: usize, value_len: u64) -> Result<()> {
  let value_len =
    usize::try_from(value_len).map_err(|_| Error::invalid_input("CBOR item length"))?;
  if end.checked_sub(start) != header_len.checked_add(value_len) {
    return Err(Error::invalid_input("CBOR item length"));
  }
  Ok(())
}

fn canonical_argument(bytes: &[u8], start: usize) -> Result<(u64, usize)> {
  let initial = *bytes
    .get(start)
    .ok_or_else(|| Error::invalid_input("CBOR header"))?;
  let additional = initial & 0x1F;
  let (value, header_len) = match additional {
    value @ 0..=23 => (u64::from(value), 1),
    24 => (u64::from(read_array::<1>(bytes, start)?[0]), 2),
    25 => (u64::from(u16::from_be_bytes(read_array(bytes, start)?)), 3),
    26 => (u64::from(u32::from_be_bytes(read_array(bytes, start)?)), 5),
    27 => (u64::from_be_bytes(read_array(bytes, start)?), 9),
    _ => return Err(Error::invalid_input("CBOR indefinite length")),
  };

  let canonical_len = if value < 24 {
    1
  } else if u8::try_from(value).is_ok() {
    2
  } else if u16::try_from(value).is_ok() {
    3
  } else if u32::try_from(value).is_ok() {
    5
  } else {
    9
  };
  if header_len != canonical_len {
    return Err(Error::invalid_input("CBOR non-shortest argument"));
  }
  Ok((value, header_len))
}

fn read_array<const LENGTH: usize>(bytes: &[u8], start: usize) -> Result<[u8; LENGTH]> {
  let first = start
    .checked_add(1)
    .ok_or_else(|| Error::invalid_input("CBOR header"))?;
  let last = first
    .checked_add(LENGTH)
    .ok_or_else(|| Error::invalid_input("CBOR header"))?;
  let slice = bytes
    .get(first..last)
    .ok_or_else(|| Error::invalid_input("CBOR header"))?;
  <[u8; LENGTH]>::try_from(slice).map_err(|_| Error::invalid_input("CBOR header"))
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use minicbor::{Encode, Encoder, encode::Write};
  use proptest::prelude::*;

  use super::{CborLimits, Prelude, decode_canonical, encode_canonical, split_message};

  const LIMITS: CborLimits = CborLimits::new(8, 16, 1_024);

  #[derive(Debug, Eq, PartialEq, minicbor::Decode, minicbor::Encode)]
  #[cbor(map)]
  struct TestBody {
    #[n(0)]
    sequence: u64,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    payload: Vec<u8>,
  }

  struct Ignored;

  impl<'bytes, Context> minicbor::Decode<'bytes, Context> for Ignored {
    fn decode(
      decoder: &mut minicbor::Decoder<'bytes>, _context: &mut Context,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
      decoder.skip()?;
      Ok(Self)
    }
  }

  struct RepeatedBody {
    accepted_items: Cell<usize>,
  }

  impl<Context> Encode<Context> for RepeatedBody {
    fn encode<Writer: Write>(
      &self, encoder: &mut Encoder<Writer>, _context: &mut Context,
    ) -> core::result::Result<(), minicbor::encode::Error<Writer::Error>> {
      for _ in 0..100 {
        encoder.bytes(&[0; 16])?;
        self.accepted_items.set(self.accepted_items.get() + 1);
      }
      Ok(())
    }
  }

  #[test]
  fn g1_core_prelude_uses_exact_network_order_bytes() {
    let encoded = Prelude::new(0x0001, 0x0203, 0x0004, 5).encode();

    assert_eq!(
      encoded,
      [
        b'M', b'R', b'L', b'Y', 0x00, 0x01, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05,
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

      let (decoded, decoded_body) =
        split_message(&message, 0x000f, 256, 512, |declared_schema, declared_kind| {
          declared_schema == schema && declared_kind == kind
        })
        .unwrap();
      prop_assert_eq!(decoded.schema_id(), schema);
      prop_assert_eq!(decoded.kind_id(), kind);
      prop_assert_eq!(decoded.flags(), flags);
      prop_assert_eq!(decoded_body.as_ptr(), message[16..].as_ptr());
      prop_assert_eq!(decoded_body, body);
    }

    #[test]
    fn g1_core_hostile_wire_and_cbor_bytes_never_panic(
      input in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
      let wire_result = std::panic::catch_unwind(|| {
        split_message(&input, 0, 256, 512, |schema, kind| schema == 1 && kind == 1)
      });
      let cbor_result = std::panic::catch_unwind(|| {
        decode_canonical::<Ignored>(&input, CborLimits::new(8, 16, 512))
      });

      prop_assert!(wire_result.is_ok());
      prop_assert!(cbor_result.is_ok());
    }

    #[test]
    fn g1_core_equivalent_cbor_values_encode_identically(
      sequence in any::<u64>(),
      payload in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
      let first = TestBody { sequence, payload: payload.clone() };
      let second = TestBody { sequence, payload };

      prop_assert_eq!(encode_canonical(&first, LIMITS).unwrap(), encode_canonical(&second, LIMITS).unwrap());
    }
  }

  #[test]
  fn g1_core_prelude_rejects_malformed_and_over_limit_messages() {
    let canonical = message(0, &[0x01]);
    assert!(split_message(&canonical[..15], 0, 8, 8, declared).is_err());

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] = b'X';
    assert!(split_message(&wrong_magic, 0, 8, 8, declared).is_err());

    let mut unknown_flags = canonical.clone();
    unknown_flags[9] = 1;
    assert!(split_message(&unknown_flags, 0, 8, 8, declared).is_err());

    let mut reserved = canonical.clone();
    reserved[11] = 1;
    assert!(split_message(&reserved, 0, 8, 8, declared).is_err());

    let mut wrong_length = canonical.clone();
    wrong_length[15] = 2;
    assert!(split_message(&wrong_length, 0, 8, 8, declared).is_err());

    assert!(split_message(&canonical, 0, 8, 8, |_, _| false).is_err());
    assert!(split_message(&canonical, 0, 0, 8, declared).is_err());
    assert!(split_message(&canonical, 0, 8, 0, declared).is_err());
  }

  #[test]
  fn g1_core_cbor_encodes_and_decodes_exact_canonical_bytes() {
    let body = TestBody {
      sequence: 1,
      payload: b"ok".to_vec(),
    };

    let encoded = encode_canonical(&body, LIMITS).unwrap();
    assert_eq!(encoded, [0xA2, 0x00, 0x01, 0x01, 0x42, b'o', b'k']);
    assert_eq!(
      decode_canonical::<TestBody>(&encoded, LIMITS).unwrap(),
      body
    );
  }

  #[test]
  fn g1_core_cbor_rejects_noncanonical_or_unsupported_forms() {
    for bytes in [
      &[0x18, 0x01][..],
      &[0x9F, 0xFF],
      &[0xA2, 0x00, 0x01, 0x00, 0x02],
      &[0xA2, 0x01, 0x01, 0x00, 0x02],
      &[0xC0, 0x00],
      &[0xF9, 0x00, 0x00],
      &[0x00, 0x00],
    ] {
      assert!(decode_canonical::<Ignored>(bytes, LIMITS).is_err());
    }
  }

  #[test]
  fn g1_core_cbor_enforces_depth_collection_and_body_limits() {
    assert!(decode_canonical::<Ignored>(&[0x81, 0x81, 0x00], CborLimits::new(1, 8, 8)).is_err());
    assert!(
      decode_canonical::<Ignored>(&[0x83, 0x00, 0x01, 0x02], CborLimits::new(4, 2, 8)).is_err()
    );
    assert!(decode_canonical::<Ignored>(&[0x00], CborLimits::new(4, 2, 0)).is_err());
  }

  #[test]
  fn g1_core_cbor_bounds_output_before_encoding_growth() {
    let body = RepeatedBody {
      accepted_items: Cell::new(0),
    };

    assert!(encode_canonical(&body, CborLimits::new(4, 8, 32)).is_err());
    assert!(body.accepted_items.get() <= 1);
  }

  #[test]
  fn g1_core_cbor_enforces_absolute_limits() {
    let mut too_deep = vec![0x81; 33];
    too_deep.push(0x00);
    assert!(
      decode_canonical::<Ignored>(&too_deep, CborLimits::new(usize::MAX, u64::MAX, usize::MAX))
        .is_err()
    );

    let oversized_collection = [0x99, 0x10, 0x01];
    assert!(
      decode_canonical::<Ignored>(
        &oversized_collection,
        CborLimits::new(usize::MAX, u64::MAX, usize::MAX)
      )
      .is_err()
    );
  }

  fn declared(schema: u16, kind: u16) -> bool {
    schema == 1 && kind == 1
  }

  fn message(flags: u16, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::from(Prelude::new(1, 1, flags, body.len() as u32).encode());
    message.extend_from_slice(body);
    message
  }
}

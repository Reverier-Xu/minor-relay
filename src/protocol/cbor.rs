use minicbor::{Decode, Decoder, Encode, Encoder, data::Type, encode::Write};

use crate::{Error, Result};

#[derive(Clone, Copy)]
pub(crate) struct CborLimits {
  max_depth: usize,
  max_collection_items: u64,
  max_body_len: usize,
}

impl CborLimits {
  pub(crate) const fn new(
    max_depth: usize, max_collection_items: u64, max_body_len: usize,
  ) -> Self {
    Self {
      max_depth,
      max_collection_items,
      max_body_len,
    }
  }

  pub(crate) const fn max_body_len(&self) -> usize {
    self.max_body_len
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

pub(crate) fn encode_canonical<T>(value: &T, limits: CborLimits) -> Result<Vec<u8>>
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

pub(crate) fn decode_canonical<'bytes, T>(bytes: &'bytes [u8], limits: CborLimits) -> Result<T>
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

/// Decodes canonical CBOR and additionally rejects non-canonical
/// encodings: the decoded value must re-encode to byte-identical input.
/// Every persisted record and every authenticated-session payload decodes
/// through this helper so "canonical form" means exactly one thing
/// crate-wide.
pub(crate) fn decode_canonical_strict<'bytes, T>(
  bytes: &'bytes [u8], limits: CborLimits, canonical_context: &'static str,
) -> Result<T>
where
  T: Decode<'bytes, ()> + Encode<()>, {
  let value: T = decode_canonical(bytes, limits)?;
  if encode_canonical(&value, limits)?.as_slice() != bytes {
    return Err(Error::invalid_input(canonical_context));
  }
  Ok(value)
}

pub(crate) fn validate_canonical(bytes: &[u8], limits: CborLimits) -> Result<()> {
  if limits.max_depth == 0
    || limits.max_collection_items == 0
    || limits.max_body_len == 0
    || bytes.is_empty()
    || bytes.len() > limits.max_body_len
  {
    return Err(Error::invalid_input("CBOR limits"));
  }

  let mut decoder = Decoder::new(bytes);
  validate_item(&mut decoder, bytes, limits)?;
  if decoder.position() != bytes.len() {
    return Err(Error::invalid_input("CBOR trailing data"));
  }
  Ok(())
}

#[derive(Debug)]
enum ContainerFrame {
  Array {
    remaining: u64,
  },
  Map {
    remaining: u64,
    expecting_key: bool,
    key_start: Option<usize>,
    previous_key: Option<(usize, usize)>,
  },
}

fn validate_item(decoder: &mut Decoder<'_>, bytes: &[u8], limits: CborLimits) -> Result<()> {
  let mut stack = Vec::<ContainerFrame>::new();
  loop {
    if let Some(ContainerFrame::Map {
      expecting_key: true,
      key_start,
      ..
    }) = stack.last_mut()
      && key_start.is_none()
    {
      *key_start = Some(decoder.position());
    }

    let start = decoder.position();
    let data_type = decoder
      .datatype()
      .map_err(|_| Error::invalid_input("CBOR type"))?;
    let container = match data_type {
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
        if decoder.position().checked_sub(start) != Some(header_len) {
          return Err(Error::invalid_input("CBOR integer"));
        }
        None
      }
      Type::Bytes => {
        let (length, header_len) = canonical_argument(bytes, start)?;
        decoder
          .bytes()
          .map_err(|_| Error::invalid_input("CBOR bytes"))?;
        validate_sized_item(start, decoder.position(), header_len, length)?;
        None
      }
      Type::String => {
        let (length, header_len) = canonical_argument(bytes, start)?;
        decoder
          .str()
          .map_err(|_| Error::invalid_input("CBOR string"))?;
        validate_sized_item(start, decoder.position(), header_len, length)?;
        None
      }
      Type::Array => {
        validate_container_depth(stack.len(), limits)?;
        let (length, _) = canonical_argument(bytes, start)?;
        let decoded_length = decoder
          .array()
          .map_err(|_| Error::invalid_input("CBOR array"))?
          .ok_or_else(|| Error::invalid_input("CBOR indefinite array"))?;
        if decoded_length != length || length > limits.max_collection_items {
          return Err(Error::invalid_input("CBOR array length"));
        }
        Some(ContainerFrame::Array { remaining: length })
      }
      Type::Map => {
        validate_container_depth(stack.len(), limits)?;
        let (length, _) = canonical_argument(bytes, start)?;
        let decoded_length = decoder
          .map()
          .map_err(|_| Error::invalid_input("CBOR map"))?
          .ok_or_else(|| Error::invalid_input("CBOR indefinite map"))?;
        if decoded_length != length || length > limits.max_collection_items {
          return Err(Error::invalid_input("CBOR map length"));
        }
        Some(ContainerFrame::Map {
          remaining: length,
          expecting_key: true,
          key_start: None,
          previous_key: None,
        })
      }
      Type::Bool => {
        decoder
          .bool()
          .map_err(|_| Error::invalid_input("CBOR bool"))?;
        None
      }
      Type::Null => {
        decoder
          .null()
          .map_err(|_| Error::invalid_input("CBOR null"))?;
        None
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
    };

    if let Some(frame) = container {
      let empty = match frame {
        ContainerFrame::Array { remaining } | ContainerFrame::Map { remaining, .. } => {
          remaining == 0
        }
      };
      stack
        .try_reserve(1)
        .map_err(|_| Error::resource_exhausted("CBOR nesting state"))?;
      stack.push(frame);
      if !empty {
        continue;
      }
      stack.pop();
    }

    if complete_item(decoder.position(), bytes, &mut stack)? {
      return Ok(());
    }
  }
}

fn complete_item(position: usize, bytes: &[u8], stack: &mut Vec<ContainerFrame>) -> Result<bool> {
  loop {
    let Some(frame) = stack.last_mut() else {
      return Ok(true);
    };
    let container_complete = match frame {
      ContainerFrame::Array { remaining } => {
        *remaining = remaining
          .checked_sub(1)
          .ok_or_else(|| Error::invalid_input("CBOR array state"))?;
        *remaining == 0
      }
      ContainerFrame::Map {
        remaining,
        expecting_key,
        key_start,
        previous_key,
      } => {
        if *expecting_key {
          let start = key_start
            .take()
            .ok_or_else(|| Error::invalid_input("CBOR map key state"))?;
          let key = bytes
            .get(start..position)
            .ok_or_else(|| Error::invalid_input("CBOR map key"))?;
          if let Some((previous_start, previous_end)) = *previous_key {
            let previous = bytes
              .get(previous_start..previous_end)
              .ok_or_else(|| Error::invalid_input("CBOR map key"))?;
            if previous >= key {
              return Err(Error::invalid_input("CBOR map key order"));
            }
          }
          *previous_key = Some((start, position));
          *expecting_key = false;
          false
        } else {
          *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| Error::invalid_input("CBOR map state"))?;
          *expecting_key = true;
          *remaining == 0
        }
      }
    };
    if !container_complete {
      return Ok(false);
    }
    stack.pop();
  }
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

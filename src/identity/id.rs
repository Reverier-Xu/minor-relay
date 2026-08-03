use std::{fmt, str::FromStr};

use crate::{Error, Result};

const RANDOM_SUFFIX_LEN: usize = 21;

macro_rules! canonical_id {
  ($name:ident, $prefix:literal, $context:literal) => {
    #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct $name(String);

    impl $name {
      pub fn parse(value: &str) -> Result<Self> {
        validate_id(value, $prefix, $context)?;
        Ok(Self(value.to_owned()))
      }

      pub fn as_str(&self) -> &str {
        &self.0
      }
    }

    impl FromStr for $name {
      type Err = Error;

      fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
          .debug_tuple(stringify!($name))
          .field(&self.0)
          .finish()
      }
    }
  };
}

canonical_id!(NodeId, "node_", "node id");
canonical_id!(ClusterId, "cluster_", "cluster id");
canonical_id!(TraceId, "trace_", "trace id");

fn validate_id(value: &str, prefix: &str, context: &'static str) -> Result<()> {
  let expected_len = prefix.len() + RANDOM_SUFFIX_LEN;
  if value.len() != expected_len || !value.starts_with(prefix) {
    return Err(Error::invalid_input(context));
  }

  let suffix = &value.as_bytes()[prefix.len()..];
  if !suffix.iter().copied().all(is_base62) {
    return Err(Error::invalid_input(context));
  }

  Ok(())
}

const fn is_base62(byte: u8) -> bool {
  byte.is_ascii_digit() || byte.is_ascii_lowercase() || byte.is_ascii_uppercase()
}

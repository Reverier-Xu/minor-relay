use crate::{Error, Result};

const DEFAULT_MEMBER_LIMIT: usize = 1_024;
const MAX_MEMBER_LIMIT: usize = 1_024;

#[derive(Debug)]
pub struct NodeConfig {
  member_limit: usize,
}

impl NodeConfig {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_member_limit(mut self, value: usize) -> Result<Self> {
    if !(1..=MAX_MEMBER_LIMIT).contains(&value) {
      return Err(Error::invalid_input("member limit"));
    }
    self.member_limit = value;
    Ok(self)
  }
}

impl Default for NodeConfig {
  fn default() -> Self {
    Self {
      member_limit: DEFAULT_MEMBER_LIMIT,
    }
  }
}

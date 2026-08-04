#[derive(Debug, Default)]
pub struct ExtensionRegistry {
  _private: (),
}

impl ExtensionRegistry {
  pub fn new() -> Self {
    Self::default()
  }
}

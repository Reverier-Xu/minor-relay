use std::sync::Arc;

use crate::{
  NodeConfig, NodeHandle, Result,
  provider::{KeyProvider, StorageFactory},
  runtime::{RuntimeDependencies, spawn_runtime},
};

pub struct NodeBuilder {
  storage: Arc<dyn StorageFactory>,
  keys: Arc<dyn KeyProvider>,
  config: NodeConfig,
}

impl NodeBuilder {
  pub fn new(storage: Arc<dyn StorageFactory>, keys: Arc<dyn KeyProvider>) -> Self {
    Self {
      storage,
      keys,
      config: NodeConfig::new(),
    }
  }

  pub fn config(mut self, value: NodeConfig) -> Self {
    self.config = value;
    self
  }

  pub async fn start(self) -> Result<NodeHandle> {
    let client = spawn_runtime(RuntimeDependencies {
      _storage: self.storage,
      _keys: self.keys,
      _config: self.config,
    })
    .await?;
    Ok(NodeHandle::new(client))
  }
}

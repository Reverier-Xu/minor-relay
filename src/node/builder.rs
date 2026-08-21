use std::sync::Arc;

use crate::{
  ExtensionRegistry, NodeConfig, NodeHandle, Result,
  api::{Entropy, SystemEntropy},
  provider::{KeyProvider, StorageFactory},
  runtime::{RuntimeDependencies, spawn_runtime},
};

pub struct NodeBuilder {
  storage: Arc<dyn StorageFactory>,
  keys: Arc<dyn KeyProvider>,
  config: NodeConfig,
  entropy: Arc<dyn Entropy>,
  extensions: ExtensionRegistry,
}

impl NodeBuilder {
  pub fn new(storage: Arc<dyn StorageFactory>, keys: Arc<dyn KeyProvider>) -> Self {
    Self {
      storage,
      keys,
      config: NodeConfig::new(),
      entropy: Arc::new(SystemEntropy),
      extensions: ExtensionRegistry::new(),
    }
  }

  pub fn config(mut self, value: NodeConfig) -> Self {
    self.config = value;
    self
  }

  pub fn extensions(mut self, value: ExtensionRegistry) -> Self {
    self.extensions = value;
    self
  }

  pub fn entropy(mut self, value: Arc<dyn Entropy>) -> Self {
    self.entropy = value;
    self
  }

  pub async fn start(self) -> Result<NodeHandle> {
    let extensions = Arc::new(self.extensions);
    let client = spawn_runtime(RuntimeDependencies {
      storage_factory: self.storage,
      context: None,
      keys: self.keys,
      config: self.config,
      entropy: self.entropy.clone(),
      extensions: extensions.clone(),
      sessions: Default::default(),
      routes: Default::default(),
      packet_tx: None,
      _runtime_seed: None,
    })
    .await?;
    Ok(NodeHandle::new(client, self.entropy, extensions))
  }
}

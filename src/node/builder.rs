use std::sync::Arc;

use crate::{
  ExtensionRegistry, NodeConfig, NodeHandle, Result,
  api::{Clock, Entropy, SystemClock, SystemEntropy},
  provider::{KeyProvider, StorageFactory},
  runtime::{RuntimeDependencies, spawn_runtime},
};

pub struct NodeBuilder {
  storage: Arc<dyn StorageFactory>,
  keys: Arc<dyn KeyProvider>,
  config: NodeConfig,
  extensions: ExtensionRegistry,
  clock: Arc<dyn Clock>,
  entropy: Arc<dyn Entropy>,
}

impl NodeBuilder {
  pub fn new(storage: Arc<dyn StorageFactory>, keys: Arc<dyn KeyProvider>) -> Self {
    Self {
      storage,
      keys,
      config: NodeConfig::new(),
      extensions: ExtensionRegistry::new(),
      clock: Arc::new(SystemClock::new()),
      entropy: Arc::new(SystemEntropy),
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

  pub fn clock(mut self, value: Arc<dyn Clock>) -> Self {
    self.clock = value;
    self
  }

  pub fn entropy(mut self, value: Arc<dyn Entropy>) -> Self {
    self.entropy = value;
    self
  }

  pub async fn start(self) -> Result<NodeHandle> {
    let mut runtime_seed = [0; 32];
    self.entropy.fill(&mut runtime_seed)?;
    let _ = self.clock.utc_now();
    let _ = self.clock.monotonic_now();

    let client = spawn_runtime(RuntimeDependencies {
      _storage: self.storage,
      _keys: self.keys,
      _config: self.config,
      _extensions: self.extensions,
      _clock: self.clock,
      _entropy: self.entropy,
      _runtime_seed: runtime_seed,
    })
    .await?;
    Ok(NodeHandle::new(client))
  }
}

#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
export PATH="/usr/local/cargo/bin:/usr/local/rustup/bin:/usr/bin:/bin"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/workspace

cd /workspace

git rev-parse --verify HEAD
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo \
  test \
  --locked \
  --lib \
  'simulation::network::tests::simulation_network_fault_matrix_gate' \
  -- \
  --ignored \
  --exact

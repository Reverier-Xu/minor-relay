#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
export PATH="/usr/local/cargo/bin:/usr/local/rustup/bin:/usr/bin:/bin"

cd /workspace

git rev-parse --verify HEAD
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo \
  --config 'env.MINOR_RELAY_SIM_SEEDS.value="1000"' \
  --config env.MINOR_RELAY_SIM_SEEDS.force=true \
  --config 'env.MINOR_RELAY_SIM_SEED.value="0"' \
  --config env.MINOR_RELAY_SIM_SEED.force=true \
  test \
  --locked \
  --lib \
  'simulation::network::tests::simulation_network_fault_matrix_gate' \
  -- \
  --ignored \
  --exact

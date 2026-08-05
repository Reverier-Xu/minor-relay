#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE MINOR_RELAY_SIM_SEED
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g1-lifecycle.sh\n' >&2
  exit 2
fi

cargo test --locked --lib 'api::tests::g1_lifecycle'
cargo test --locked --lib 'node::event::tests::g1_lifecycle'
cargo test --locked --test lifecycle g1_lifecycle

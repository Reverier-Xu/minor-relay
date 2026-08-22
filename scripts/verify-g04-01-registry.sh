#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g04-01-registry.sh\n' >&2
  exit 2
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

require_nonempty_tests() {
  local label=$1 listing=$2
  if ! grep -Eq ': test$' "$listing"; then
    printf 'verification target matched no tests: %s\n' "$label" >&2
    exit 1
  fi
}

# Registration lane (SC-G04-P0-01..02).
cargo test --locked --lib transport::registry -- --list > "$TMP/registry.list"
require_nonempty_tests transport_registry "$TMP/registry.list"
cargo test --locked --lib transport::registry

# Authenticated transport lane (SC-G04-P0-03): the built-in registered WSS
# connection carries a real TLS exporter binding.
cargo test --locked --lib transport::registry::tests::wss_transport_connection_carries_a_real_tls_exporter_binding

# Secure WSS regression lane (SC-G04-P0-04): the built-in WSS transport is
# registered by default and the secure join/packet/reconnect regression on
# the same connection path stays green.
cargo test --locked --lib transport::registry::tests::extension_registry_defaults_to_the_builtin_wss_transport
cargo test --locked --test secure_join

#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g04-03-replacement.sh\n' >&2
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

# Deterministic ownership lane (SC-G04-P0-09).
cargo test --locked --lib session::replacement_tests -- --list > "$TMP/replace.list"
require_nonempty_tests session_replacement "$TMP/replace.list"
cargo test --locked --lib session::replacement_tests

# Crossed-dial convergence and drain lane (SC-G04-P0-10..11, E2E-03).
cargo test --locked --test secure_join secure_join_crossed_dial_converges_to_one_session

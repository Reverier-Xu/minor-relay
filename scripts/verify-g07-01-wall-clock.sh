#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/verify-g07-01-wall-clock.sh\n' >&2
  exit 1
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

# Conversion lane (SC-G07-P0-01): total epoch-saturating second/millisecond
# conversions over host SystemTime with exact round-trips under freeze and
# rollback.
cargo test --locked --lib time:: -- --list > "$TMP/time.list"
require_nonempty_tests time_conversions "$TMP/time.list"
cargo test --locked --lib time::

# Retention lane (SC-G07-P0-02, SC-G06-P0-18): trace retention sweeps
# re-read the wall clock every pass; rollback/freeze delay expiry and a
# forward jump expires immediately.
cargo test --locked --lib routing::trace -- --list > "$TMP/trace.list"
require_nonempty_tests routing_trace "$TMP/trace.list"
cargo test --locked --lib routing::trace

# Liveness lane (SC-G07-P0-02): session idle/keepalive deadlines re-read
# the wall clock after every wake across rollback, freeze, and jumps.
cargo test --locked --lib liveness -- --list > "$TMP/liveness.list"
require_nonempty_tests session_liveness "$TMP/liveness.list"
cargo test --locked --lib liveness

# Recovery backoff lane (SC-G07-P0-02): retry scheduling re-reads wall
# time and reacts to discontinuities identically.
cargo test --locked --lib membership::recovery -- --list > "$TMP/recovery.list"
require_nonempty_tests recovery_backoff "$TMP/recovery.list"
cargo test --locked --lib membership::recovery

# Public-surface lane (SC-G07-P1-03): the public inventory keeps causal
# timestamps, peer-clock sampling, and clock health on its forbidden-token
# list, and the facade exports none of them.
for token in 'pub struct ClockHealth' 'pub trait WallClock' 'pub fn wall_clock'; do
  grep -Fqx "  \"$token\"," docs/api-inventory.toml || {
    printf 'inventory no longer forbids %s\n' "$token" >&2
    exit 1
  }
  if rg -q "ClockHealth|WallClock|wall_clock" src/lib.rs; then
    printf 'public facade exposes a clock-consensus surface\n' >&2
    exit 1
  fi
done

printf 'VERIFY-G07-01 PASS\n'

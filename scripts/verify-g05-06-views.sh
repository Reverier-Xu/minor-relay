#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if (($# != 0)); then
  printf 'usage: scripts/verify-g05-06-views.sh\n' >&2
  exit 2
fi
# The public membership/topology view lane (SC-G05-P0-23..26 core).
cargo test --locked --test secure_join secure_join_public_membership_and_topology_views
cargo test --locked --test secure_join secure_join_sixteen_node_membership_joins_and_views
# The membership failure matrix: duplicate delivery, partition healing, and
# immediate recovery observability (SC-G05-P0-22/27).
cargo test --locked --test membership_sync membership_sync_failure_matrix_partition_healing
# The metadata convergence SLO: every sampled sample stays below
# 10,000 milliseconds (SC-G05-P0-29).
cargo test --locked --test membership_sync membership_sync_slo_trend_stays_below_bound

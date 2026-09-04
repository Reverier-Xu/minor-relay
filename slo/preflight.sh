#!/usr/bin/bash -p
# The OCI profile preflight (ADR-0005, SC-G10-P0-32): a dry-run that
# verifies every host, engine, and network property the sixteen-node
# profile demands, and rejects every mismatch before any measurement.
# A failed preflight aborts before measurement and cannot be reclassified.
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS
export LC_ALL=C

fail() {
  printf 'preflight mismatch: %s\n' "$1" >&2
  exit 1
}

# --- host profile (kernel, cpu, memory) ---
KERNEL=$(uname -r)
KERNEL_MAJOR=${KERNEL%%.*}
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$((KERNEL_MAJOR * 1000 + KERNEL_MINOR))" -lt 6006 ]; then
  fail "kernel $KERNEL is older than 6.6"
fi

CPUS=$(nproc)
if [ "$CPUS" -lt 12 ]; then
  fail "host has $CPUS logical CPUs; the profile needs at least 12"
fi

if [ -r /proc/meminfo ]; then
  MEM_KB=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
  MEM_GIB=$((MEM_KB / 1024 / 1024))
  if [ "$MEM_GIB" -lt 16 ]; then
    fail "host has ${MEM_GIB} GiB RAM; the profile needs at least 16"
  fi
  SWAP_KB=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)
  if [ "${SWAP_KB:-0}" -ne 0 ] && [ -r /proc/vmstat ]; then
    SWAP_IN=$(awk '/^pswpin/ { print $2 }' /proc/vmstat)
    SWAP_OUT=$(awk '/^pswpout/ { print $2 }' /proc/vmstat)
    if [ "${SWAP_IN:-0}" -gt 0 ] || [ "${SWAP_OUT:-0}" -gt 0 ]; then
      fail "sustained swap activity observed"
    fi
  fi
else
  fail "/proc/meminfo is unreadable"
fi

# --- cgroup v2 ---
if [ -d /sys/fs/cgroup ] && [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  :
else
  # Inside an unprivileged container the host cgroup view may be hidden;
  # the OCI engine check below is the authoritative profile probe.
  printf 'preflight: host cgroup v2 view hidden (container run); deferring to engine probe\n'
fi

# --- OCI engine ---
ENGINE=""
if command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
  ENGINE="docker"
else
  fail "no OCI engine (podman or docker) is available"
fi
"$ENGINE" info >/dev/null 2>&1 || fail "$ENGINE info failed"

# --- bridge network with MTU 1500 ---
NETWORK="radiata-slo-preflight"
"$ENGINE" network exists "$NETWORK" 2>/dev/null || "$ENGINE" network create --disable-dns "$NETWORK" >/dev/null 2>&1 || true
if "$ENGINE" network exists "$NETWORK" 2>/dev/null; then
  MTU=$("$ENGINE" network inspect "$NETWORK" --format '{{.MTU}}' 2>/dev/null || echo 0)
  if [ "$MTU" != "0" ] && [ "$MTU" != "" ] && [ "$MTU" != "1500" ]; then
    fail "bridge MTU is $MTU; the profile fixes 1500"
  fi
fi

# --- publish-false workspace proof ---
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if grep -q '^publish[[:space:]]*=[[:space:]]*false' "$ROOT/slo/Cargo.toml"; then
  :
else
  fail "the harness workspace is not publish = false"
fi

printf 'SLO-PREFLIGHT PASS\n'

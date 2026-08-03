#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ $# -ne 1 || ! $1 =~ ^T-G[0-9]{2}-[0-9]{2}$ ]]; then
  printf 'usage: scripts/verify-task.sh T-Gxx-yy\n' >&2
  exit 2
fi
TASK_ID=$1

scripts/validate-planning-docs.sh
command -v timeout >/dev/null 2>&1 || { printf 'missing timeout utility\n' >&2; exit 2; }

MANIFEST=$(taplo get -o json -f docs/task-verification.toml)
TASK=$(jq -c --arg id "$TASK_ID" '.task[] | select(.id == $id)' <<<"$MANIFEST")
[[ -n $TASK ]] || { printf 'unknown task: %s\n' "$TASK_ID" >&2; exit 2; }

STATE=$(jq -r '.state' <<<"$TASK")
VERIFY_ID=$(jq -r '.verification_id' <<<"$TASK")
case "$STATE" in
  ready) ;;
  planned)
    printf '%s is planned; register literal argv and change state to ready before RED\n' "$TASK_ID" >&2
    exit 2
    ;;
  inline)
    printf '%s predates the dispatcher and retains its accepted inline documentation check\n' "$TASK_ID" >&2
    exit 2
    ;;
  *)
    printf 'invalid task state for %s: %s\n' "$TASK_ID" "$STATE" >&2
    exit 2
    ;;
esac

VERIFICATION=$(jq -c --arg id "$VERIFY_ID" '.verification[] | select(.id == $id)' <<<"$MANIFEST")
[[ -n $VERIFICATION ]] || { printf 'missing verification: %s\n' "$VERIFY_ID" >&2; exit 2; }
mapfile -t ARGV < <(jq -r '.argv[]' <<<"$VERIFICATION")
((${#ARGV[@]} > 0)) || { printf 'empty verification argv: %s\n' "$VERIFY_ID" >&2; exit 2; }
TIMEOUT_SECONDS=$(jq -r '.timeout_seconds' <<<"$VERIFICATION")
printf 'running %s for %s\n' "$VERIFY_ID" "$TASK_ID"
timeout --foreground --signal=TERM --kill-after=30s "${TIMEOUT_SECONDS}s" "${ARGV[@]}"

if [[ $(jq -r '.include_quality' <<<"$TASK") == true ]]; then
  QUALITY_TIMEOUT_SECONDS=$(jq -r '.quality_timeout_seconds' <<<"$MANIFEST")
  while IFS= read -r encoded; do
    command_json=$(printf '%s' "$encoded" | base64 --decode)
    mapfile -t QUALITY_ARGV < <(jq -r '.[]' <<<"$command_json")
    printf 'running quality command: %s\n' "${QUALITY_ARGV[*]}"
    timeout --foreground --signal=TERM --kill-after=30s "${QUALITY_TIMEOUT_SECONDS}s" "${QUALITY_ARGV[@]}"
  done < <(jq -r '.quality_argv[] | @base64' <<<"$MANIFEST")
fi

printf '%s verification: PASS\n' "$TASK_ID"

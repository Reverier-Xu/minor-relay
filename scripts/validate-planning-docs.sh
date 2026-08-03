#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

fail() {
  printf 'planning validation failed: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing tool: $1"
}

version_at_least() {
  local actual=$1 minimum=$2
  [[ $(printf '%s\n%s\n' "$minimum" "$actual" | sort -V | head -n 1) == "$minimum" ]]
}

require_tool taplo
require_tool jq
require_tool rg
require_tool git
require_tool sha256sum
require_tool timeout

TAPLO_VERSION=$(taplo --version | awk '{print $2}')
JQ_VERSION=$(jq --version | sed 's/^jq-//')
version_at_least "$TAPLO_VERSION" 0.10.0 || fail "Taplo >=0.10.0 required"
version_at_least "$JQ_VERSION" 1.8.0 || fail "jq >=1.8.0 required"

TOML_FILES=(
  docs/api-inventory.toml
  docs/api-inventory.toml
  docs/scenario-catalog.toml
  docs/threat-model.toml
  docs/decision-register.toml
  docs/task-verification.toml
  docs/evidence-impact.toml
)
taplo lint --no-auto-config "${TOML_FILES[@]}" >/dev/null

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for file in "${TOML_FILES[@]}"; do
  name=$(basename "$file" .toml)
  taplo get -o json -f "$file" > "$TMP/$name.json"
done

jq -e '.schema == "relay.woooo.tech/schemas/api-inventory-v1" and .status == "accepted"' "$TMP/api-inventory.json" >/dev/null || fail "invalid API inventory schema/status"
jq -e '.schema == "relay.woooo.tech/schemas/planning-scenarios-v1" and .status == "accepted"' "$TMP/scenario-catalog.json" >/dev/null || fail "invalid scenario schema/status"
jq -e '.schema == "relay.woooo.tech/schemas/threat-model-v1" and .status == "accepted"' "$TMP/threat-model.json" >/dev/null || fail "invalid threat schema/status"
jq -e '.schema == "relay.woooo.tech/schemas/decision-register-v1" and .status == "accepted"' "$TMP/decision-register.json" >/dev/null || fail "invalid decision schema/status"
jq -e '.schema == "relay.woooo.tech/schemas/task-verification-v1" and .status == "accepted"' "$TMP/task-verification.json" >/dev/null || fail "invalid task schema/status"
jq -e '.schema == "relay.woooo.tech/schemas/evidence-impact-v1" and .status == "accepted"' "$TMP/evidence-impact.json" >/dev/null || fail "invalid impact schema/status"

TASK_PLAN=docs/implementation-plan.md
[[ -f $TASK_PLAN ]] || fail "missing implementation plan"
mapfile -t PLAN_TASKS < <(rg -o '^\| T-G[0-9]{2}-[0-9]{2} ' "$TASK_PLAN" | awk '{print $2}' | sort)
[[ ${#PLAN_TASKS[@]} -eq 69 ]] || fail "expected 69 plan tasks, found ${#PLAN_TASKS[@]}"
[[ $(printf '%s\n' "${PLAN_TASKS[@]}" | uniq -d | wc -l) -eq 0 ]] || fail "duplicate plan task"
printf '%s\n' "${PLAN_TASKS[@]}" > "$TMP/plan-tasks.txt"

jq -e '
  def pad2: tostring | if length == 1 then "0" + . else . end;
  [
    .scenario_set[] as $set
    | range(0; ($set.cases | length)) as $index
    | {
        id: ("SC-G" + (($set.gate[1:] | tonumber) | pad2) + "-" + $set.priority + "-" + (($set.first + $index) | pad2)),
        owner_task: $set.owner_task,
        gate: $set.gate,
        priority: $set.priority,
        verification_id: $set.verification_id,
        title: $set.cases[$index].title,
        acceptance: $set.cases[$index].acceptance,
        threats: $set.cases[$index].threats
      }
  ]
' "$TMP/scenario-catalog.json" > "$TMP/scenarios.json"

check_scenario_ids() {
  local file=$1
  jq -e '
    length == 226
    and ([.[].id] | unique | length) == 226
    and all(.[]; (.id | test("^SC-G[0-9]{2}-P[01]-[0-9]{2}$")) and (.title | length > 0) and (.acceptance | length > 0))
  ' "$file" >/dev/null
}
check_scenario_ids "$TMP/scenarios.json" || fail "invalid, missing, or duplicate SC record"
[[ $(jq '.e2e | length' "$TMP/scenario-catalog.json") -eq 10 ]] || fail "expected ten E2E records"
[[ $(jq '[.e2e[].id] | unique | length' "$TMP/scenario-catalog.json") -eq 10 ]] || fail "duplicate E2E ID"
jq -e 'all(.e2e[]; (.id | test("^E2E-(0[1-9]|10)$")) and (.title | length > 0) and (.acceptance | length > 0))' "$TMP/scenario-catalog.json" >/dev/null || fail "invalid E2E record"

expand_reference() {
  local reference=$1 prefix first last value
  if [[ $reference =~ ^(SC-G[0-9]{2}-P[01]-)([0-9]{2})\.\.([0-9]{2})$ ]]; then
    prefix=${BASH_REMATCH[1]}
    first=$((10#${BASH_REMATCH[2]}))
    last=$((10#${BASH_REMATCH[3]}))
    (( first <= last )) || fail "descending scenario range: $reference"
    for ((value = first; value <= last; value++)); do
      printf '%s%02d\n' "$prefix" "$value"
    done
  elif [[ $reference =~ ^SC-G[0-9]{2}-P[01]-[0-9]{2}$ ]]; then
    printf '%s\n' "$reference"
  else
    fail "invalid scenario reference: $reference"
  fi
}

: > "$TMP/plan-scenarios.tsv"
while IFS= read -r line; do
  task=$(printf '%s\n' "$line" | sed -E 's/^\| (T-G[0-9]{2}-[0-9]{2}) .*/\1/')
  mapfile -t references < <(printf '%s\n' "$line" | rg -o 'SC-G[0-9]{2}-P[01]-[0-9]{2}(\.\.[0-9]{2})?')
  ((${#references[@]} > 0)) || fail "$task has no scenario reference"
  for reference in "${references[@]}"; do
    while IFS= read -r id; do
      printf '%s\t%s\n' "$id" "$task" >> "$TMP/plan-scenarios.tsv"
    done < <(expand_reference "$reference")
  done
done < <(rg '^\| T-G[0-9]{2}-[0-9]{2} ' "$TASK_PLAN")
sort -o "$TMP/plan-scenarios.tsv" "$TMP/plan-scenarios.tsv"

jq -r '.[] | [.id, .owner_task] | @tsv' "$TMP/scenarios.json" | sort > "$TMP/catalog-scenarios.tsv"
diff -u "$TMP/plan-scenarios.tsv" "$TMP/catalog-scenarios.tsv" >/dev/null || fail "plan and catalog SC ownership differ"

: > "$TMP/plan-e2e.tsv"
while IFS= read -r line; do
  task=$(printf '%s\n' "$line" | sed -E 's/^\| (T-G[0-9]{2}-[0-9]{2}) .*/\1/')
  while IFS= read -r id; do
    [[ -n $id ]] && printf '%s\t%s\n' "$id" "$task" >> "$TMP/plan-e2e.tsv"
  done < <(printf '%s\n' "$line" | rg -o 'E2E-(0[1-9]|10)' || true)
done < <(rg '^\| T-G[0-9]{2}-[0-9]{2} ' "$TASK_PLAN")
sort -o "$TMP/plan-e2e.tsv" "$TMP/plan-e2e.tsv"
jq -r '.e2e[] | [.id, .owner_task] | @tsv' "$TMP/scenario-catalog.json" | sort > "$TMP/catalog-e2e.tsv"
diff -u "$TMP/plan-e2e.tsv" "$TMP/catalog-e2e.tsv" >/dev/null || fail "plan and catalog E2E ownership differ"

jq -e --rawfile tasks "$TMP/plan-tasks.txt" '
  ($tasks | split("\n") | map(select(length > 0))) as $known
  | ([.task[].id] | length) == 69
  and ([.task[].id] | unique | length) == 69
  and ([.verification[].id] | length) == 69
  and ([.verification[].id] | unique | length) == 69
  and all(.task[]; .id as $id | ($known | index($id)) != null)
  and all(.verification[]; .owner_task as $owner | ($known | index($owner)) != null)
' "$TMP/task-verification.json" >/dev/null || fail "invalid task/verification ownership"

jq -e --slurpfile scenarios "$TMP/scenarios.json" --slurpfile catalog "$TMP/scenario-catalog.json" '
  (.task | map({key: .id, value: .verification_id}) | from_entries) as $owner_verification
  | all($scenarios[0][]; .verification_id == $owner_verification[.owner_task])
  and all($catalog[0].e2e[]; .verification_id == $owner_verification[.owner_task])
' "$TMP/task-verification.json" >/dev/null || fail "scenario/E2E verification ownership mismatch"

jq -e '
  (.verification | map({key: .id, value: .}) | from_entries) as $verifications
  | all(.task[];
      ($verifications[.verification_id].owner_task == .id)
      and (.state == $verifications[.verification_id].state)
      and (
        if .state == "ready" then ($verifications[.verification_id].argv | length) > 0
        elif (.state == "planned" or .state == "inline") then ($verifications[.verification_id].argv | length) == 0
        else false
        end
      )
    )
' "$TMP/task-verification.json" >/dev/null || fail "task readiness or argv state invalid"

check_argv_policy() {
  local file=$1
  jq -e '
    def safe_arg: type == "string" and (length > 0) and (test("[\\n\\r;&|`$<>]") | not);
    def allowed_program: test("^scripts/[a-z0-9-]+\\.sh$") or . == "cargo" or . == "taplo" or . == "cargo-hack" or . == "cargo-fuzz" or . == "act" or . == "gh" or . == "docker" or . == "podman";
    [
      ["taplo", "fmt", "--check"],
      ["cargo", "+nightly", "fmt", "--all", "--", "--check"],
      ["cargo", "check", "--workspace", "--all-targets", "--all-features", "--locked"],
      ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"],
      ["cargo", "test", "--workspace", "--all-features", "--locked"]
    ] as $q
    | .quality_timeout_seconds == 1800
    and .quality_argv == $q
    and all(.task[]; .include_quality == true)
    and all(.quality_argv[]; (length > 0) and (.[0] | allowed_program) and all(.[]; safe_arg))
    and all(.verification[] | select(.state == "ready");
      (.timeout_seconds >= 1 and .timeout_seconds <= 86400)
      and (.argv[0] | allowed_program)
      and all(.argv[]; safe_arg)
      and (((.argv[0] | test("^scripts/")) | not) or ((.argv | length) == 1 or ((.argv | length) == 2 and .argv[1] == "--self-test")))
    )
  ' "$file" >/dev/null
}
check_argv_policy "$TMP/task-verification.json" || fail "unsafe, altered, or unbounded verification argv/Q"
TASK_MANIFEST_DIGEST=$(jq -cS '.' "$TMP/task-verification.json" | sha256sum | awk '{print $1}')
[[ $TASK_MANIFEST_DIGEST == 71a63f556818a2f8a1953f5a30e585a90a80f58b2063ec419149a9dabd581fc9 ]] || fail "task readiness/argv manifest differs from frozen handoff"

check_threat_shape() {
  local file=$1
  jq -e '
    ["credential-guessing", "replay", "impersonation", "identity-clones", "sybil-admission", "stale-metadata", "protocol-downgrade", "route-amplification", "oversized-payloads", "slow-peers", "future-timestamps", "malicious-members", "secret-disclosure"] as $mandatory
    | [.threat[].id] == [range(1; 30) | "THR-" + (tostring | if length == 1 then "00" + . elif length == 2 then "0" + . else . end)]
    and ([.threat[].mandatory_key | select(length > 0)] | sort) == ($mandatory | sort)
    and all(.threat[]; .status == "accepted" and (.priority == "P0" or .priority == "P1") and (.mitigation | length) > 0 and has("residual") and (.scenario_ids | length) > 0)
  ' "$file" >/dev/null
}
check_threat_shape "$TMP/threat-model.json" || fail "threat model continuity, mandatory categories, or mitigation invalid"

jq -e --slurpfile scenarios "$TMP/scenarios.json" --slurpfile catalog "$TMP/scenario-catalog.json" --rawfile tasks "$TMP/plan-tasks.txt" '
  ($tasks | split("\n") | map(select(length > 0))) as $known_tasks
  | (($scenarios[0] | map(.id)) + ($catalog[0].e2e | map(.id))) as $known_scenarios
  | [.threat[].id] == [range(1; 30) | "THR-" + (tostring | if length == 1 then "00" + . elif length == 2 then "0" + . else . end)]
  and ([.threat[].mandatory_key | select(length > 0)] | length) == 13
  and ([.threat[].mandatory_key | select(length > 0)] | unique | length) == 13
  and all(.threat[];
    . as $threat
    | $threat.status == "accepted"
    and ($threat.priority == "P0" or $threat.priority == "P1")
    and ($known_tasks | index($threat.owner_task)) != null
    and ($threat.mitigation | length) > 0
    and ($threat | has("residual"))
    and ($threat.scenario_ids | length) > 0
    and all($threat.scenario_ids[]; . as $scenario | ($known_scenarios | index($scenario)) != null)
  )
' "$TMP/threat-model.json" >/dev/null || fail "threat model continuity, ownership, or mitigation invalid"

jq -e --slurpfile threats "$TMP/threat-model.json" '
  ($threats[0].threat | map(.id)) as $known
  | all(.[]; . as $scenario | all($scenario.threats[]; . as $threat | ($known | index($threat)) != null))
' "$TMP/scenarios.json" >/dev/null || fail "SC references unknown threat"
jq -e --slurpfile threats "$TMP/threat-model.json" '
  ($threats[0].threat | map(.id)) as $known
  | all(.e2e[]; . as $scenario | all($scenario.threats[]; . as $threat | ($known | index($threat)) != null))
' "$TMP/scenario-catalog.json" >/dev/null || fail "E2E references unknown threat"

jq -e --rawfile tasks "$TMP/plan-tasks.txt" '
  ($tasks | split("\n") | map(select(length > 0))) as $known
  | ([.constant[].id] | length) == 44
  and ([.constant[].id] | length) == ([.constant[].id] | unique | length)
  and all(.constant[]; . as $constant | ($constant.id | test("^[a-z0-9][a-z0-9.-]+$")) and ($constant.value | length > 0) and ($constant.unit | length > 0) and ($constant.source | length > 0) and ($known | index($constant.owner_task)) != null)
' "$TMP/decision-register.json" >/dev/null || fail "invalid decision constant ownership"
DECISION_DIGEST=$(jq -cS '.constant' "$TMP/decision-register.json" | sha256sum | awk '{print $1}')
[[ $DECISION_DIGEST == 22262e1bc49daacb1faa3f5bd716b47ea5b10561a41711f61d1b2012d99bd717 ]] || fail "decision register differs from frozen 44-entry map"

check_forbidden_api_tokens() {
  local document=$1 inventory=$2 token rust_blocks
  rust_blocks=$(mktemp "$TMP/api-rust.XXXXXX")
  awk '/^```rust$/{block=1; next} /^```$/{block=0} block' "$document" > "$rust_blocks"
  while IFS= read -r token; do
    ! rg -Fiq "$token" "$rust_blocks" || return 1
  done < <(jq -r '.forbidden_public_tokens[]' "$inventory")
}

check_api_inventory() {
  local inventory=$1 document digest item token rust_blocks
  digest=$(jq -cS '.' "$inventory" | sha256sum | awk '{print $1}')
  [[ $digest == 423c42a591fb233f8da35fd2ac9340fece6a6efe6ef43e7d5880e4732b573b42 ]] || return 1
  document=$(jq -r '.document' "$inventory")
  [[ $document == docs/api-manifest.md && -f $document ]] || return 1
  [[ $(sha256sum "$document" | awk '{print $1}') == "$(jq -r '.sha256' "$inventory")" ]] || return 1
  jq -e '
    (.node_handle_signatures | length) == 3
    and (.commands | length) == 16 and (.commands | unique | length) == 16
    and (.queries | length) == 18 and (.queries | unique | length) == 18
    and (.events | length) == 8 and (.events | unique | length) == 8
    and (.extension_traits | length) == 13 and (.extension_traits | unique | length) == 13
    and (.required_reexports | length) == 42 and (.required_reexports | unique | length) == 42
    and ([.commands[] | select(. == "CleanupState")] | length) == 1
  ' "$inventory" >/dev/null || return 1
  while IFS= read -r item; do
    rg -Fq "$item" "$document" || return 1
  done < <(jq -r '.node_handle_signatures[], .commands[], .queries[], .events[], .extension_traits[], .required_reexports[]' "$inventory")
  check_forbidden_api_tokens "$document" "$inventory"
}
check_api_inventory "$TMP/api-inventory.json" || fail "API inventory, digest, exports, or forbidden-token policy invalid"

check_evidence_sets() {
  local file=$1
  jq -e --slurpfile tasks "$TMP/task-verification.json" --slurpfile threats "$TMP/threat-model.json" '
    ($tasks[0].verification | map(.id)) as $verification_ids
    | ($tasks[0].task | map(.id)) as $task_ids
    | ($threats[0].threat | map(.id)) as $threat_ids
    | ([.path_rule[].id] | length) == ([.path_rule[].id] | unique | length)
    and all(.path_rule[];
      . as $rule
      | ($rule.globs | length) > 0
      and ($rule.verification_ids | length) > 0
      and ($rule.threat_ids | length) > 0
      and ($rule.precedence >= 0)
      and ($task_ids | index($rule.owner_task)) != null
      and all($rule.verification_ids[]; . as $verification | ($verification_ids | index($verification)) != null)
      and all($rule.threat_ids[]; . as $threat | ($threat_ids | index($threat)) != null)
    )
    and ([.shard[].id] | length) == ([.shard[].id] | unique | length)
    and ([.shard[].verification_ids[]] | sort) == ($verification_ids | sort)
    and all(.shard[]; .p95_seconds <= 600 and .p95_seconds > 0)
  ' "$file" >/dev/null
}
check_evidence_sets "$TMP/evidence-impact.json" || fail "invalid evidence-impact ownership or shards"
SHARD_DIGEST=$(jq -cS '.shard' "$TMP/evidence-impact.json" | sha256sum | awk '{print $1}')
[[ $SHARD_DIGEST == 67825920e3b496560fd63e64b915645a7ab5c8250809851d324e3a7c31808a7d ]] || fail "shard DAG differs from frozen G0-G10 layout"

mapfile -t PROJECT_FILES < <(
  {
    git ls-files
    git ls-files --others --exclude-standard
  } | sort -u | rg -v '^(target/|\.pi-subagents/|\.git/)'
)

path_rule_result() {
  local manifest=$1 path=$2 encoded rule precedence glob matched best=-1 owners=0
  while IFS= read -r encoded; do
    rule=$(printf '%s' "$encoded" | base64 --decode)
    precedence=$(jq -r '.precedence' <<<"$rule")
    matched=false
    while IFS= read -r glob; do
      if [[ $path == $glob ]]; then
        matched=true
        break
      fi
    done < <(jq -r '.globs[]' <<<"$rule")
    if $matched; then
      if (( precedence > best )); then
        best=$precedence
        owners=1
      elif (( precedence == best )); then
        ((owners += 1))
      fi
    fi
  done < <(jq -r '.path_rule[] | @base64' "$manifest")
  printf '%s %s\n' "$best" "$owners"
}

check_project_paths() {
  local manifest=$1 path best owners
  for path in "${PROJECT_FILES[@]}"; do
    read -r best owners < <(path_rule_result "$manifest" "$path")
    (( best >= 0 )) || return 1
    (( owners == 1 )) || return 1
  done
}
check_project_paths "$TMP/evidence-impact.json" || fail "unmapped or ambiguous evidence-affecting project path"

for document in docs/roadmap.md docs/development-gates.md docs/implementation-plan.md; do
  (( $(wc -l < "$document") <= 300 )) || fail "$document exceeds 300 lines"
done
[[ $(rg -c '^### G[0-9]+:' docs/development-gates.md) -eq 11 ]] || fail "development gate count mismatch"
[[ $(rg -c '^## G[0-9]+:' docs/implementation-plan.md) -eq 11 ]] || fail "implementation gate count mismatch"
[[ $(rg -c '^\| E2E-' docs/development-gates.md) -eq 10 ]] || fail "development E2E count mismatch"
for adr in docs/adr/000{1,2,3,4,5,6}-*.md; do
  rg -q '^status: accepted$' "$adr" || fail "unaccepted ADR: $adr"
done

if [[ ${1:-} == "--self-test" ]]; then
  jq '. + [.[0]]' "$TMP/scenarios.json" > "$TMP/negative-duplicate-scenario.json"
  if check_scenario_ids "$TMP/negative-duplicate-scenario.json"; then
    fail "duplicate-SC negative fixture was accepted"
  fi

  jq '.threat[0].mitigation = ""' "$TMP/threat-model.json" > "$TMP/negative-missing-mitigation.json"
  if check_threat_shape "$TMP/negative-missing-mitigation.json"; then
    fail "missing-mitigation negative fixture was accepted"
  fi

  jq '.path_rule += [(.path_rule[0] | .id = "IMPACT-AMBIGUOUS-DISTINCT")]' "$TMP/evidence-impact.json" > "$TMP/negative-ambiguous-path.json"
  if check_project_paths "$TMP/negative-ambiguous-path.json"; then
    fail "distinct equal-precedence path ambiguity was accepted"
  fi

  jq '.shard[0].verification_ids[0] = "VERIFY-UNKNOWN"' "$TMP/evidence-impact.json" > "$TMP/negative-invalid-shard.json"
  if check_evidence_sets "$TMP/negative-invalid-shard.json"; then
    fail "invalid-shard negative fixture was accepted"
  fi

  jq '.commands[0] = "NodeBuilder"' "$TMP/api-inventory.json" > "$TMP/negative-api-inventory.json"
  if check_api_inventory "$TMP/negative-api-inventory.json"; then
    fail "altered API inventory was accepted"
  fi

  cp docs/api-manifest.md "$TMP/negative-api-document.md"
  printf '\n```rust\npub fn leak() -> redb::Database;\n```\n' >> "$TMP/negative-api-document.md"
  if check_forbidden_api_tokens "$TMP/negative-api-document.md" "$TMP/api-inventory.json"; then
    fail "forbidden public API token was accepted"
  fi

  jq '(.verification[] | select(.state == "ready")).argv = ["env", "bash", "-c", "touch /tmp/planning-pwn"]' "$TMP/task-verification.json" > "$TMP/negative-hostile-argv.json"
  if check_argv_policy "$TMP/negative-hostile-argv.json"; then
    fail "hostile-argv negative fixture was accepted"
  fi
fi

printf 'planning validation: PASS (69 tasks, 226 SC, 10 E2E, 29 THR)\n'

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
  docs/scenario-catalog.toml
  docs/threat-model.toml
  docs/decision-register.toml
  docs/task-verification.toml
  docs/evidence-impact.toml
)
taplo lint --no-auto-config "${TOML_FILES[@]}" >/dev/null

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

verify_frozen_document() {
  local path=$1 expected=$2 actual
  actual=$(sha256sum "$path" | awk '{print $1}')
  [[ $actual == "$expected" ]] || fail "frozen planning document changed: $path"
}

verify_frozen_document docs/adr/0005-sixteen-node-slo-profile.md 26f5d67c84ad4331e5d2c33d699f4f107849933f15951cc5b6f76d6676447431
verify_frozen_document docs/adr/0007-core-responsibility-and-metadata.md cdc4851aef0ca0109077ab20ecd7298e7f2310b34eec1150003950554e689eab
verify_frozen_document docs/adr/0008-session-trust-membership-sync.md 3ab4573643e72e261bbf86cf01ee3646e37f7d439b178a1b6b1571898089953a
verify_frozen_document docs/roadmap.md 159a070efca404dace1a7140ef04fe94bc2338a644bc3e7311318af934bde99f
verify_frozen_document docs/development-gates.md 4faa7918fa79697d10e29be6b14fe3cc833436db2d2981c48d23075d86d455e4
verify_frozen_document docs/implementation-plan.md b86d2116166de002e0fc8ae1b7f8cfca1edfcf214ba685bbbdb3127c755b27ac
verify_frozen_document docs/api-manifest.md de2c782d411dc795714bb1e274eaf86cc88b60c4dbce11d115f3c74fa90a96e6
verify_frozen_document docs/api-inventory.toml 7e89e7fb773866b1b6b2be9bde5e79fbdc09bb690f91538f891989cc865c9d10
verify_frozen_document docs/decision-register.toml 19058685bbcc5df01c7cd5f2a8556ceda2597aaf800fe9b36db978c7d1be3a5d
verify_frozen_document docs/scenario-catalog.toml 022200bbeff389f8a8b76d8189055f0eee75b29523263f9456dd89bc212d002a
verify_frozen_document docs/threat-model.md 6f933d2abac26ce94542db5defc5cf83ae317c888e3afa2c6e5daab8e2be9f0d
verify_frozen_document docs/threat-model.toml 945e1a1c8fde32c47c5fa38bbe6f6ac763c4ce829f6e7d4ff42ced8b65a93ad4
verify_frozen_document docs/task-verification.toml 04d6c7a4f438d921f1468953c6fef3bdc24b5020c301caec9981fbd4323b01ed
verify_frozen_document docs/evidence-impact.toml 87d82c30f4537ba7e5219cb7d21722899e5e06f736813edb1cb8000887c334a7

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
        rebaseline: $set.cases[$index].rebaseline,
        threats: $set.cases[$index].threats
      }
  ]
' "$TMP/scenario-catalog.json" > "$TMP/scenarios.json"

check_scenario_ids() {
  local file=$1
  jq -e '
    length == 226
    and ([.[].id] | unique | length) == 226
    and all(.[]; (.id | test("^SC-G[0-9]{2}-P[01]-[0-9]{2}$")) and (.title | length > 0) and (.acceptance | length > 0) and (.rebaseline == "ADR-0007" or .rebaseline == "ADR-0008"))
  ' "$file" >/dev/null
}
check_scenario_ids "$TMP/scenarios.json" || fail "invalid, missing, or duplicate SC record"
[[ $(jq '.e2e | length' "$TMP/scenario-catalog.json") -eq 10 ]] || fail "expected ten E2E records"
[[ $(jq '[.e2e[].id] | unique | length' "$TMP/scenario-catalog.json") -eq 10 ]] || fail "duplicate E2E ID"
jq -e 'all(.e2e[]; (.id | test("^E2E-(0[1-9]|10)$")) and (.title | length > 0) and (.acceptance | length > 0) and .rebaseline == "ADR-0007")' "$TMP/scenario-catalog.json" >/dev/null || fail "invalid E2E record or stale responsibility marker"

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

check_g1_verification_map() {
  local file=$1
  jq -e '
    [
      {task: "T-G01-01", verification: "VERIFY-G01-01", argv: ["scripts/verify-g1-core.sh"]},
      {task: "T-G01-02", verification: "VERIFY-G01-02", argv: ["scripts/verify-g1-lifecycle.sh"]},
      {task: "T-G01-03", verification: "VERIFY-G01-03", argv: ["scripts/verify-g1-simulator.sh"]},
      {task: "T-G01-04", verification: "VERIFY-G01-04", argv: ["scripts/verify-g1-artifacts.sh"]},
      {task: "T-G01-05", verification: "VERIFY-G01-05", argv: ["scripts/verify-g1-closure.sh"]}
    ] as $expected
    | [.task[] | select(.id | startswith("T-G01-"))]
      == [$expected[] | {id: .task, verification_id: .verification, state: "ready", include_quality: true}]
    and [.verification[] | select(.owner_task | startswith("T-G01-"))]
      == [$expected[] | {id: .verification, owner_task: .task, state: "ready", argv, timeout_seconds: 1800}]
  ' "$file" >/dev/null
}
check_g1_verification_map "$TMP/task-verification.json" || fail "G1 verification map differs from the reviewed executable baseline"

check_g2_entry_map() {
  local file=$1
  jq -e '
    [
      {task: "T-G02-01", verification: "VERIFY-G02-01", state: "ready", argv: ["scripts/verify-g2-storage-contract.sh"]},
      {task: "T-G02-02", verification: "VERIFY-G02-02", state: "ready", argv: ["scripts/verify-g2-identity-records.sh"]},
      {task: "T-G02-03", verification: "VERIFY-G02-03", state: "ready", argv: ["scripts/verify-g2-json-adapter.sh"]},
      {task: "T-G02-04", verification: "VERIFY-G02-04", state: "ready", argv: ["scripts/verify-g2-crash-matrix.sh"]},
      {task: "T-G02-05", verification: "VERIFY-G02-05", state: "ready", argv: ["scripts/verify-g2-native-json.sh"]}
    ] as $expected
    | [.task[] | select(.id | startswith("T-G02-"))]
      == [$expected[] | {id: .task, verification_id: .verification, state, include_quality: true}]
    and [.verification[] | select(.owner_task | startswith("T-G02-"))]
      == [$expected[] | {id: .verification, owner_task: .task, state, argv, timeout_seconds: 1800}]
  ' "$file" >/dev/null
}
check_g2_entry_map "$TMP/task-verification.json" || fail "G2 entry map differs from the reviewed executable baseline"

check_g3_entry_map() {
  local file=$1
  jq -e '
    [
      {task: "T-G03-01", verification: "VERIFY-G03-01", state: "ready", argv: ["scripts/verify-g3-handshake.sh"]},
      {task: "T-G03-02", verification: "VERIFY-G03-02", state: "ready", argv: ["scripts/verify-g3-tls-transport.sh"]},
      {task: "T-G03-03", verification: "VERIFY-G03-03", state: "ready", argv: ["scripts/verify-g3-admission.sh"]},
      {task: "T-G03-04", verification: "VERIFY-G03-04", state: "ready", argv: ["scripts/verify-g3-selection.sh"]},
      {task: "T-G03-05", verification: "VERIFY-G03-05", state: "ready", argv: ["scripts/verify-g3-packet-streams.sh"]},
      {task: "T-G03-06", verification: "VERIFY-G03-06", state: "ready", argv: ["scripts/verify-g3-hostile.sh"]}
    ] as $expected
    | [.task[] | select(.id | startswith("T-G03-"))]
      == [$expected[] | {id: .task, verification_id: .verification, state, include_quality: true}]
    and [.verification[] | select(.owner_task | startswith("T-G03-"))]
      == [$expected[] | {id: .verification, owner_task: .task, state, argv, timeout_seconds: 1800}]
  ' "$file" >/dev/null
}
check_g3_entry_map "$TMP/task-verification.json" || fail "G3 entry map differs from the reviewed executable baseline"

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

check_threat_shape() {
  local file=$1
  jq -e '
    ["credential-guessing", "replay", "impersonation", "identity-clones", "sybil-admission", "stale-metadata", "protocol-downgrade", "route-amplification", "oversized-payloads", "slow-peers", "future-timestamps", "malicious-members", "secret-disclosure"] as $mandatory
    | [.threat[].id] == [range(1; 30) | "THR-" + (tostring | if length == 1 then "00" + . elif length == 2 then "0" + . else . end)]
    and ([.threat[].mandatory_key | select(length > 0)] | sort) == ($mandatory | sort)
    and all(.threat[]; .status == "accepted" and (.priority == "P0" or .priority == "P1") and (.mitigation | length) > 0 and (.residual | length) > 0 and (.scenario_ids | length) > 0)
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
    and ($threat.residual | length) > 0
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

jq -r '.[] as $scenario | $scenario.threats[] | [., $scenario.id] | @tsv' "$TMP/scenarios.json" > "$TMP/scenario-threat-links.tsv"
jq -r '.e2e[] as $scenario | $scenario.threats[] | [., $scenario.id] | @tsv' "$TMP/scenario-catalog.json" >> "$TMP/scenario-threat-links.tsv"
sort -u -o "$TMP/scenario-threat-links.tsv" "$TMP/scenario-threat-links.tsv"
jq -r '.threat[] as $threat | $threat.scenario_ids[] | [$threat.id, .] | @tsv' "$TMP/threat-model.json" | sort -u > "$TMP/threat-scenario-links.tsv"
if [[ -n $(comm -23 "$TMP/threat-scenario-links.tsv" "$TMP/scenario-threat-links.tsv") ]]; then
  fail "threat register references a scenario that does not reference the threat"
fi

jq -e --rawfile tasks "$TMP/plan-tasks.txt" '
  ($tasks | split("\n") | map(select(length > 0))) as $known
  | ([.constant[].id] | length) > 0
  and ([.constant[].id] | length) == ([.constant[].id] | unique | length)
  and all(.constant[]; . as $constant | ($constant.id | test("^[a-z0-9][a-z0-9.-]+$")) and ($constant.value | length > 0) and ($constant.unit | length > 0) and ($constant.source | length > 0) and ($known | index($constant.owner_task)) != null)
  and ([.constant[].id | select(. == "cluster.member-ceiling" or . == "protocol.inflight-requests-default" or . == "routing.trace-global-bytes-default" or . == "routing.trace-source-bytes-default" or . == "storage.json-bytes-default" or . == "clock.max-future-skew-default" or . == "clock.absolute-future-horizon")] | length) == 0
  and ([.constant[] | select(.id == "scale.functional-trend-members" and .value == "1024")] | length) == 1
  and ([.constant[] | select(.id == "admission.source-bucket-limit" and .value == "1024")] | length) == 1
  and ([.constant[] | select(.id == "wire.receive-frame-default" and .value == "65536")] | length) == 1
  and ([.constant[] | select(.id == "wire.decode-depth-default" and .value == "16")] | length) == 1
  and ([.constant[] | select(.id == "wire.collection-items-default" and .value == "1024")] | length) == 1
  and ([.constant[] | select(.id == "session.queued-messages-default" and .value == "256")] | length) == 1
  and ([.constant[] | select(.id == "runtime.anti-entropy-default")] | length) == 1
  and ([.constant[] | select(.id == "recovery.neighbor-target-default")] | length) == 1
  and ([.constant[] | select(.id == "recovery.fan-out-default")] | length) == 1
  and ([.constant[] | select(.id == "recovery.initial-backoff-default")] | length) == 1
  and ([.constant[] | select(.id == "recovery.maximum-backoff-default")] | length) == 1
  and ([.constant[] | select(.id == "trace.metadata-active-default")] | length) == 1
  and ([.constant[] | select(.id == "trace.metadata-terminal-default")] | length) == 1
  and ([.constant[] | select(.id == "storage.receipt-retention-default" and .value == "30")] | length) == 1
' "$TMP/decision-register.json" >/dev/null || fail "invalid decision constant shape, ownership, or responsibility boundary"

check_forbidden_api_tokens() {
  local document=$1 inventory=$2 token rust_blocks
  rust_blocks=$(mktemp "$TMP/api-rust.XXXXXX")
  awk '/^```rust$/{block=1; next} /^```$/{block=0} block' "$document" > "$rust_blocks"
  while IFS= read -r token; do
    ! rg -Fiq "$token" "$rust_blocks" || return 1
  done < <(jq -r '.forbidden_public_tokens[]' "$inventory")
}

check_api_inventory() {
  local inventory=$1 document item rust_blocks
  document=$(jq -r '.document' "$inventory")
  [[ $document == docs/api-manifest.md && -f $document ]] || return 1
  rust_blocks=$(mktemp "$TMP/api-inventory-rust.XXXXXX")
  awk '/^```rust$/{block=1; next} /^```$/{block=0} block' "$document" > "$rust_blocks"
  [[ $(sha256sum "$document" | awk '{print $1}') == "$(jq -r '.sha256' "$inventory")" ]] || return 1
  jq -e '
    (.node_handle_signatures | length) > 0 and (.node_handle_signatures | unique | length) == (.node_handle_signatures | length)
    and (.commands | length) > 0 and (.commands | unique | length) == (.commands | length)
    and (.queries | length) > 0 and (.queries | unique | length) == (.queries | length)
    and (.events | length) > 0 and (.events | unique | length) == (.events | length)
    and (.extension_traits | length) > 0 and (.extension_traits | unique | length) == (.extension_traits | length)
    and .extension_traits == [
      "Entropy",
      "KeyProvider",
      "StorageFactory",
      "Storage",
      "StoreSnapshot",
      "StoreScan",
      "Discovery",
      "PacketBody",
      "PacketConsumer",
      "NeighborPolicy",
      "LoadBalancingPolicy"
    ]
    and (.required_reexports | length) > 0 and (.required_reexports | unique | length) == (.required_reexports | length)
    and ((.commands + .queries + .events) | length) == ((.commands + .queries + .events) | unique | length)
    and (. as $inventory | all(($inventory.commands + $inventory.queries + $inventory.events)[]; . as $operation | (($inventory.extension_traits + $inventory.required_reexports) | index($operation)) == null))
    and ([.required_reexports[] | select(. == "OutboundPacket")] | length) == 1
    and ([.required_reexports[] | select(. == "ResourceName")] | length) == 1
    and ([.extension_traits[] | select(. == "StoreSnapshot")] | length) == 1
    and ([.extension_traits[] | select(. == "StoreScan")] | length) == 1
  ' "$inventory" >/dev/null || return 1
  while IFS= read -r item; do
    rg -Fq "$item" "$document" || return 1
  done < <(jq -r '.node_handle_signatures[], .required_reexports[]' "$inventory")
  while IFS= read -r item; do
    rg -Fq "pub struct $item" "$rust_blocks" || return 1
    rg -Fq "impl Command for $item" "$rust_blocks" || return 1
  done < <(jq -r '.commands[]' "$inventory")
  while IFS= read -r item; do
    rg -Fq "pub struct $item" "$rust_blocks" || return 1
    rg -Fq "impl Query for $item" "$rust_blocks" || return 1
  done < <(jq -r '.queries[]' "$inventory")
  while IFS= read -r item; do
    rg -Fq "pub struct $item" "$rust_blocks" || return 1
    rg -Fq "impl Event for $item" "$rust_blocks" || return 1
  done < <(jq -r '.events[]' "$inventory")
  while IFS= read -r item; do
    rg -Fq "pub trait $item" "$rust_blocks" || return 1
  done < <(jq -r '.extension_traits[]' "$inventory")
  rg -o '^pub (struct|enum|trait|type) [A-Za-z0-9_]+' "$rust_blocks" | awk '{print $3}' | sort > "$TMP/api-declared-names-all.txt"
  [[ ! -s $TMP/api-declared-names-all.txt ]] || [[ $(uniq -d "$TMP/api-declared-names-all.txt" | wc -l) -eq 0 ]] || return 1
  uniq "$TMP/api-declared-names-all.txt" > "$TMP/api-declared-names.txt"
  jq -r '[.commands[], .queries[], .events[], .extension_traits[], .required_reexports[]] | unique[]' "$inventory" | sort -u > "$TMP/api-inventoried-names.txt"
  diff -u "$TMP/api-declared-names.txt" "$TMP/api-inventoried-names.txt" >/dev/null || return 1
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
    and (
      (.shard | map({key: .id, value: .}) | from_entries) as $shards
      | def acyclic($id; $seen):
          if ($seen | index($id)) != null then false
          else all($shards[$id].depends_on[]; acyclic(.; $seen + [$id]))
          end;
        def path_seconds($id):
          $shards[$id].p95_seconds + ([$shards[$id].depends_on[] | path_seconds(.)] | max // 0);
        all(.shard[];
          . as $shard
          | ($shard.p95_seconds <= 600 and $shard.p95_seconds > 0)
          and ($shard.cadences | length) > 0
          and ($shard.cadences | unique | length) == ($shard.cadences | length)
          and all($shard.cadences[]; . == "merge" or . == "gate" or . == "nightly" or . == "weekly" or . == "release")
          and ($shard.cadences | index("merge")) != null
          and ($shard.cadences | index("gate")) != null
          and all($shard.depends_on[]; . as $dependency | ($shards | has($dependency)) and $dependency != $shard.id)
          and acyclic($shard.id; [])
          and path_seconds($shard.id) <= 600
        )
    )
  ' "$file" >/dev/null
}
check_evidence_sets "$TMP/evidence-impact.json" || fail "invalid evidence-impact ownership or shards"

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
for adr in docs/adr/000{1,2,3,4,5,6,7}-*.md; do
  rg -q '^status: accepted$' "$adr" || fail "unaccepted ADR: $adr"
done
for adr in docs/adr/000{1,2,3,4,6}-*.md; do
  rg -q 'Amended by ADR-0007' "$adr" || fail "ADR lacks ADR-0007 amendment marker: $adr"
done
rg -q '^amended: 2026-08-04$' docs/adr/0005-*.md || fail "ADR-0005 is not the re-ratified workload"
for stratum in 'Five fixed-admission samples' 'Five direct-packet samples' 'Five routed-packet samples' 'Five node-metadata samples' 'Five resource-metadata samples'; do
  rg -Fq "$stratum" docs/adr/0005-*.md || fail "ADR-0005 lacks exact revised stratum: $stratum"
done

ACTIVE_RESPONSIBILITY_DOCUMENTS=(
  docs/roadmap.md
  docs/development-gates.md
  docs/implementation-plan.md
  docs/api-manifest.md
  docs/decision-register.toml
  docs/scenario-catalog.toml
  docs/threat-model.md
  docs/threat-model.toml
  docs/evidence-impact.toml
)
LEGACY_ACTIVE_PATTERN='cluster\.member-ceiling|HlcTimestamp|DirectRequest|RoutedRequest|PutState|CleanupState|StateCodec|ClockHealth|with_member_limit|protocol\.inflight-requests|routing\.trace-(global|source)-bytes|storage\.json-bytes|clock\.max-future|clock\.absolute-future|at the hard 1,024-member ceiling|membership defaults to and cannot exceed|persisted HLC|peer clock health|future quarantine|payload journal|durable payload acceptance|Vec<(MemberView|TrustedIdentityView|ResourceView|TopologyEdgeView)>'

check_active_responsibility_terms() {
  ! rg -ni "$LEGACY_ACTIVE_PATTERN" "$@" >/dev/null
}
check_active_responsibility_terms "${ACTIVE_RESPONSIBILITY_DOCUMENTS[@]}" || fail "superseded semantics reintroduced in active planning documents"

rg -Fq 'allocates a core-generated `TraceId` synchronously' docs/api-manifest.md || fail "API does not allocate TraceId before body delivery"
rg -Fq 'pub enum PacketTarget' docs/api-manifest.md || fail "API lacks exact-node/resource packet target"
rg -Fq 'pub fn send_sync' docs/api-manifest.md || fail "API lacks synchronous packet delivery"
rg -Fq 'pub fn send_async' docs/api-manifest.md || fail "API lacks asynchronous route handle"
rg -Fq 'pub fn derive_return_packet' docs/api-manifest.md || fail "API lacks caller-derived endpoint-swapped packet"
rg -Fq 'pub trait StoreSnapshot' docs/api-manifest.md || fail "API lacks provider-owned snapshot SPI"
rg -Fq 'pub trait StoreScan' docs/api-manifest.md || fail "API lacks streaming scan SPI"
rg -Fq 'impl TransactionId' docs/api-manifest.md || fail "API lacks canonical TransactionId text contract"
rg -Uq 'impl RouteHandle \{\s+pub fn trace_id\(&self\) -> &TraceId;' docs/api-manifest.md || fail "route handle lacks direct TraceId access"
rg -Fq 'MatchingNodes(Selector)' docs/api-manifest.md || fail "API lacks node-label packet target"
rg -Fq 'fn capabilities(&self) -> KeyCapabilities;' docs/api-manifest.md || fail "key provider capability contract missing"
rg -Fq 'pub fn operations(&self) -> &[StoreOperation];' docs/api-manifest.md || fail "storage transaction is not inspectable"
rg -Fq 'pub fn new(items: Vec<EndpointCandidate>' docs/api-manifest.md || fail "discovery provider cannot construct pages"
rg -Fq 'pub fn new(peers: Vec<NodeId>)' docs/api-manifest.md || fail "neighbor policy cannot construct a plan"
! rg -Fq 'pub trait WallClock' docs/api-manifest.md || fail "public wall-clock injection reintroduced"
! rg -Fq 'pub fn timestamp(self' docs/api-manifest.md || fail "caller-controlled resource timestamp reintroduced"
rg -Fq 'ForgetReceipt { transaction: TransactionId' docs/api-manifest.md || fail "receipt cleanup operation missing"
rg -Fq '`Unknown` freezes later commits' docs/api-manifest.md || fail "unknown-commit freeze semantics missing"
rg -Fq 'There is no hard node-count ceiling.' docs/roadmap.md || fail "roadmap lacks no-ceiling responsibility"
rg -Fq 'current-process incoming-stream admission' docs/api-manifest.md || fail "API acknowledgement semantics missing"
rg -Uq 'never stores\s+body bytes' docs/api-manifest.md || fail "API no-body-storage rule missing"
rg -Fq 'gives no causal, freshness, or real-time guarantee' docs/api-manifest.md || fail "resource metadata caveat missing"
rg -Uq 'Rollback, freeze, and forward\s+jumps' docs/api-manifest.md || fail "wall-clock discontinuity caveat missing"

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

  jq '.shard[0].depends_on = [.shard[0].id]' "$TMP/evidence-impact.json" > "$TMP/negative-shard-cycle.json"
  if check_evidence_sets "$TMP/negative-shard-cycle.json"; then
    fail "cyclic-shard negative fixture was accepted"
  fi

  jq '.shard[1].depends_on = [.shard[2].id]' "$TMP/evidence-impact.json" > "$TMP/negative-slow-merge-path.json"
  if check_evidence_sets "$TMP/negative-slow-merge-path.json"; then
    fail "overlong merge critical path was accepted"
  fi

  jq '.shard[1].cadences = ["gate"]' "$TMP/evidence-impact.json" > "$TMP/negative-missing-merge-cadence.json"
  if check_evidence_sets "$TMP/negative-missing-merge-cadence.json"; then
    fail "shard without merge cadence was accepted"
  fi

  jq '.commands[0] = "NodeBuilder"' "$TMP/api-inventory.json" > "$TMP/negative-api-inventory.json"
  if check_api_inventory "$TMP/negative-api-inventory.json"; then
    fail "cross-category API inventory substitution was accepted"
  fi

  jq '(.events[0]) as $event | (.required_reexports | index("NodeBuilder")) as $index | .events[0] = "NodeBuilder" | .required_reexports[$index] = $event' "$TMP/api-inventory.json" > "$TMP/negative-event-category.json"
  if check_api_inventory "$TMP/negative-event-category.json"; then
    fail "cross-category event substitution was accepted"
  fi

  jq '(.extension_traits | index("PacketBody")) as $index | .extension_traits[$index] = "Command"' "$TMP/api-inventory.json" > "$TMP/negative-open-extension-category.json"
  if check_api_inventory "$TMP/negative-open-extension-category.json"; then
    fail "sealed trait accepted as an open extension"
  fi

  jq '.threat[0].residual = ""' "$TMP/threat-model.json" > "$TMP/negative-missing-residual.json"
  if check_threat_shape "$TMP/negative-missing-residual.json"; then
    fail "missing-residual negative fixture was accepted"
  fi

  cp docs/roadmap.md "$TMP/negative-legacy-active.md"
  printf '\npub struct HlcTimestamp;\n' >> "$TMP/negative-legacy-active.md"
  if check_active_responsibility_terms "$TMP/negative-legacy-active.md"; then
    fail "reintroduced superseded active term was accepted"
  fi

  jq '[.[] | if .id == "SC-G00-P0-01" then del(.rebaseline) else . end]' "$TMP/scenarios.json" > "$TMP/negative-stale-scenario.json"
  if check_scenario_ids "$TMP/negative-stale-scenario.json"; then
    fail "scenario without ADR-0007 evidence marker was accepted"
  fi

  cp docs/api-manifest.md "$TMP/negative-api-document.md"
  printf '\n```rust\npub fn leak() -> redb::Database;\n```\n' >> "$TMP/negative-api-document.md"
  if check_forbidden_api_tokens "$TMP/negative-api-document.md" "$TMP/api-inventory.json"; then
    fail "forbidden public API token was accepted"
  fi

  jq '(.verification[] | select(.id == "VERIFY-G01-03")).argv = ["scripts/verify-g1-core.sh"]' "$TMP/task-verification.json" > "$TMP/negative-g1-verification-map.json"
  if check_g1_verification_map "$TMP/negative-g1-verification-map.json"; then
    fail "substituted G1 verification argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G02-01")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-01")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-01")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g2-entry-map.json"
  if check_g2_entry_map "$TMP/negative-g2-entry-map.json"; then
    fail "substituted G2-01 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G02-02")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-02")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-02")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g2-02-entry-map.json"
  if check_g2_entry_map "$TMP/negative-g2-02-entry-map.json"; then
    fail "substituted G2-02 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G02-03")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-03")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-03")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g2-03-entry-map.json"
  if check_g2_entry_map "$TMP/negative-g2-03-entry-map.json"; then
    fail "substituted G2-03 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G02-04")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-04")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-04")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g2-04-entry-map.json"
  if check_g2_entry_map "$TMP/negative-g2-04-entry-map.json"; then
    fail "substituted G2-04 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G02-05")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-05")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G02-05")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g2-05-entry-map.json"
  if check_g2_entry_map "$TMP/negative-g2-05-entry-map.json"; then
    fail "substituted G2-05 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G03-01")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G03-01")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G03-01")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g3-01-entry-map.json"
  if check_g3_entry_map "$TMP/negative-g3-01-entry-map.json"; then
    fail "substituted G3-01 verification state/argv was accepted"
  fi

  jq '
    (.task[] | select(.id == "T-G03-02")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G03-02")).state = "planned"
    | (.verification[] | select(.id == "VERIFY-G03-02")).argv = []
  ' "$TMP/task-verification.json" > "$TMP/negative-g3-02-entry-map.json"
  if check_g3_entry_map "$TMP/negative-g3-02-entry-map.json"; then
    fail "substituted G3-02 verification state/argv was accepted"
  fi

  jq '(.verification[] | select(.state == "ready")).argv = ["env", "bash", "-c", "touch /tmp/planning-pwn"]' "$TMP/task-verification.json" > "$TMP/negative-hostile-argv.json"
  if check_argv_policy "$TMP/negative-hostile-argv.json"; then
    fail "hostile-argv negative fixture was accepted"
  fi
fi

printf 'planning validation: PASS (69 tasks, 226 SC, 10 E2E, 29 THR)\n'

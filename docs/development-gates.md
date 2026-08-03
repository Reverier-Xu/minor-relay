# Rapid Iteration Development Gates

## Reason for Existence

This document defines the evidence gates between the approved roadmap and a future implementation
task plan. It orders the smallest useful vertical slices, records real path dependencies, and fixes
the test architecture before production code is scheduled.

This is not the implementation backlog. It does not assign files, estimates, commits, owners, or
issue-sized tasks. Those are produced only after this gate plan is accepted.

## Gate Protocol

A gate has four states: `NOT_STARTED`, `ACTIVE`, `BLOCKED`, or `PASS`.

- Work enters a gate only after every listed dependency has passed.
- Parallel work is allowed only where the gate explicitly names a stable shared contract.
- A gate passes only from automated evidence; prose completion claims do not count.
- A skipped, quarantined, retried-until-green, or nondeterministic required test blocks the gate.
- Every failure must retain its seed, topology, event timeline, selected feature labels, storage
  fault point, and redacted node logs when those values apply.
- A downstream prototype may start early, but it cannot close a gate or freeze a public contract
  before its dependencies pass.

The standard repository quality suite is named `Q`:

```bash
taplo fmt --check
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

G1 adds production-only Clippy denials for `unwrap_used` and `expect_used`; `Q` enforces them from
that gate onward without forbidding deliberate assertions in test code.

## Corrected Path Dependencies

The roadmap milestones describe product scope, not strict implementation sequencing. Development
must preserve these cross-milestone dependencies:

1. Define the storage consumer contract before identity keys, clocks, descriptors, trace journals,
   or user records depend on persistence.
2. Prototype identity, credential admission, TLS WebSocket channel binding, and authenticated
   feature-label selection together; none can be accepted independently.
3. Close cluster-wide trust propagation only after signed admission-grant and trust-snapshot
   dissemination exists.
4. Close topology rerouting only after multi-hop routing exists.
5. Close durable trace delivery only after the trace journal passes crash tests.
6. Close label restart guarantees only after the resource record and mutation semantics exist.
7. After G3, every wire or persisted-format change adds a golden vector and previous-version
   contract fixture; G10 runs the final mixed-binary matrix.

## Verification Architecture

| Level | Primary scope | Required evidence |
| --- | --- | --- |
| Unit | Parsing, validation, ordering, selectors, limits, redaction, finite state transitions | Module-local tests cover valid, boundary, and invalid paths without panic |
| Property/model | IDs, envelopes, total order, LWW algebra, selectors, deduplication, state commands | Shrunk reproducible failures; P0 pure properties run 10,000 cases per merge and 100,000 nightly |
| Contract | Storage, discovery, session, codec, clock, registry, and public error traits | Every enabled implementation passes the same reusable semantic suite |
| Simulation | Directed links, virtual time, loss, duplication, reorder, partition, restart, skew, and churn | Same seed yields the same event digest; no wall-clock sleeps |
| Integration | Tokio task ownership, loopback sockets, TLS, WebSocket, filesystem, and redb | Real production I/O path with isolated ports, directories, keys, and cluster IDs |
| E2E | Public facade, multi-node delivery, restart, partition, mixed backend, and mixed binaries | No private module access or test-only protocol shortcuts |
| Security | Admission, transcript, replay, downgrade, secret handling, quotas, and hostile members | Every threat-model item maps to at least one negative test |
| Fuzz | Wire/persisted decoders, negotiation, admission/routing states, and selector parser | Regression corpus per merge; no crash, hang, OOM, or secret-bearing diagnostic |
| Soak | Churn, slow peers, retry storms, partitions, clocks, and state mutations | No invariant failure, resource bound violation, or residual task after quiescence |
| SLO | Sixteen-node convergence under the accepted network/workload profile | Every post-warm-up run is at most 10 seconds; host, sample count, exclusion policy, inputs, and all attempted samples are published |
| Platform/feature | Linux, macOS, Windows, default JSON, redb, and supported combinations | Native execution with zero warnings and backend contract parity |

## Harness Boundaries

- Use Tokio `test-util` and an injected clock for retry, keepalive, anti-entropy, and simulated skew.
  Real socket and filesystem assertions use real time and never share virtual-time deadlines.
- Use `proptest` for pure properties and generated command sequences. Generate an async scenario
  first, then execute it inside one Tokio runtime.
- A deterministic in-memory model is allowed inside the simulator, but no in-memory backend is
  shipped or used to claim storage acceptance.
- TLS WebSocket acceptance traverses loopback TCP, the production Rustls/WebSocket path, certificate
  validation, application authentication, and transcript/channel binding. `rcgen` may provide
  isolated test certificates.
- JSON and redb contract tests use unique `tempfile` directories. JSON durability uses same-directory
  replacement and explicit flush rules; redb tests use real transactions and integrity checks.
- Crash tests use a helper subprocess and deterministic kill points. In-process panic tests do not
  count as crash evidence.
- Public e2e tests bind `127.0.0.1:0`, avoid external networks, and never depend on test order,
  ambient credentials, shared databases, fixed ports, or IPv6 availability.
- Failed tests print a redacted replay command, seed, virtual timestamp, node/event timeline,
  topology, retry/queue/task maxima, feature selection, and storage fault point.
- `cargo-hack` validates feature powersets once storage features exist. `cargo-fuzz` is required for
  hardening. Loom is permitted only for small hand-owned synchronization primitives. Criterion is
  optional for microbenchmarks and is never the SLO oracle.

## Evidence Cadence

| Cadence | Required suite | Target |
| --- | --- | --- |
| Every merge | `Q` plus every available affected unit/property/contract, regression corpus, simulation seed, and e2e suite | At most 10 minutes |
| Gate closure | `Q` plus every applicable gate scenario; 1,000 simulation seeds and real I/O/crash tests once their harnesses exist | Fully automated pass |
| Nightly | 10,000 simulation seeds, native OS matrix, feature powerset, bounded fuzz runs, performance trends | No new failure or unbounded growth |
| Weekly | Eight-hour churn/partition/slow-peer soak | Return to baseline tasks and queues after quiescence |
| Release | Twenty-four-hour soak, extended fuzzing, mixed binaries, storage recovery, threat matrix, and SLO attestation | No unresolved P0/P1 finding |

Cadence rows apply only after the owning harness exists; G0 closes with documentation checks only.
Durations and case counts may change only through an evidence-backed test ADR. Reducing them to hide
flakiness is not allowed.

## Development Gates

### G0: Freeze the Decision Envelope

- **Build:** Accept ADRs for TLS bootstrap/channel binding, wire framing, authenticated negotiation,
  ID/key binding, storage transactions, trace retention/ACK boundaries, timestamp ordering, cleanup,
  feature policy, MSRV, functional `0.1.0`, test/fuzz budgets, corpus/target ownership, and failure
  replay policy; complete the threat model and typed command-bus API. Fix the 1,024-member ceiling,
  admission limits, revoke/content boundary, and exact 16-node SLO profile.
- **Depends on:** Approved `docs/roadmap.md` only.
- **Parallel:** ADR drafts and threat analysis may proceed independently, then reconcile shared
  schema, feature, size, time, retry, and durability constants.
- **Verify:** Validator expands 226 SC/ten E2E, 29 threats and one-owner constants; API/path/argv/negative fixtures pass.
- **Pass:** Decisions and threats close; `T-G01-01` can start without inventing API, scenario, constant, or evidence ownership.

### G1: Establish Deterministic Foundations

- **Build:** Domain-qualified IDs/tags, limits, errors, schema-tagged envelopes, Tokio lifecycle, injected
  clock/entropy, deterministic network simulator, topology fixtures, failure artifact capture, a
  minimal public lifecycle facade, and production-only `unwrap`/`expect` Clippy denials.
- **Depends on:** G0 ID, format, runtime, clock, and limit decisions.
- **Parallel:** Pure value types, lifecycle ownership, and simulator links/faults may proceed against
  frozen interfaces.
- **Verify:** `Q`; parser/order/round-trip properties; deterministic event-digest replay; virtual-time
  loss, duplication, reorder, partition, restart, address-change, and skew scenarios.
- **Pass:** M0 behavior and its minimal public facade are reproducible, bounded, tested, panic-free,
  and sufficient to remove the placeholder API.

### G2: Establish Persistence Consumers

- **Build:** Conditional cross-family transactions, snapshots/scans, committed/aborted/unknown
  reconciliation, immutable-generation JSON, secret-safe key provider, and canonical identity records.
- **Depends on:** G1 serialization, errors, test clock, and fault harness; G0 durability decisions.
- **Parallel:** Storage contract, JSON adapter, key provider, and crash helper may proceed after the
  canonical transaction boundary is fixed.
- **Verify:** Base/per-key conflicts; old/new/unknown JSON faults; fail-closed corruption, native locks,
  provider intents, ordered scans, capability-level refusal, schema/redaction, and pinned cargo-hack
  check/test powersets from the first `json` feature.
- **Pass:** Identity and genesis transactions reconcile authoritatively; a referenced key is never
  deleted and one credential generation never commits two subject bindings.

### G3: Prove the Two-Node Secure Vertical Slice

- **Build:** Two durable identities, empty-store cluster genesis, one API server, single-use rotating
  join credential, authenticated TLS WebSocket, transcript/channel binding, atomic admission records,
  feature-label selection, one registered request, and bidirectional session use.
- **Depends on:** G1 protocol/lifecycle primitives and G2 identity/trust persistence.
- **Parallel:** TLS fixtures, admission state machine, key proof, and direct dispatch may proceed only
  after canonical handshake messages and transcript fields are frozen.
- **Verify:** Real loopback TLS WebSocket e2e; replay, wrong channel/key/cluster/schema, feature-offer
  downgrade, credential leakage, rotation, and disconnect/reconnect; inject abort, response-loss, and
  unknown outcomes at every admission commit boundary and prove one subject per generation.
- **Pass:** Address plus credential admits a node; after disconnect or credential rotation, later
  traffic uses asymmetric trust only and both endpoints concurrently initiate over one session.

### G4: Generalize Sessions and Trust Propagation

- **Build:** Discovery/session registries, endpoint/readdress/crossed-dial lifecycle, backpressure,
  signed trust snapshots, trust query/sync, graceful replacement, and shutdown.
- **Depends on:** G3 authenticated direct session and accepted negotiation state machine.
- **Parallel:** Discovery/endpoints, session lifecycle, and signed admission dissemination may proceed
  against the immutable identity binding.
- **Verify:** Admit a node and prove reciprocal exact public-key trust with every online member; catch
  up an offline member by normal sync; disconnect the issuer and reconnect elsewhere only after both
  endpoints establish the other's key; also cover slow peers, readdressing, cancellation, and leaks.
- **Pass:** Direct sessions are reusable and bounded; public-key trust reaches every member, and all
  reconnection remains credential-free after join.

### G5: Prove Bounded Membership and Recovery

- **Build:** Signed monotonic descriptors, local liveness, digest anti-entropy, sparse cyclic neighbor
  policy, bounded maintenance, and the single-flight three-fixed-round plus one-fan-out recovery state.
- **Depends on:** G4 trusted sessions, endpoint lifecycle, crossed-dial handling, and cancellation.
- **Parallel:** Descriptor convergence and neighbor/recovery state machines may proceed after descriptor
  ownership, revision, and removal-marker rules are frozen.
- **Verify:** Seeded 16-node topology/SLO simulation plus 1,024-member functional scale trends; exact
  recovery counts, edge loss, bridge partition, restart, stale replay, readdressing, and storm bounds.
- **Pass:** Metadata meets the accepted SLO profile and topology repairs adjacency without claiming routed delivery.

### G6: Prove Reliable Multi-Hop Delivery

- **Build:** Source-signed request/attempt ordinals, 15-hop DATA/reverse-receipt envelopes, durable
  journals, persist-before-write, destination acceptance/dispatch gate, signed ACK/reject, count/byte
  quotas, 24h retention, alternate paths, and three source retries using the same trace.
- **Depends on:** G5 active topology, G4 dispatch/session path, and G2 transaction guarantees; G6
  defines and crash-qualifies its own trace records.
- **Parallel:** Route calculation, forwarding state machine, and model tests may proceed after the
  persist/forward/accept/ACK boundary is fixed.
- **Verify:** Three-hop public e2e; fault every DATA/receipt transaction and write boundary; forged
  ordinal/ACK/reject, handler, retry/quota, and conservative-age current/prior-boot, unknown-commit,
  rollback/jump/discontinuity/post-expiry tests; bridge failure and task-bound checks.
- **Pass:** Target acceptance is durable and deduplicated; ACK never claims handler success; M3 rerouting closes.

### G7: Prove Partition-Tolerant Replication

- **Build:** Signed opaque records, persisted HLC/watermark, authenticated clock samples, strict LWW,
  bounded future quarantine, tombstones, deltas/normal anti-entropy, and explicit local cleanup.
- **Depends on:** G6 routed dispatch, G5 membership, G2 storage contract, and G0 clock/cleanup decisions.
- **Parallel:** Comparator/clock model and anti-entropy may proceed after the canonical record and
  equal-version rules are fixed.
- **Verify:** HLC branches/exhaustion/crash atomicity; signature/comparator algebra; sample health;
  5s/absolute quarantine bounds and maturation; 8+8 sync; conservative retention age; tombstone
  restoration and acknowledged stale resurrection; deterministic 16-node SLO scenarios plus bounded
  32/64/128/256/512/1,024-member functional convergence trends with no larger-scale latency claim.
- **Pass:** Every online node converges deterministically without a reconnect-only merge path.

### G8: Qualify redb and Mixed Storage

- **Build:** Feature-gated redb, conditional transaction parity, integrity checks, explicit migration
  graph, unknown-outcome reconciliation, and backend capability reporting.
- **Depends on:** G7 canonical state transactions, G6 trace journal, and all earlier durable records.
- **Parallel:** redb adapter, feature CI, and crash fixtures may proceed against the frozen contract.
- **Verify:** JSON/redb parity; conflicts; process-kill reconciliation; provider create/delete intents
  and receipt cleanup; migration duplicate/cycle/ambiguity/no-path and old-or-new recovery; unsupported
  source/destination schema/older reader; feature powerset checks.
- **Pass:** Identity, trust, clock, descriptors, traces, tombstones, and values survive restart on both backends.

### G9: Complete Resources, Explicit Operations, and Facade

- **Build:** Versioned labels/resources, relaxed selector grammar, reserved platform/feature labels,
  atomic label/revoke/cleanup/active-leave operations, identity rotation, events, and completion of
  the established public facade.
- **Depends on:** G7 conflict semantics, G8 durable transactions, G5 metadata sync, and G6 operations.
- **Parallel:** Selector parser/property tests may start after G1; platform labels and facade work may
  proceed after resource records freeze.
- **Verify:** Concurrent label convergence, selector parity, local atomic fault injection, active-leave
  restart, JSON/redb persistence, native platform labels, and facade-only e2e without Lycoris types.
- **Pass:** User-directed metadata operations are atomic locally and connectivity maintenance never erases metadata.

### G10: Harden Compatibility and Attest `0.1.0`

- **Build:** Golden vectors, feature selection, mixed binaries, fuzz/soak attestations, native CI,
  public OCI SLO harness, immutable candidate, complete ledger, external token, tag, and publication.
- **Depends on:** G3 feature selection and every complete format/state transition from G4-G9.
- **Parallel:** Fuzz, vectors, native CI, soak, API/threat review, observability, and harness preparation
  may run after formats freeze; candidate evidence, complete-ledger validation, token, tag, and publish
  remain strictly sequential.
- **Verify:** `Q`; native matrices; mixed binaries; fuzz/soak/storage evidence; qualified OCI harness;
  125 exact-candidate SLO samples; complete attempt ledger; guarded token/tag/publish.
- **Pass:** Every roadmap criterion maps to exact-commit evidence, no P0/P1 remains, and the API/wire/
  storage baselines and guarded publication transition are approved for functional `0.1.0`.

## Required E2E Catalog

| ID | Scenario | Owner gate | Acceptance |
| --- | --- | --- | --- |
| E2E-01 | Secure join and credential rotation | G3 | Join succeeds once; reconnect ignores rotated join credential |
| E2E-02 | Outbound-only bidirectional session | G4 | Listener sends API traffic over the dialer's existing session |
| E2E-03 | Crossed dial and readdress | G4 | One owned session remains; identity and trust remain stable |
| E2E-04 | Sixteen-node recovery | G5 | Exact three fixed rounds and one fan-out; metadata meets SLO profile |
| E2E-05 | Three-hop ACK loss | G6 | One durable acceptance; duplicate re-ACK; at most three retries |
| E2E-06 | Eight-plus-eight partition merge | G7 | Same/disjoint keys and tombstones converge by normal sync tick |
| E2E-07 | JSON/redb crash and restart | G8 | State is old-or-new atomically and logical records converge |
| E2E-08 | Labels, revoke, cleanup, and leave | G9 | Explicit operations persist; automatic connectivity does not erase state |
| E2E-09 | Mixed binaries and feature/platform labels | G10 | Signed feature intersection controls behavior; labels accurately advertise support |
| E2E-10 | Published sixteen-node SLO | G10 | Every run is at most 10 seconds under the exact accepted profile |

E2E-01 through E2E-06 use the public facade in-process with real loopback I/O where applicable.
Crash/restart and mixed-binary cases use subprocesses. E2E-10 runs in a controlled benchmark
environment; ordinary shared CI records trends but is not the release SLO oracle.

## Test Framework Acceptance

The test framework itself passes only when:

1. Unit tests remain beside their owning modules; public behavior tests use only `tests/` and the facade.
2. A failed property or simulation test can be replayed from one retained seed and event digest.
3. Contract suites run unchanged against every enabled implementation.
4. Real TLS WebSocket, JSON, redb, and subprocess crash paths cannot be replaced by mocks at their gates.
5. Fault injection reaches every documented security, transaction, retry, and cleanup boundary.
6. Native Linux, macOS, and Windows jobs exercise filesystem, process, socket, TLS, and timer behavior.
7. Logs/artifacts contain no credential, key, opaque value, address/path, or sensitive transcript;
   replay is a closed executable ID plus validated argv, never a shell command.
8. Tests assert task, queue, cache, frame, retry, and fan-out bounds and return to baseline after shutdown.
9. No required gate relies on sleep-based timing, test-order dependence, external networking, or CI reruns.
10. G0 assigns stable IDs to 226 scenarios and 29 threat rows, freezes the typed command-bus API,
    decision constants, evidence paths, and task argv before the owning gate begins; IDs are never reused.

## Handoff to Implementation

The executable decomposition is defined in the
[Implementation Task Plan](implementation-plan.md). Its 69 issue-sized tasks name gate ownership,
predecessor artifacts, scenario IDs, public/API impact, expected files, focused commands, and
rollback boundaries. No production task starts before its dependencies and G0 ID ratification pass.

Verify this plan with:

```bash
test -f docs/development-gates.md
test "$(wc -l < docs/development-gates.md)" -le 300
test "$(grep -c '^### G[0-9]' docs/development-gates.md)" -eq 11
test "$(grep -c '^| E2E-' docs/development-gates.md)" -eq 10
```

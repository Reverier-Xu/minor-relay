# Rapid Iteration Development Gates

## Reason for Existence

This document orders the 69 stable implementation tasks and their evidence. ADR-0007 reopened G0 and
superseded conflicting active semantics. No production gate may resume until the rebaselined G0 passes.

## Gate Protocol

A gate is `NOT_STARTED`, `ACTIVE`, `BLOCKED`, or `PASS`.

- A gate passes only from automated evidence for its current predicates. Evidence for superseded
  predicates does not count.
- Work enters a gate only after dependencies pass. Existing code is re-evaluated instead of presumed
  complete.
- Required failures, skips, nondeterminism, or retries-until-green block closure.
- Failure artifacts retain replay seed, wall-clock observations, topology, selected features, route
  status, storage fault point, and redacted logs where applicable.
- All collections and work are finite, but population size is not a product limit. Member, trust,
  resource, topology, and policy-input evidence uses pages, streams, or incremental observations.

`Q` is the repository quality suite documented in `AGENTS.md` and `task-verification.toml`.

## Corrected Path Dependencies

1. Rebaseline the public contract, scenarios, threats, constants, and evidence before production work.
2. Define internal metadata storage before identity, trust, node revisions, trace metadata, or resources
   depend on it.
3. Prove fixed admission, TLS exporter binding, and authenticated feature intersection together.
4. Prove exact-node packet streaming before multi-hop and selector delivery.
5. Prove signed node revisions before topology recovery and resource metadata before selector routing.
6. Prove provider-owned snapshots, streaming scans, conditional transactions, reconciliation, and
   capability refusal before JSON/redb parity or migrations.
7. After G3, every wire or persisted metadata change adds current and previous fixtures.

## Verification Architecture

| Level | Required evidence |
| --- | --- |
| Unit/property | Parsing, canonical text, tuple ordering, selectors, finite limits, and state machines cover valid/boundary/invalid paths |
| Contract | Key, storage, transport, discovery, packet consumer, policy, and provider implementations share reusable suites |
| Simulation | Directed links, loss, reorder, partition, restart, readdress, and `SystemTime` rollback/freeze/jump replay by seed |
| Integration | Real Tokio, TLS 1.3 WebSocket, filesystem, JSON, redb, process crash, and lock paths |
| E2E | Public facade proves admission, packet streams, metadata convergence, restart, and mixed binaries |
| Security | Every accepted threat maps to negative scenarios and typed bounded failure |
| Fuzz/soak | Wire, packet, metadata, storage, admission, negotiation, routing, and selectors preserve invariants and baselines |
| SLO/scale | Revised 16-node workload supplies latency evidence; 1,024 nodes supply mandatory functional/trend evidence only |
| Platform | Native Linux, macOS, Windows and feature powersets pass with zero warnings |

## Harness Boundaries

- Tests inject wall-clock observations internally. Production semantics always use host `SystemTime`;
  executor timers only wake work to re-read wall time.
- Packet tests use streams larger than frame and queue capacities, assert constant memory/backpressure,
  and prove body bytes never enter storage or artifacts.
- Crash/restart and disconnect terminate active streams explicitly. No test helper continues a body.
- Storage contract tests consume provider-owned immutable snapshots by exact lookup and unsigned-byte
  ordered scan streams; they do not materialize the whole store.
- JSON is a test backend; redb is production; external SPI implementations run the same contract.
- Public E2E tests use only the facade and contain no business object, workload scheduler, or deployment
  behavior.
- Failed tests print closed replay argv, never shell text, and redact credentials, keys, provider
  handles, body bytes, paths, and addresses.

## Evidence Cadence

| Cadence | Required suite | Target |
| --- | --- | --- |
| Every merge | `Q` plus affected unit/property/contract/regression/simulation/E2E | At most 10 minutes |
| Gate closure | `Q`, all owned scenarios, 1,000 seeds, and available real I/O/crash contracts | Automated pass |
| Nightly | 10,000 seeds, native matrix, feature powerset, bounded fuzz, 1,024-node trend | No invariant failure or unbounded growth |
| Weekly | Eight-hour packet/metadata/connectivity churn | Return to resource baseline |
| Release | Twenty-four-hour soak, mixed binaries, storage recovery, threats, revised SLO | No unresolved P0/P1 |

## Development Gates

### G0: Rebaseline Core Responsibility

- **Build:** Keep existing stable IDs while freezing ADR-0007 product, packet, metadata, time, storage,
  population-query, threat, API, and evidence ownership. Retain the complete fixed admission policy.
- **Depends on:** Accepted ADR-0007.
- **Verify:** Planning validator expands exactly 69 tasks, 226 SC, ten E2E, and 29 THR; verifies shape,
  ownership, digests, API content, and rejects reintroduced superseded active semantics.
- **Pass:** Active documents agree; old evidence cannot match revised acceptance text; G1 may resume.

### G1: Establish Deterministic Foundations

- **Build:** Canonical IDs/tags including text-roundtripping `TransactionId`, checked caller-selected
  finite limits, errors, Tokio lifecycle, sealed bus, injected entropy, no production wall-clock read
  before an owned deadline exists, simulator time separation, and secret-safe replay artifacts.
- **Depends on:** G0.
- **Verify:** `Q`; namespace/text/encoding properties; lifecycle and injected entropy; no ambient G1
  wall-clock read; deterministic scheduler/wall-time rollback, freeze, and jump replay; checked time
  arithmetic; artifact redaction and closed argv.
- **Pass:** The minimal facade and deterministic harness contain only approved responsibilities.

### G2: Establish Internal Metadata Persistence

- **Build:** Provider-owned immutable snapshots, exact lookup, ordered streaming scans, conditional
  cross-family transactions, receipts/reconciliation/capabilities, key intents, identity records, JSON.
- **Depends on:** G1 and G0 storage boundary.
- **Verify:** Transaction text roundtrip; base/per-key conflict; committed/aborted/conflict/unknown;
  crash/lock/corruption; resource exhaustion without truncation; key custody; feature powersets.
- **Pass:** Core metadata reconciles authoritatively with no body/business bytes or core storage quotas.

### G3: Prove the Two-Node Secure Packet Slice

- **Build:** Genesis, fixed admission, TLS 1.3 WebSocket exporter binding, exact feature intersection,
  immediate trace allocation, exact-node outgoing and incoming ordered streams, current-process ACK.
- **Depends on:** G1 and G2.
- **Verify:** Real loopback join and bidirectional packet E2E; fixed admission abuse matrix; malformed,
  replay, downgrade, disconnect, stream-order, and no-storage cases.
- **Pass:** Either endpoint streams opaque packets; interruption is explicit and no conversation
  semantics exist in core.

### G4: Generalize Sessions and Trust

- **Build:** Transport/discovery registries, node-owned endpoint revisions, readdress/crossed-dial,
  bounded queues, signed trust snapshots, paged trust queries, replacement, shutdown.
- **Depends on:** G3.
- **Verify:** Reciprocal trust, offline catch-up, alternate-peer reconnect, slow peer, backpressure,
  replacement, cancellation, wall-clock deadlines, and leak baselines.
- **Pass:** Authenticated sessions and trust remain reusable, bounded, and credential-free after join.

### G5: Prove Membership, Topology, and Recovery

- **Build:** Signed node-owner revisions, paged membership/topology, incremental policy observations,
  sparse neighbors, reachability, and configurable continuous recovery with immediate-recovery command.
- **Depends on:** G4.
- **Verify:** Revision conflict/replay; paging across changes; recovery activation/stop/reactivation;
  partitions; 16-node readiness; 1,024-node functional/trend evidence without rejection boundary.
- **Pass:** Known online members regain an authenticated path without whole-population APIs or full mesh.

### G6: Prove Multi-Hop Packet Streams

- **Build:** Exact-node/matching-node-label targets, caller-selected load balancing/routing, constant-memory
  ordered forwarding, sync ACK/route error, async handle/status, selected destination, trace metadata.
- **Depends on:** G5, G4, and G2.
- **Verify:** Three-hop E2E; selector choice; large/slow streams; backpressure; disconnect/restart; route
  error; status/retention; body absence from storage; `SystemTime` discontinuities.
- **Pass:** Delivery is explicit and bounded; no body persistence, continuation, or core conversation.

### G7: Prove Core Metadata Convergence

- **Build:** Signed owner-only node revisions and generic named resources with reserved type/URI labels,
  custom labels, timestamp/writer/removal/digest ordering, pages, selectors, and normal repair.
- **Depends on:** G6, G5, and G2.
- **Verify:** Signature/revision/tuple algebra; equal timestamp; rollback; future dominance; partitions;
  URI non-following; paging; explicit no-causality/no-freshness behavior; revised 16-node workload.
- **Pass:** Core metadata converges deterministically without business records or peer-clock machinery.

### G8: Qualify redb and Mixed Metadata Storage

- **Build:** redb, contract parity, integrity, migration graph, reconciliation, and capability reporting.
- **Depends on:** G7 and G2.
- **Verify:** JSON/redb/external-provider parity; streaming scan order; crash/conflict; migration
  interruption/refusal; mixed restart; typed exhaustion; feature powersets.
- **Pass:** Identity, trust, node, resource, route, receipt, and schema metadata survive as specified.

### G9: Complete Resource Operations and Facade

- **Build:** Resource writes/removals/labels/selectors, revoke, leave/rotation, recovery command, route
  status/events, paged population queries, and final sealed facade.
- **Depends on:** G8, G7, G6, and G5.
- **Verify:** Multiwriter convergence; selector parity; revoke/leave crash paths; URI non-deletion;
  no whole-population vectors; public-facade E2E.
- **Pass:** Explicit operations affect only core metadata and key intents.

### G10: Harden Compatibility and Attest `0.1.0`

- **Build:** Golden vectors, mixed binaries, packet/metadata/storage fuzzing, native CI, soak, external
  OCI harness, revised 16-node workload, immutable candidate, ledger, token, and publication guards.
- **Depends on:** Every prior gate.
- **Verify:** `Q`; native/features; fuzz/soak; 1,024-node functional trend; 125 revised-workload samples;
  complete attempt lineage; negative evidence and release fixtures.
- **Pass:** API/wire/metadata baselines and exact-candidate evidence are approved with no P0/P1 finding.

## Required E2E Catalog

| ID | Scenario | Owner gate | Acceptance |
| --- | --- | --- | --- |
| E2E-01 | Secure join and credential rotation | G3 | Fixed admission succeeds once; trusted reconnect ignores later credential rotation |
| E2E-02 | Outbound-only bidirectional packet session | G4 | Either endpoint admits incoming packet streams on the existing session |
| E2E-03 | Crossed dial and readdress | G4 | One session remains and node-owned endpoint revisions preserve identity |
| E2E-04 | Sixteen-node recovery | G5 | Configured recovery reaches connected authenticated paths and quiesces |
| E2E-05 | Three-hop packet interruption | G6 | Ordered bytes or explicit failure; ACK means current-process stream admission only |
| E2E-06 | Eight-plus-eight metadata merge | G7 | Node revisions/resources converge by their distinct approved rules |
| E2E-07 | JSON/redb crash and restart | G8 | Internal metadata is old-or-new and scans remain ordered |
| E2E-08 | Resources, revoke, and leave | G9 | Operations preserve external objects and affect only core metadata/key intents |
| E2E-09 | Mixed binaries | G10 | Authenticated feature intersection preserves packet and metadata compatibility |
| E2E-10 | Revised sixteen-node SLO | G10 | All 125 samples use admission, packets, node revisions, and resources |

## Test Framework Acceptance

The framework passes only when retained seeds replay exactly, contract suites run unchanged across
providers, real I/O is not replaced at acceptance gates, wall-clock discontinuities are explicit,
population evidence is streamed/paged, body bytes never enter storage/artifacts, and every stable ID has
one current owner. G0 validation is itself negative-tested.

## Handoff to Implementation

[Implementation Plan](implementation-plan.md) owns the 69 stable task rows. No production task resumes
until reopened G0 passes. A task handoff uses the current row and scenarios, never superseded evidence.

```bash
test -f docs/development-gates.md
test "$(wc -l < docs/development-gates.md)" -le 300
test "$(grep -c '^### G[0-9]' docs/development-gates.md)" -eq 11
test "$(grep -c '^| E2E-' docs/development-gates.md)" -eq 10
```

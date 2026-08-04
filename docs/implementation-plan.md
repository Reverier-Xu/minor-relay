# minor-relay Implementation Task Plan

## Reason for Existence

This document is the executable backlog derived from [Development Gates](development-gates.md).
It defines issue-sized vertical tasks, exact dependencies, expected ownership, public API impact,
automated evidence, and rollback boundaries. It schedules no production work by itself.

G0 is complete. `T-G01-01` is the only dependency-eligible production task; every other production task remains
`BLOCKED` until its listed predecessors pass. Before RED, a task registers literal verification argv
and changes its task-verification state from `planned` to `ready`.

## Task Contract

- Each task targets one observable behavior and should fit within roughly three engineering days.
- Each task starts `failing`, follows red-green-refactor, passes every focused command, then passes `Q`.
- `P0` covers security, data loss, convergence, or critical availability; `P1` covers core behavior;
  `P2` covers bounded utilities or documentation. Security is `H`, `M`, `L`, or `N`.
- Dependency shorthand such as `03-01` means `T-G03-01`; `G3 PASS` means every G3 task passed.
- Scenario IDs use `SC-Gxx-Pn-nn`; `E2E-01` through `E2E-10` have exactly one owning closure task.
  G0 ratifies 226 SC, ten E2E, and immutable `THR-001` through `THR-029` records.
- T-G00-06 freezes `docs/api-manifest.md` as a sealed typed command/query/event bus with exact
  signatures and `src/lib.rs` reexports. API tasks implement it or amend it before RED; no writer invents API.
- After G3, every wire or persisted-format task updates `tests/fixtures/format-manifest.toml`, adds a
  current golden vector and a previous-version fixture, and runs the compatibility contract.
- Gate closure runs `Q` plus every scenario owned by that gate. `docs/task-verification.toml` and
  `scripts/verify-task.sh` own literal argv; planned tasks register commands and become ready before RED.
  G0-01 through G0-05 retain accepted inline checks because they predate the dispatcher.
- A task never closes on a mock where its gate requires real I/O. Workflow changes run `act` when
  Docker is available; otherwise run all CI commands locally and require a passing pushed Actions run.

Rollback codes:

- `R0`: Revert independently; no public, wire, or persisted compatibility exists.
- `R1`: Revert only before any listed dependent lands; remove unshipped fixtures/test data with it.
- `R2`: Disable the capability but retain readers, tags, migrations, and fixtures for written formats.
- `R3`: Irreversible security/data action; recover only through a forward operation or migration.

## Package Decision Register

| Candidate | Status | Earliest task | Constraint |
| --- | --- | --- | --- |
| Tokio | `[OK]` 1.53.1 | T-G01-02 | Minimal named features; `test-util` only for tests |
| Rustls stack | `[OK]` rustls 0.23.37, tokio-rustls 0.26.4, tokio-tungstenite 0.30.0 | T-G03-02 | Defaults/TLS1.2 off; one ring provider; no native TLS |
| `minicbor` | `[OK]` 2.3.0 | T-G01-01 | Deterministic CBOR with explicit IDs/golden vectors |
| Crypto/support | `[OK]` ed25519-dalek 3.0, hkdf/hmac 0.13, sha2 0.11, base64 0.23 | T-G01-01 | No secret serde; base64 SIMD-unsafe off |
| JSON support | `[OK]` serde/json 1.0, fs4 1.1, atomic-write-file 0.3, rustix 1.1 | T-G02-03 | Optional `json`; observable safe lock/file/directory barriers; test-only adapter |
| `redb` | `[OK]` 4.1.0 | T-G08-02 | Optional `redb`; no unconditional type leaks |
| Dev tools | `[OK]` proptest 1.11, tempfile 3.27, rcgen 0.14.8 | First owning tests | Test-only and retained failures |
| CI tools | `[OK]` cargo-hack 0.6.45, cargo-fuzz 0.13.2, semver-checks 0.50, deny 0.20 | G2/G10 | Pinned tools, not crate dependencies |
| Planning tools | `[OK]` Bash 5.2+, Taplo 0.10+, jq 1.8+ | T-G00-06 | Structured TOML/JSON and literal argv only; no eval/generated shell |

Any new package requires G0 slopcheck and an explicit plan amendment before use.

## Reason for Depth

| Abstraction | Reason |
| --- | --- |
| Injected clock/entropy | Deterministic timing, retry, skew, and generated identity replay |
| Storage contract | JSON and redb need identical atomicity, crash, migration, and error semantics |
| Discovery/transport registries | Extensions must not require central type switches |
| Deterministic simulator | Directed reachability, partitions, duplication, restart, and churn need replay |
| Durable trace journal | Persist-before-forward and duplicate re-ACK must survive process loss |
| Public facade | Wire, backend, and task internals must remain replaceable after API stabilization |

## Critical Path

`G0 -> G1 -> G2 -> G3 -> G4 -> G5 -> G6 -> G7 -> G8 -> G9 -> G10`

Parallel work is permitted only where rows share passed predecessors. Gate acceptance waits for all
tasks. Selector parsing (`T-G09-02`) may be prototyped after G1, but its API remains blocked by G9.

## G0: Decision Envelope

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G00-01 Identity/bootstrap/channel ADR | P0/H | Roadmap | Fix IDs, keys, credential admission, TLS bootstrap/binding, replay and key loss; no API | `docs/adr/0001-identity-bootstrap-and-channel-binding.md` | SC-G00-P0-01..02; accepted ADR check | R0 |
| T-G00-02 Wire/features/delivery ADR | P0/H | 00-01 | Fix CBOR prelude/limits, signed feature intersection, TraceId, 24h retention, ACK and four ordinals | `docs/adr/0002-wire-negotiation-and-delivery.md` | SC-G00-P0-03..05; accepted ADR check | R0 |
| T-G00-03 Persistence/HLC/cleanup ADR | P0/M | 00-01,02 | Fix conditional transactions, generation durability, HLC/skew/quarantine, migration and cleanup risk | `docs/adr/0003-persistence-ordering-and-cleanup.md` | SC-G00-P0-06..07; accepted ADR check | R0 |
| T-G00-04 Toolchain/features/evidence ADR | P1/L | 00-02,03 | Fix Rust 1.97.1, additive features/dependencies, 0.1 token, budgets, corpora and safe replay | `Cargo.toml`, `docs/adr/0004-toolchain-features-and-test-evidence.md` | SC-G00-P1-01..02; accepted ADR plus metadata checks | R0 |
| T-G00-05 Sixteen-node OCI SLO ADR | P1/N | 00-02,03,04 | Fix host/container/bridge/redb/topology/workload/readiness, 125 samples and no-exclusion rule | `docs/adr/0005-sixteen-node-slo-profile.md` | SC-G00-P1-03..04; accepted ADR/profile checks | R0 |
| T-G00-06 Threat/scenario/API reconciliation | P0/H | 00-01..05 | Freeze 1,024 members, admission/revoke semantics, typed bus, 226 SC/ten E2E/29 THR, constants, impact and argv | ADR-0006, planning manifests, `scripts/{validate-planning-docs,verify-task}.sh` | SC-G00-P0-08..09; `scripts/verify-task.sh T-G00-06` | R0 |

## G1: Deterministic Foundation

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G01-01 Core values/envelopes | P0/M | 00-06 | Export manifest IDs/tags/errors/config with 1,024-member ceiling; private prelude/deterministic CBOR | `Cargo.toml`, `Cargo.lock`, `src/{config,error}.rs`, `src/identity/id.rs`, `src/protocol/{tag,envelope}.rs` | SC-G01-P0-01, SC-G01-P1-01..02; value/namespace/CBOR/bound properties | R1 |
| T-G01-02 Tokio lifecycle/typed bus | P0/L | 01-01 | Implement manifest sealed Command/Query/Event, NodeBuilder/NodeHandle, Clock/Entropy, start/shutdown; declare exact builder-required storage/key SPI without invoking it; bound event capacity at default 256/max 1,024 | manifests, `src/{api,node,runtime}/*`, `src/lib.rs`, lifecycle test | SC-G01-P0-02, SC-G01-P1-03; public typed-bus lifecycle/clock contract | R1 |
| T-G01-03 Deterministic network simulator | P0/L | 01-01,02 | Model directed links, virtual time, bounded count/bytes, delay, loss, one duplicate, reorder, overlapping partitions, heal, restart, address change and skew; no API | `Cargo.toml`, `Cargo.lock`, private `src/lib.rs` wiring, `src/simulation/{mod,network,event,topology}.rs` | SC-G01-P0-03, SC-G01-P1-04; `MINOR_RELAY_SIM_SEEDS=1000 cargo test --locked --lib simulation_network_fault_matrix` | R0 |
| T-G01-04 Unified failure artifact/replay | P0/M | 01-03 | Implement a publish-false internal test-support crate with bounded producer-neutral allowlisted artifact schema and closed replay argv; keep simulator adapters private and add no `minor_relay` facade API | `Cargo.toml`, `Cargo.lock`, `test-support/**`, `src/simulation/{mod,scenario,fixture,artifact,redaction}.rs`, `tests/fixtures/failure-artifacts/*` | SC-G01-P0-04..05; forbidden-field/injection/provenance/write-path/truncation/normalization and byte-stable simulation tests | R0 |
| T-G01-05 G1 facade/MSRV/lint closure | P0/M | 01-01..04 | Facade proof, Rust 1.97.1/stable jobs, locked deps, deny checks and production panic denials | `src/lib.rs`, `test-support/src/lib.rs`, `tests/foundation_public.rs`, `deny.toml`, `scripts/check-dependency-graph.sh`, `scripts/verify-g1-closure.sh`, `.github/workflows/quality_check.yml` | SC-G01-P0-06..07; external facade lifecycle, private/absent path doctests, MSRV/stable locked Q, exact resolved dependency baseline, cargo-deny and Clippy `-D warnings` | R0 |

## G2: Identity Persistence

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G02-01 Conditional storage contract | P0/M | 01-05 | Implement the declared storage SPI: snapshot/per-key CAS, cross-family batch, TxnId receipt lifetime/reconciliation, scans/capabilities/errors | `src/storage/{contract,error,contract_tests}.rs` | SC-G02-P0-01, SC-G02-P1-01; conflict/order/unknown plus pending-reference-safe receipt cleanup | R1 |
| T-G02-02 Identity/genesis/admission records | P0/H | 02-01,01-01 | Implement the declared key SPI and version `IdentityBinding`, `ClusterGenesis`, `CredentialUse`, `AdmissionGrant`; secret-safe provider behavior | `src/identity/{records,key_provider}.rs`, `src/storage/record.rs` | SC-G02-P0-02..03; uniqueness, indeterminate-commit reconciliation and redaction properties | R1 |
| T-G02-03 JSON immutable-generation adapter | P0/M | 02-01,02 | JSON lock/checksummed chain/capability levels plus first complete feature-powerset CI | `Cargo.toml`, `Cargo.lock`, JSON modules, `.github/workflows/quality_check.yml` | SC-G02-P0-04, SC-G02-P1-02; pinned cargo-hack check/test for no-default/default/all combinations | R1 |
| T-G02-04 JSON/provider crash matrix | P0/M | 02-03,01-04 | Fault key create/delete intents, write/flush/rename/reopen barrier, response and temp cleanup | `src/storage/json/{fault,crash_tests}.rs`, key-provider crash fixtures | SC-G02-P0-05..06; old/new/unknown, receipt retention, all-final chain and referenced-key non-deletion | R0 |
| T-G02-05 JSON native robustness | P0/H | 02-04 | Native path-alias locks, invalid-highest fail-close, directory/delete errors and unsupported capabilities | JSON modules, `src/storage/error.rs`, `.github/workflows/quality_check.yml` | SC-G02-P0-07, SC-G02-P1-03; native suite plus `act`/local Q and pushed run | R0 |

## G3: Secure Two-Node Vertical Slice

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G03-01 Authenticated handshake/vectors | P0/H | G2 PASS | Genesis receiver plus domain feature/limit registries, definition digests and private offer states | `src/identity/admission.rs`, `src/protocol/{handshake,features}.rs`, handshake/registry fixtures | SC-G03-P0-01..04; invalid graph/digest/namespace mutation and handshake vector contracts | R1 |
| T-G03-02 Real TLS WebSocket request | P0/H | 03-01 | Implement manifest typed Listen/JoinCluster/DirectRequest over real WSS | transport/frame, typed bus, `tests/secure_two_node.rs` | SC-G03-P0-05..06; exact real-join integration test | R1 |
| T-G03-03 Atomic admission/reconciliation | P0/H | 03-02 | Commit binding/use/grant once; quarantine and reconcile unknown outcome; recover lost response | `src/identity/{admission,records}.rs`, `src/node/direct.rs`, `tests/admission_crash.rs` | SC-G03-P0-07..09; fault every commit/response boundary and forbid two subjects per generation | R2 |
| T-G03-04 Feature selection/disconnect/reconnect | P0/H | 03-03 | Signed feature-definition intersection/effective limits; no fallback; credential-free reconnect | `src/protocol/features.rs`, `src/identity/admission.rs`, `src/node/direct.rs`, `tests/negotiation_security.rs` | SC-G03-P0-10..14, E2E-01; permutations, unknown/required/conflict/limit boundaries, exact bytes and downgrade cases | R2 |
| T-G03-05 Bidirectional multiplexing | P0/H | 03-02,04 | Bounded correlation/concurrent requests both ways; manifest overload/session errors | `src/protocol/message.rs`, `src/node/session.rs`, `tests/bidirectional_session.rs` | SC-G03-P0-15..17; bidirectional suite | R2 |
| T-G03-06 Hostile/admission-input closure | P0/H | 03-01..05 | Freeze errors; enforce 4/64 pending, 16/256/min, bucket/deadline limits and hostile frame rejection | config/error/transport/session, `tests/g3_security.rs` | SC-G03-P0-18..22; admission limit/replay/binding/malformed/oversized suite | R1 |

## G4: Session and Trust Generalization

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G04-01 Discovery/transport registries | P0/H | G3 PASS | Export manifest extension traits/registration; WSS still requires authenticated result | `src/transport/{traits,registry}.rs`, `src/discovery/registry.rs`, transport contract test | SC-G04-P0-01..04; registry contract plus secure two-node regression | R1 |
| T-G04-02 Endpoint lifecycle/readdress | P0/H | 04-01 | Export manifest endpoint view; bound/merge/expire candidates by identity | `src/transport/endpoint.rs`, `src/discovery/candidates.rs`, endpoint test | SC-G04-P0-05..08; endpoint suite | R1 |
| T-G04-03 Crossed-dial/session replacement | P0/H | 04-01,02 | Deterministically own one authenticated session and drain replacement; no new API | `src/node/{session,session_set}.rs`, `tests/crossed_dial.rs` | SC-G04-P0-09..11; crossed-dial suite | R1 |
| T-G04-04 Queue/keepalive/shutdown bounds | P0/H | 04-03 | Export manifest limit config/errors; bounded queues/keepalive/idle/cancel | `src/node/{session,lifecycle}.rs`, `src/transport/keepalive.rs`, session lifecycle test | SC-G04-P0-12..15; session lifecycle suite | R1 |
| T-G04-05 Trust snapshot/dissemination/query | P0/H | 04-01,02,03-04 | Manifest trust view; persist new key everywhere; signed snapshot to joiner; offline catch-up | `src/identity/{trust_snapshot,trust_sync}.rs`, `src/node/api.rs`, `tests/{three_node_trust,offline_trust_catchup}.rs`, fixtures/manifest | SC-G04-P0-16..19; bidirectional trust views, offline restart and format contracts | R2 |
| T-G04-06 Reciprocal alternate-peer reconnect | P0/H | 04-02..05 | Disconnect issuer; both endpoints establish exact peer key before credential-free member session | `tests/{issuer_disconnect,outbound_only,readdress,crossed_dial}.rs` | SC-G04-P0-20..22, E2E-02/E2E-03; grant-carrying and four facade-only targets | R0 |

## G5: Membership, Topology, and Recovery

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G05-01 Signed descriptors/vectors | P0/H | G4 PASS | Export manifest immutable descriptor/update API; signed revisions/removal markers | `src/membership/{descriptor,store}.rs`, descriptor test, descriptor fixtures/manifest | SC-G05-P0-01..05; security plus current/previous vector contract | R2 |
| T-G05-02 Membership digest anti-entropy | P0/H | 05-01 | Bounded read-only members query and normal-tick digest sync through 1,024-member ceiling | `src/membership/{digest,sync}.rs`, convergence/scale tests | SC-G05-P0-06..09; membership security, bound and scale suite | R2 |
| T-G05-03 Sparse neighbor policy | P0/H | 05-01,02,04-04 | Export manifest policy/topology view; bounded sparse cycle distinct from reachability | `src/topology/{policy,maintenance,view}.rs`, topology test | SC-G05-P0-10..13; topology suite | R1 |
| T-G05-04 Exact recovery state machine | P0/H | 05-03 | Three fixed rounds then bounded all-known fan-out; no new API | `src/topology/{recovery,attempt_log}.rs` | SC-G05-P0-14..19; recovery unit/model tests | R1 |
| T-G05-05 Sixteen-node recovery simulation/E2E | P0/H | 05-02..04 | Simulated exact counts plus facade-only 16-node E2E using public counting transport | simulation recovery, `tests/{simulation_recovery,e2e_recovery}.rs` | SC-G05-P0-20..22, E2E-04; run both targets and assert `3P+K` | R0 |
| T-G05-06 Failure/readiness/SLO closure | P0/H | 05-01..05 | Public reciprocal trust/descriptor/topology readiness for induced 15-node and exact 32-edge final graph | simulation topology/membership/trust, `tests/g5_failure_matrix.rs` | SC-G05-P0-23..29; reusable OCI readiness contract plus failure matrix and metadata SLO trend | R0 |

## G6: Reliable Multi-Hop Delivery

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G06-01 Signed routed request/attempt | P0/H | G5 PASS | Manifest TraceId/delivery types; domain handler tags; source-signed request plus ordinals; 15-hop no-fanout | `src/routing/{envelope,policy}.rs`, route fixtures/manifest | SC-G06-P0-01..04; signature mutation, ordinal fabrication, hop and <=60 DATA-write properties | R1 |
| T-G06-02 Durable DATA/receipt journal | P0/H | 06-01,G2 PASS | Journal pinned DATA next/predecessor receipt hops, write ambiguity, retention and count/byte quotas | `src/routing/journal.rs`, routing journal/crash tests, trace fixtures/manifest | SC-G06-P0-05..08; ordinal, pinned-hop, no autonomous retry, quota and compatibility contracts | R2 |
| T-G06-03 Persist-before-forward both ways | P0/H | 06-02,G4 PASS | Commit before one DATA/reverse-receipt write; recover only same pending ordinal, no branch/fallback | `src/routing/forwarder.rs`, `tests/{routing_forward,routing_crash}.rs` | SC-G06-P0-09..11; fault every DATA/receipt write boundary and assert 15-hop receipt bound | R2 |
| T-G06-04 Durable acceptance/dispatch/receipt | P0/H | 06-02,G4 PASS | Gate routed handler/features; atomic Accepted/DispatchStarted; signed ACK/reject; duplicate re-ACK | `src/routing/destination.rs`, `src/protocol/dispatch.rs`, destination/crash tests | SC-G06-P0-12..15; unsupported handler, at-most-once initiation, full-quota duplicate/conflict precedence | R2 |
| T-G06-05 Four-ordinal retry/retention E2E | P0/H | 06-03,04 | Ordinals 0..=3, route/late ACK, 24h TTL and conservative lower-bound age across uncertainty | `src/routing/{source,retry}.rs`, `src/node/api.rs`, `tests/{routing_e2e,routing_retention}.rs` | SC-G06-P0-16..20, E2E-05; current/prior boot, unknown commit, rollback/jump/discontinuity and post-expiry cases | R2 |

## G7: Partition-Tolerant Replication

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G07-01 HLC/clock health/watermark | P0/H | G6 PASS,G2 PASS | Manifest HLC health/errors; authenticated samples, checked transitions, persisted watermark and 5s quarantine | `src/state/clock.rs`, `tests/{clock_sync,clock_restart}.rs` | SC-G07-P0-01..02, SC-G07-P1-03; every branch/overflow/crash/sample/quarantine boundary | R2 |
| T-G07-02 Signed record/strict order vectors | P0/H | 07-01 | Manifest signed opaque records and codec registry; HLC/writer/tombstone/digest total order | `src/state/{record,version,codec}.rs`, record/codec fixtures/manifest | SC-G07-P0-04..06; field mutation, signature, comparator algebra and equivocation contracts | R2 |
| T-G07-03 Atomic local/remote state API | P0/H | 07-02,G2 PASS | Manifest get/put/delete; atomically commit mutation/remote history with HLC watermark | `src/state/store.rs`, `src/node/api.rs`, `tests/{state_api,state_crash}.rs` | SC-G07-P0-07..09; local/remote/watermark old-or-new and CAS conflicts | R2 |
| T-G07-04 Delta/anti-entropy sync | P0/H | 07-03,G6 PASS | Bounded delta/digest handlers and normal-tick repair; no new API | `src/state/{sync,merge}.rs`, `tests/state_sync.rs` | SC-G07-P0-10..11, SC-G07-P1-12; complete state sync target | R2 |
| T-G07-05 Private tombstone cleanup machinery | P0/H | 07-04 | Internal exact CAS transaction/history/quarantine removal and resurrection risk; export no command | `src/state/cleanup.rs`, private cleanup tests | SC-G07-P0-13..15; race/crash/peer restore/offline stale/no-auto/no-public tests | R3 |
| T-G07-06 Partition/scale/SLO closure | P0/H | 07-04,05 | Public clock/state predicates, 8+8 merge, 1,024-member functional trend and quantified 16-node SLO | `tests/{state_e2e,state_scale,state_slo}.rs` | SC-G07-P0-16..18, E2E-06; exact winner/tombstone, ceiling bounds and no larger-scale latency claim | R0 |

## G8: redb and Mixed Storage

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G08-01 Complete conditional storage v2 | P0/H | G7 PASS,G6 PASS | Manifest backend/factory with CAS, receipts, capabilities, all-record durability and reconciliation | `src/storage/{backend,schema}.rs`, JSON, storage contract test | SC-G08-P0-01..02, SC-G08-P1-03; JSON all-record conditional/reconciliation contract | R1 |
| T-G08-02 Optional redb adapter | P0/H | 08-01 | Manifest redb factory behind `redb`; no redb type leaks | `Cargo.toml`, `Cargo.lock`, `src/storage/redb.rs` | SC-G08-P0-04..05, SC-G08-P1-06; default/no-default/redb contract commands | R1 |
| T-G08-03 redb crash/conflict/integrity | P0/H | 08-02,02-04 | Kill committed/aborted/unknown, conditional conflicts, provider create/delete intents and integrity reopen | `src/storage/redb.rs`, `tests/{storage_crash,storage_conflict}.rs` | SC-G08-P0-07..09; provider/receipt cleanup parity, reconciliation and no-partial-family writes | R1 |
| T-G08-04 Transactional migration graph | P0/H | 08-03 | Immutable explicit edges; reject duplicate/cycle/ambiguity/downgrade; old-or-new interruption | `src/storage/migration.rs`, storage fixtures/manifest, migration test | SC-G08-P0-10..12; every edge twice, unknown outcomes and older-reader refusal | R2 |
| T-G08-05 Mixed backend/feature closure | P0/H | 08-04,G7 PASS | Restart JSON/redb cluster, compare logical records, feature powerset CI; no API | `tests/{e2e_mixed_storage,storage_restart}.rs`, `.github/workflows/quality_check.yml` | SC-G08-P0-13..14, SC-G08-P1-15, E2E-07; both tests + cargo-hack + `act`/pushed run | R0 |

## G9: Resources, Explicit Operations, and Facade

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G09-01 Versioned labels/resources/vectors | P0/H | G8 PASS,G7 PASS | Export manifest labels/resources; enforce owner DNS domains, reserved categories and per-key versions | `src/resource/{label,record}.rs`, membership/storage, resource fixtures/manifest | SC-G09-P0-01..04; namespace ownership, resource and compatibility contracts | R2 |
| T-G09-02 Selectors/queries | P1/M | 09-01 | Export manifest selector/query signatures; bounded equality/set/existence grammar | `src/resource/selector.rs`, `src/node/api.rs`, `tests/selectors.rs` | SC-G09-P1-05..08; property/evaluator/convergence cases | R1 |
| T-G09-03 Atomic label mutations/events | P0/H | 09-01,02,G6 PASS | Export manifest label batch/event; one post-commit event, never maintenance deletion | `src/resource/operation.rs`, `src/node/events.rs`, resource operation test | SC-G09-P0-09..12; label/event cases on JSON/redb | R2 |
| T-G09-04 Explicit authorization revoke | P0/H | 09-03,G8 PASS | Typed RevokeNode; durable close/deny authority while signed replicated content stays eligible | identity/trust, typed bus, `tests/revoke.rs` | SC-G09-P0-13..14; crash/reconnect denial plus delayed-content convergence | R3 |
| T-G09-05 Sole public CleanupState | P0/H | 09-03,G7 PASS | Export only manifest CleanupState command over G7 private machinery with typed risk acknowledgement | state cleanup, typed bus, `tests/explicit_cleanup.rs` | SC-G09-P0-15..17; single-export, local atomicity, risk/no-auto tests | R3 |
| T-G09-06 Active leave/identity rotation | P0/H | 09-04,05,G2 PASS | Export manifest leave outcome; recoverable new ID/key and old local state removal | `src/node/lifecycle.rs`, key/trust/storage paths, `tests/active_leave.rs` | SC-G09-P0-18..21; JSON/redb crash/restart cases | R3 |
| T-G09-07 Platform/session-feature facade closure | P0/H | 09-01..06,G3 PASS | Informational supported/platform labels plus pair/session-scoped selected-feature resources | `src/resource/{platform,session_features}.rs`, `src/lib.rs`, `tests/{platform_labels,facade_only}.rs` | SC-G09-P0-22..26, E2E-08; prove resource labels never authorize negotiation | R2 |

## G10: Compatibility and `0.1.0` Evidence

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G10-01 Aggregate/freeze format manifest | P0/H | G9 PASS; manifest from 03-01,04-05,05-01,06-01/02,07-02,08-04,09-01 | Freeze existing vectors, previous readers and migration chain; version errors only | `src/protocol/compatibility.rs`, `src/storage/migration.rs`, `tests/fixtures/format-manifest.toml`, `tests/{golden_vectors,storage_migrations}.rs` | SC-G10-P0-01..05; golden + JSON/redb migration suites | R2 |
| T-G10-02 Mixed-binary feature intersection | P0/H | 10-01 | Prior/current subprocesses, no-fallback rejection, signed pair-scoped feature/platform parity | `tests/{mixed_version,support/subprocess}.rs` | SC-G10-P0-06..09, E2E-09; both initiator roles, required/optional labels and resource cleanup | R2 |
| T-G10-03 Decoder/selector fuzzing | P0/H | 10-01 | Own `wire_decode`, `persisted_decode`, `selector` targets and bounded reviewed corpus manifests | `fuzz/{Cargo.toml,fuzz_targets/{wire_decode,persisted_decode,selector}.rs,corpus/*}` | SC-G10-P0-10..11; impact activation, deterministic corpus replay and bounded live fuzz | R0 |
| T-G10-04 State-machine fuzzing | P0/H | 10-01 | Own `admission`, `feature_selection`, `routing` targets and reviewed corpora | `fuzz/fuzz_targets/{admission,feature_selection,routing}.rs`, corpora | SC-G10-P0-12..14; state invariants, corpus hygiene and bounded live fuzz | R0 |
| T-G10-05 Secret-safe observability | P0/H | 10-02,G9 PASS | Bounded production public readiness/quiescence/resource counters; no private observer API | `src/observability.rs`, owned subsystem hooks, `tests/observability.rs` | SC-G10-P0-15..16; zero-queue/stable-session/clock/quarantine/resource baselines and redaction | R1 |
| T-G10-06 Churn/resource soak | P0/H | 10-05,G7 PASS | Separate 8h weekly/24h release churn suites and baseline resource assertions; no API | `tests/soak.rs` | SC-G10-P0-17..19; explicit 8h and 24h ignored commands | R0 |
| T-G10-07 Native CI/evidence matrix | P0/H | 10-03,04,06,G8 PASS | Rust 1.97.1/stable, native OS/features, pinned fuzz and scheduled soak attestations | `.github/workflows/{quality_check,nightly,release}.yml` | SC-G10-P0-20..24; cargo-hack/deny plus `act` or local matrices and pushed run | R0 |
| T-G10-08 Typed-bus API/semver review | P0/H | 10-01,02,G9 PASS | Approve exact functional 0.1 typed command/query/event facade; no additional exports | API manifest/review, public-api tests, `src/lib.rs` | SC-G10-P0-25..26; cargo-public-api, semver-checks and external test | R2 |
| T-G10-09 Evidence validator preflight | P0/H | 10-03..08 | Implement threat/budget/attempt-ledger/profile validator and prove it rejects synthetic invalid ledgers | evidence/threat docs, `scripts/validate-release-evidence.sh` | SC-G10-P0-27..29; interrupted/under-budget/rerun/SHA/sample/exclusion negative fixtures | R0 |
| T-G10-10 OCI SLO harness qualification | P0/H | 10-02,05,07,08,09,G5 PASS,G7 PASS | Build publish-false node/controller images, isolated networks, redb volumes, prechecks and no-shortcut tests | `tests/slo-harness/*`, OCI/compose files, harness qualification evidence | SC-G10-P0-30..33; Docker/Podman profile dry run, topology/readiness/workload/cleanup and private-access negatives | R0 |
| T-G10-11 Candidate and complete SLO ledger | P0/H | 10-10 and all pre-candidate G10 tasks | Create publication-ready immutable candidate; run exact release matrices and five-run/125-sample SLO ledger | `Cargo.toml`, release workflow, external release/SLO evidence | SC-G10-P0-34..37, E2E-10; every sample <=10s, exact SHA/lock/image/attempt lineage and Q | R0 |
| T-G10-12 Token, tag, and publish | P0/H | 10-11 | Validate complete provider ledger, issue external candidate token, then guarded tag/publish | release environment/attestation config, validator, release evidence | SC-G10-P0-38..40; token SHA/lock/ledger match, negative guard tests and registry confirmation | R0 |

## Gate Closure And Parallel Lanes

| Gate | Parallel-ready tasks after entry | Closure |
| --- | --- | --- |
| G0 | ADR drafts overlap; acceptance follows dependencies | 00-06 |
| G1 | Core values/lifecycle design overlap after G0 | 01-05 |
| G2 | JSON/key-seam design overlap after 02-01 | 02-05 |
| G3 | TLS fixtures/handshake internals overlap after message freeze | 03-06 |
| G4 | Endpoints/trust-record design overlap after 04-01 | 04-06 |
| G5 | Digest/recovery model design overlap after descriptor rules | 05-06 |
| G6 | 06-03 and 06-04 | 06-05 |
| G7 | Comparator/codec and sync design overlap after 07-02 | 07-06 |
| G8 | Adapter/CI preparation overlap after 08-01 | 08-05 |
| G9 | Selector prototype may start after G1; API waits for 09-01 | 09-07 |
| G10 | 10-03/04, 10-05/06, API inventory and harness preparation | 10-12 |

## Handoff Rules

Before starting a task, copy its row into the issue or agent handoff and expand it into RED/GREEN
steps without changing scope. Include accepted predecessor paths, scenario and threat IDs, exact
API-manifest signatures, package decisions, every focused command, `Q`, and rollback code. One writer
owns the worktree; fresh reviewers check correctness/security and test evidence before gate closure.

Verify this plan with:

```bash
test -f docs/implementation-plan.md
test "$(wc -l < docs/implementation-plan.md)" -le 300
test "$(rg -c '^\| T-G[0-9]{2}-[0-9]{2} ' docs/implementation-plan.md)" -eq 69
test "$(rg -c '^## G[0-9]+:' docs/implementation-plan.md)" -eq 11
```

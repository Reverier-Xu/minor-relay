---
id: ADR-0006
title: Freeze planning ownership and a typed command bus facade
status: accepted
date: 2026-08-02
deciders: minor-relay maintainers
---

# Freeze Planning Ownership and a Typed Command Bus Facade

## Context

ADRs 0001 through 0005 fixed the security, wire, persistence, toolchain, evidence, and sixteen-node
SLO decisions. Their scenario IDs remained provisional, the roadmap threat list had no immutable IDs,
and later tasks could still invent public signatures or evidence commands while implementing.

G0 also exposed three unresolved decisions:

- the product member ceiling had been conflated with the sixteen-node SLO profile;
- admission concurrency and rate limits had no accepted numerical owner; and
- revocation did not define how previously signed replicated content behaves.

The public API must be general-purpose, Rust 1.97.1 compatible, free of Lycoris-specific types, and
small enough to evolve after functional `0.1.0`. Three designs were compared: one large typed
`NodeHandle`, capability sub-handles, and a typed command/query/event bus. The maintainer selected the
typed bus.

## Decision

### Cluster Scale and SLO Scope

The configurable cluster membership limit defaults to and may not exceed 1,024 members. Implementations
must enforce the limit before admitting or persisting a member that would exceed it. Applications may
configure a smaller positive limit.

Sixteen is not a product membership limit. It is the only latency-qualified population for functional
`0.1.0`. Under ADR-0005, clusters from one through sixteen members must satisfy the published
sixteen-node profile and every applicable measured sample must complete in at most ten seconds.

Clusters from 17 through 1,024 members must remain functionally bounded and eventually converge under
healthy connectivity. Scale tests record trends at 32, 64, 128, 256, 512, and 1,024 members, but
functional `0.1.0` makes no numerical convergence-latency promise for those sizes. A later accepted ADR
and measured evidence are required before publishing a larger-scale SLO formula.

### Admission Resource Limits

Credential entropy and single use do not bound unauthenticated CPU, memory, or task consumption.
Every API listener therefore enforces these defaults:

| Limit | Default | Configurable range |
| --- | ---: | ---: |
| Pending unauthenticated attempts per normalized source | 4 | 1-16 |
| Pending unauthenticated attempts globally | 64 | 16-256 |
| Attempts per source per fixed 60-second window | 16 | 1-60 |
| Attempts globally per fixed 60-second window | 256 | 64-4,096 |
| Retained source buckets | 1,024 | fixed maximum |
| Idle source-bucket lifetime | 10 minutes | fixed |
| Verified attempts entering commit per credential generation | 1 | fixed |
| Complete authentication deadline | 10 seconds | fixed |

The per-source pending/rate limits may not exceed their global equivalents. Limits cannot be disabled.
The source key is a normalized transport-observed address used only for abuse control, never identity,
trust, persistence, or authorization. Source keys and counters do not enter failure artifacts.

A full bucket table rejects an unseen source instead of evicting an active bucket. Empty buckets expire
after ten minutes on the injected monotonic clock. Rate windows are fixed, non-sliding, monotonic
60-second intervals; rollback or discontinuity cannot grant extra attempts. Limit rejection returns the
same secret-safe `Overloaded` class, performs no credential proof or durable mutation, and does not
consume the credential generation.

Credential verification remains constant-time with respect to secret bytes. At most one valid proof for
a generation may enter the durable admission transaction. Concurrent valid proofs either observe that
reservation or reconcile its outcome; they cannot commit another subject.

### Revocation Boundary

Revocation removes connection and authorization authority. Once the local durable revoke transaction is
known committed, the node:

- closes active sessions for the exact revoked NodeId/public-key binding;
- rejects new sessions and online operations from that identity;
- rejects a newly presented raw AdmissionGrant whose issuer is already locally revoked; and
- prevents the revoked identity from issuing a new accepted admission through that node.

Revocation does not erase or reinterpret signed replicated content. Valid state, resource, descriptor,
and historical trust records already accepted anywhere remain eligible for normal deterministic
anti-entropy, even when first observed by another node after it learns the revoke. Existing members
admitted through the revoked issuer remain independently trusted. A trust snapshot from a currently
trusted member may continue to carry those bindings.

This preserves convergence without consensus or a globally agreed revocation instant. It also means a
malicious member can pre-sign content or pass signed content through a colluding trusted member after
revocation. That is an accepted residual risk: a colluding trusted member can already submit its own
mutations. Removing content requires the explicit state/resource cleanup APIs; maintenance never turns
revoke into implicit data deletion.

### Typed Command Bus

`docs/api-manifest.md` is the normative functional `0.1.0` source API. `NodeHandle` exposes only:

```rust
pub async fn command<C: Command>(&self, command: C) -> Result<C::Output>;
pub async fn query<Q: Query>(&self, query: Q) -> Result<Q::Output>;
pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>>;
```

`Command`, `Query`, and `Event` are public but sealed. Downstream code cannot add arbitrary local bus
operations. New built-in operations add request/query/event types and sealed implementations. This is
normally semver-additive, but all functional `0.1.0` operations are frozen before publication.

Application protocols remain extensible through unsealed, domain-tagged `FeatureDefinition`,
`LimitDefinition`, `ProtocolDefinition`, codec, and handler contracts. Storage, keys, clocks, entropy,
discovery, transport, neighbor/routing policies, and state codecs use explicit public extension traits. Dynamic extension traits use the
manifest `BoxFuture` ABI and must be object-safe without `async-trait`.

The typed bus is not the wire protocol. Command/query types, Rust `TypeId`, internal type erasure, and
event subscriptions never appear on the network or in persisted data. Wire envelopes, CBOR, TLS,
transaction records, concrete JSON/redb types, Tokio channels/tasks, and reconciliation state remain
private.

### Provider Declarations and Event Queue Bounds

`NodeBuilder::new` requires the final object-safe `StorageFactory` and `KeyProvider` types before G2 can
start, while G2 depends on the G1 facade. T-G01-02 therefore owns declaration of the complete manifest
signatures for `StorageFactory`, `Storage`, `KeyProvider`, and their transitively named opaque values and
enums. It retains those injected providers but performs no storage or key operation. T-G02-01 and
T-G02-02 continue to own all constructors, validation, transaction, reconciliation, persistence,
redaction, provider behavior, implementations, and contract suites. Empty marker versions of these
open traits are forbidden because adding required methods later would break implementors.

Each transient event subscription has a default capacity of 256 items and accepts an explicit capacity
only in `1..=1,024`. Zero and larger values fail before channel allocation. This per-subscription bound
does not assign concrete event production or subscriber-count policy to G1; those remain with their
owning event tasks.

### Cleanup Ownership

G7 owns the private exact-tombstone cleanup transaction, crash semantics, and resurrection model. It
exports no cleanup operation. G9 owns the sole public `CleanupState` command, typed irreversible-risk
acknowledgement, events, and facade tests. No second public cleanup surface is permitted.

### Immutable Planning Manifests

These files are normative:

- `docs/scenario-catalog.toml`: 226 exact `SC-*` cases and ten `E2E-*` cases;
- `docs/threat-model.toml`: immutable `THR-001` through `THR-029` ownership and mitigations;
- `docs/threat-model.md`: boundaries, accepted residual risks, and interpretation;
- `docs/api-manifest.md` plus `docs/api-inventory.toml`: exact public signatures, reexports, and canonical digest;
- `docs/decision-register.toml`: shared constants with exactly one owning task;
- `docs/task-verification.toml`: structured command registration and task readiness; and
- `docs/evidence-impact.toml`: path-to-evidence activation and shard ownership.

Scenario IDs are computed from each catalog set's gate, priority, first ordinal, and ordered cases.
Changing a case title or predicate preserves its ID; inserting or removing a case inside an accepted set
is forbidden. New cases append a new non-overlapping set and never reuse an ID.

`T-G00-06` ratifies all previously provisional IDs. Later changes require an accepted plan amendment,
retain prior IDs, and pass `scripts/validate-planning-docs.sh` before RED.

### Validator Toolchain

Planning validators use existing project tools only:

- Bash 5.2 or newer for array-safe execution and orchestration;
- Taplo 0.10.0 or newer for TOML parsing/linting and JSON extraction; and
- jq 1.8.0 or newer for structured queries and invariant checks.

The scripts do not parse TOML with regular expressions and never use `eval`, `sh -c`, generated shell,
or unquoted command strings. Markdown task/scenario references are extracted only to compare them with
the structured manifests; TOML remains authoritative.

`verify-task.sh` executes only a registered literal argv array. Planned tasks with no command refuse to
run. Before RED, the owning task changes its verification state to `ready`, registers every focused
command, and passes planning validation. Every implemented task also runs `Q`.

## Threat Disposition

`docs/threat-model.toml` contains 29 immutable threats. The thirteen roadmap-mandatory categories appear
exactly once as `mandatory_key` values. Every threat has one primary task owner, one or more scenario
links, a mitigation, and either an empty residual or a named accepted residual risk. No P0/P1 threat may
remain with status `open` at release.

Extensions run in-process and are trusted code, not a sandbox boundary. Malicious peers, inputs,
protocol participants, evidence producers, CI identities, and storage/network providers remain modeled
at their documented boundaries. A hostile operating system, hypervisor, process memory reader, or
application retaining private-key-provider authority is outside the core protection boundary and is a
named residual risk.

## Verification

G0 closes only when:

- all six ADRs are accepted;
- planning TOML lints and expands to exactly 226 unique SC and ten unique E2E IDs;
- every plan reference resolves to the same one owner;
- `THR-001..029` are contiguous, unique, mitigated, and scenario-linked;
- every constant and API operation has one owner;
- every tracked/relevant path has one most-specific evidence-impact rule;
- task verification uses only bounded literal argv arrays;
- G7/G9 cleanup ownership is non-overlapping;
- cluster/SLO/admission/revocation decisions appear consistently in the roadmap, gates, plan, and ADRs;
- negative fixtures prove duplicate IDs, missing threats, ambiguous path rules, unregistered tasks, and
  shell-like replay arguments fail; and
- repository quality checks pass with zero warnings.

## Rejected Alternatives

### Sixteen-Member Product Ceiling

Rejected by maintainer decision. Sixteen is the measured SLO population. Functional membership supports
up to 1,024 members with no larger-scale latency claim in `0.1.0`.

### Unbounded Membership

Rejected because every protocol collection, fan-out, queue, scan, and test oracle needs a finite hard
ceiling. The public maximum may be raised only with an ADR and scale evidence.

### One Large NodeHandle

Rejected because its inherent method namespace expands with every operation and the typed bus gives a
smaller stable dispatch surface.

### Capability Sub-Handles

Rejected by maintainer preference. They provide useful least-authority delegation but add many public
handle types. `NodeHandle` authority remains application-controlled in the selected design.

### Open Command Trait

Rejected because downstream commands would require exposing internal dispatch registration and could
confuse local Rust operations with authenticated protocol extensions.

### Local First-Seen Revocation Cutoff

Rejected because partitioned nodes can first observe the same signed record on opposite sides of a
local revoke and diverge permanently.

### Automatic Invalidation of Revoked Authors' Content

Rejected because revoke would implicitly mutate or erase user state and violate explicit cleanup
ownership.

### Ad Hoc Shell TOML Parsing

Rejected because quoting, arrays, and nested records would make planning validation itself ambiguous.

## Consequences

- G1 may begin with all public operations, threats, scenarios, constants, and verification ownership
  frozen.
- `NodeHandle` remains a full-authority handle; applications that need least privilege must wrap it or
  retain it only in a trusted coordinator.
- The bus adds private type-erasure machinery, but the public operation types remain statically typed.
- Supporting 1,024 members requires bounded large-scale functional tests without claiming unmeasured
  latency.
- Revocation stops connectivity but is not content erasure.
- Admission floods are bounded at every listener even when credential entropy is uncompromised.

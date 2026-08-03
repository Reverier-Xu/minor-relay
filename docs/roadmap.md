# minor-relay Development Roadmap

## Reason for Existence

This document turns the product requirements for `minor-relay` into an ordered, verifiable
development program. It governs milestone scope and completion gates; ADRs govern design choices.

`minor-relay` is a general-purpose Rust library for secure cluster connectivity, failure recovery,
multi-hop traffic, and eventually consistent replicated state. It supports `lycoris` without
depending on Lycoris-specific workload, scheduler, schema, or deployment concepts.

## Product Contract

The library will provide:

- Stable node identity independent of addresses, connections, labels, and storage.
- An overlay in which directed dialability produces authenticated full-duplex
  sessions, and either endpoint can initiate requests after session establishment.
- Sparse cyclic connectivity, complete node metadata at every member, automatic
  multi-hop routing, and deterministic recovery after connection loss.
- Partition-tolerant last-writer-wins (LWW) replication for namespaced opaque data.
- Pluggable transports, protocol handlers, routing policies, codecs, clocks, and KV
  storage backends through traits and registries keyed by stable tags.
- Portable behavior across Windows, macOS, and Linux.

Cluster membership is configurable from one through a hard ceiling of 1,024 members. The ten-second SLO
is quantified only for one-to-sixteen-member healthy components under ADR-0005. Larger clusters must
converge functionally but have no `0.1.0` latency promise. The clock spans accepted mutation through all
online readers observing the winner; partitions pause it and reconnection starts a new interval.

Connectivity requires at least one node to open an outbound WebSocket to a reachable peer. The
established full-duplex channel then carries API traffic in both directions, including for a node
that cannot accept inbound Internet connections.

## Non-Goals

- Consensus, linearizable state, cross-key transactions, guaranteed application responses, or
  exactly-once execution of arbitrary application side effects.
- Workload scheduling, workload schemas, or Lycoris-specific resource types.
- Treating liveness observations as durable membership or as identity.
- NAT hole punching, STUN, public rendezvous, or relay infrastructure in the core library.
- Runtime selection, backend selection, or application payload types through closed
  public enums or central `match` statements.

## Architecture Rules

1. Model three separate graphs: directed endpoint reachability, undirected active sessions, and the logical routing graph. Never infer identity from any graph.
2. Bind each `NodeId` to a durable public key and authenticate possession of its private key on every session. IP addresses are replaceable endpoint candidates.
3. Keep wire envelopes, security state machines, and convergence ordering closed and auditable. Use registries only at genuine extension boundaries.
4. Tag network and persisted formats from their first release. Unknown schema/tag IDs, duplicate registrations, and oversized values fail clearly.
5. Bound all frames, queues, caches, fan-out, retries, and concurrent tasks. Apply backpressure instead of allowing unbounded memory growth.
6. Separate durable declarations from transient observations. Automatically maintain only connection and admission status; every other metadata mutation requires an explicit atomic user API.
7. Store opaque values with domain schema tags, persisted HLC, writer, and tombstone metadata. Core convergence never decodes payloads.
8. Public tags use `relay.woooo.tech/<category>/<name>`; extensions use a controlled DNS domain and registries, never central type switches. Closed internal enums remain appropriate for finite correctness-critical state machines.
9. Forbid `unsafe`, production `unwrap()`, and production `expect()`. Public errors must be contextual, stable where promised, and free of credentials or private material.

## Planned Module Boundaries

| Area | Responsibility | Primary extension boundary |
| --- | --- | --- |
| `identity` | Node/cluster IDs, keys, trust, admission, rotation, revocation | Key provider and secure key storage traits |
| `protocol` | Schema-tagged envelopes, feature-label negotiation, handler dispatch | Namespaced protocol-tag registry |
| `transport` | Peer discovery, API serving, WebSocket dial/listen, encrypted full-duplex sessions | Transport and discovery registries |
| `membership` | Durable node descriptors, admission state, metadata sync | Descriptor extension registry |
| `topology` | Reachability, active adjacency, neighbor selection, reconnect | Neighbor policy trait |
| `routing` | Next-hop selection, delivery ACKs, trace deduplication, forwarding | Routing policy and handler registries |
| `state` | Namespaces, synchronized timestamp versions, LWW, anti-entropy, tombstones | Codec and namespace registries |
| `storage` | Portable records, atomicity contract, migrations, adapters | Storage factory/backend traits |
| `resource` | Labels, selectors, and node resource queries | Resource operation handlers |
| `node` | Builder, lifecycle, public API, events, task ownership | Injectable services for tests and embedding |

`src/lib.rs` will remain a deliberate facade. Backend internals and wire-model details
will not become public merely because they are implemented in the same crate.

## Mandatory Decision Gate

ADRs must preserve these accepted constraints and decide only their remaining implementation details:

- Tokio owns asynchronous execution, cancellation, shutdown, and task supervision.
- Membership defaults to and cannot exceed 1,024; the quantified SLO covers only one through 16 nodes under ADR-0005, while larger scale has functional/trend evidence without a latency claim.
- Peer-to-peer scanning is discovery-only. Nodes expose API servers and use TLS WebSockets for authenticated full-duplex traffic; core scope excludes hole punching.
- Wire framing, schema-ID decoder dispatch, feature-label selection, trace retention, ACK boundaries, and downgrade prevention remain explicit protocol decisions.
- ADRs fix `prefix-nanoid` syntax, node-ID/public-key binding, key persistence, and collisions. A lost private key requires a new identity and fresh join.
- Each receiving node owns one rotating string credential. Acceptance by any member admits the node
  cluster-wide. The credential establishes temporary join trust only; it is never replicated,
  logged, or used by established-member authentication.
- Programmatic revoke is a connectivity/authorization boundary and does not invalidate signed content;
  state cleanup, tombstone cleanup, and active leave remain explicit atomic APIs. Active leave rotates
  the local node ID/key and removes old local cluster state. No unrelated metadata changes silently.
- Nodes synchronize clocks and order LWW mutations by timestamp plus stable writer ID and a final
  deterministic tie-breaker. ADRs must define skew bounds, restart behavior, and bad-clock handling.
- Every routed request uses a `prefix-nanoid`-style `TraceId`. Forwarders and the target persist
  deduplication records; the target returns a delivery ACK after acceptance. The source performs at
  most three backoff retries when the ACK is missing. Application success is outside this contract.
- The default JSON-file backend rewrites serialized state and is test-only; redb is the first production backend, under the same crash-safety and atomicity contract.

A threat model must cover credential guessing, replay, impersonation, identity clones,
Sybil admission, stale metadata, protocol downgrade, route amplification, oversized
payloads, slow peers, future timestamps, malicious members, and secret disclosure.

## Milestones

### M0: Contract-First Foundation

Deliver core IDs, endpoint candidates, tags, configuration validation, error taxonomy,
Tokio lifecycle primitives, synchronized test clocks, seeded randomness, and versioned serialization.
Build a deterministic simulation harness for delay, loss, duplication, reordering,
partitions, restarts, address changes, clock skew, and directed reachability.

Exit gate:

- Parsing, ordering, size-limit, invalid-input, and serialization property tests pass.
- The simulator reproduces seeded scenarios and advances entirely by virtual time.
- The crate builds without a persistent backend or platform-specific service.
- The placeholder API is removed only when its replacement facade is tested.

### M1: Durable Identity and Secure Admission

Generate validated `prefix-nanoid` IDs, persist key material, maintain signed trust
bindings, and prove key possession during every session. Implement admission through a receiving
node's rotating credential, using only its address and credential as external inputs. Bind admission
and every later secure session to node ID, public key, cluster ID, base schema ID, complete signed
feature-label offers and their selected intersection, nonces, and the authenticated transcript. Loss of the private key creates a new identity rather than key recovery.

Exit gate:

- A node joins through any one reachable member using that member's address and credential only.
- Every online member persists the propagated identity; offline members catch up through normal sync.
- The new node may disconnect its issuer and reconnect elsewhere without a credential; rotation does not disconnect admitted nodes or change their trust bindings.
- Captured transcripts, wrong keys, wrong clusters, and ID collisions fail without leaking secrets.

### M2: Transport-Neutral Full-Duplex Sessions

Define discovery and session traits plus registries. Use peer-to-peer scanning only to discover
candidates. Each node exposes an API server and establishes authenticated TLS WebSockets through
Tokio; once established, the channel carries concurrent requests in both directions. Track multiple
expiring endpoint candidates and implement bounded frames, backpressure, crossed-dial deduplication,
keepalive, graceful replacement, and cancellation.

Exit gate:

- A discovery result can establish a TLS WebSocket without importing Lycoris behavior.
- Either side concurrently initiates API requests over one session regardless of the dialer.
- An outbound session lets an inbound-unreachable node receive forwarded API traffic.
- Readdressing preserves identity; invalid proofs, versions, tags, and frames fail closed.

### M3: Membership, Sparse Topology, and Recovery

Replicate complete durable node descriptors while keeping liveness local and transient.
Implement signed monotonic descriptor updates, digest-based anti-entropy, and pluggable neighbor
selection that keeps at least one reachable peer and may connect up to every peer while preserving
sparse cyclic adjacency and bounded connection maintenance.

Implement disconnected recovery as a single-flight deterministic state machine:

1. Enter only when inbound plus outbound active-session count is zero.
2. Run exactly three fixed-interval rounds against preferred known peers.
3. If still disconnected, attempt every known node with a usable endpoint exactly once,
   using an ADR-bounded concurrent work set.
4. Cancel remaining work on success, deduplicate crossed dials, then resume normal
   maintenance without an unbounded retry storm.

Exit gate:

- A sparse cyclic test cluster converges all node metadata within the SLO profile.
- Tests observe exactly three fixed rounds and one all-known-node attempt phase.
- Single-edge failures reroute when the graph permits; bridge loss reports a partition.
- Restarted, readdressed nodes reconnect through any reachable trusted member.
- Stale descriptors cannot resurrect expired endpoints or removed metadata.

### M4: Transparent Multi-Hop Routing

Add routed envelopes with source/destination IDs, `TraceId`, protocol tag, hop limit, and bounded
payload. Persist trace records at each forwarding hop and at the destination. Compute next hops from
active sessions, invalidate stale routes, suppress duplicates, enforce quotas, and dispatch local
operations through registered handlers. A destination ACK confirms receipt, not handler success.

Exit gate:

- Public requests cross at least three hops without exposing intermediate nodes.
- A missing ACK triggers no more than three source retries using the defined backoff schedule.
- Replayed traces are not redispatched, and the destination re-ACKs an accepted duplicate.
- Cycles and stale routes terminate; alternate paths work or return a typed delivery failure.

### M5: Partition-Tolerant LWW Replication

Expose namespaced opaque KV records. Synchronize clocks, persist HLC watermarks, and order mutations
by HLC, stable writer ID, tombstone rank, and canonical digest. Represent deletion as a signed tombstone.
Use deltas for prompt dissemination and digest/range or Merkle-style anti-entropy for repair;
reconnection uses the normal synchronization tick, not a recovery-only merge. Tombstone removal
occurs only through an explicit user cleanup API.

Exit gate:

- Partitioned components update disjoint and identical keys, reconnect, and converge.
- Same-key conflicts resolve identically despite equal timestamps and message reordering.
- Deletes never resurrect unless a user explicitly accepts that risk through cleanup.
- Structured and unstructured bytes round-trip without core schema knowledge.
- Clock skew, resynchronization, bad clocks, partitions, and restarts have deterministic tests.
- State converges functionally with bounded resources through 1,024 members; every applicable
  one-to-sixteen-member sample satisfies the documented SLO profile.

### M6: Feature-Gated KV Storage

Define backend traits from required semantics: conditional atomic batches, immutable snapshots,
ordered prefix scans, durable commit/flush, reconciliation, schema graphs, capability reporting, and
crash recovery. Enable a JSON-file backend by default; it rewrites serialized
state and is strictly for tests. Provide redb as the first feature-gated production backend. Do not
ship an in-memory backend.

Exit gate:

- JSON and redb nodes coexist and converge to identical logical records.
- Restart preserves identity, trust, clocks, membership, labels, traces, tombstones, and user data.
- Crash tests cover atomic file replacement for JSON and transactional persistence for redb.
- CI covers default JSON, redb alone, and every supported feature combination.

### M7: Node Resources, Labels, and Public Facade

Model node resources with identity, versioned metadata, labels, capabilities, and observed
connectivity. Borrow Kubernetes selector semantics for equality, inequality, set membership,
non-membership, existence, and non-existence, but use relaxed documented length limits. Reserve
internal labels for protocol features, platform identity, and platform-specific capabilities.
Expose atomic APIs for label mutation, programmatic revoke, cleanup, active leave, selector query,
and events; keep application resource operations in registered handlers.

Exit gate:

- Converged peers return identical selector results after concurrent label changes.
- Explicit revoke closes authorization/sessions but preserves signed content; cleanup and leave are atomic, and connectivity maintenance never erases metadata.
- Active leave rotates local identity and removes old local cluster state.
- Windows, macOS, and Linux nodes advertise feature and compatibility labels.
- Public integration tests use only the facade and contain no Lycoris-specific types.

### M8: Interoperability and Release Hardening

Add protocol golden vectors, mixed-binary tests, parser and state-machine fuzzing, property/model
tests, churn and partition soak tests, and OS-specific CI. Breaking API and wire changes are allowed
until the functional `0.1.0` release. Publication remains disabled until exact-commit G10 attestation.
Afterward, evolve the public API compatibly, retain exact base schema readers, and intersect authenticated feature-label offers so old and new binaries can coexist.
Mirror supported features and platform facts into informational reserved labels; expose pairwise
selected features only as session-scoped resources. Resource labels never replace handshake selection.

Exit gate:

- Linux, macOS, and Windows pass the supported feature matrix with zero warnings.
- Mixed binary releases select one sufficient common feature-label set and operate in one cluster.
- Malformed, replayed, stale, slow, and saturated scenarios fail within resource limits.
- Published benchmarks state the exact conditions under which the 16-node SLO holds.
- The functional `0.1.0` facade, release token, exact commit, and publication transition pass explicit review.

## Requirement Traceability

| Requirement | Owning milestones |
| --- | --- |
| 1. Sparse cyclic graph, directed dialability, full-duplex channels, 10 s sync | M0, M2, M3, M5, M8 |
| 2. Partial direct connectivity and transparent routing | M3, M4 |
| 3. Offline nodes, address churn, outbound WebSocket reachability | M0, M2, M3, M8 |
| 4. Partition workloads and latest-key merge on normal sync | M0, M5, M6 |
| 5. Full metadata, three fixed retries, then one fan-out | M3 |
| 6. Generated ID and asymmetric authenticated encryption | M1, M2 |
| 7. Per-receiver bootstrap credential, then credential-free operation | M1 |
| 8. Pluggable JSON and redb feature-gated KV backends | M6 |
| 9. Windows, macOS, and Linux | M0, M2, M8 |
| 10. Kubernetes-style node labels and selection | M3, M7 |
| 11. General Lycoris foundation with registry/tag/trait extensibility | All |

## Delivery Order

Milestones define product scope, not strict implementation sequence. Execution follows the
[Rapid Iteration Development Gates](development-gates.md), which resolve cross-milestone dependencies.

The completion dependency remains `M0 -> (M1 + M2) -> M3 -> M4 -> M5 -> M6 -> M7 -> M8`;
the storage contract precedes M1 and M4, M3 rerouting closes with M4, M4 durability closes with M6,
and M6 label-restart coverage closes with M7.

## Definition of Done

Every milestone must pass the repository quality gates:

```bash
taplo fmt --check
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Each implementation change must also pass its milestone-specific simulation, security,
compatibility, feature-matrix, and platform checks. Review the final diff for accidental
API, dependency, generated-file, and metadata changes before merging.

Verify this roadmap with:

```bash
test -f docs/roadmap.md
test "$(wc -l < docs/roadmap.md)" -le 300
grep -q '^## Requirement Traceability$' docs/roadmap.md
grep -q '^### M8: Interoperability and Release Hardening$' docs/roadmap.md
```

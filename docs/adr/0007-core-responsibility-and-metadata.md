---
id: ADR-0007
title: Bound radiata to cluster connectivity and metadata
status: accepted
date: 2026-08-04
deciders: radiata maintainers
---

# Bound radiata to Cluster Connectivity and Metadata

## Context

The original roadmap accumulated application-state replication, clock coordination, business request
semantics, storage capacity policy, and deployment assumptions around a cluster connectivity library.
Those responsibilities made the public contract broader than the intended product: a reusable framework
that maintains authenticated cluster connectivity, transports opaque data, and converges metadata.

This ADR reopens the G0 responsibility boundary before G2. It supersedes conflicting scope decisions in
ADR-0001 through ADR-0006 without erasing their historical rationale. Identity, admission, authenticated
transport, canonical wire encoding, conditional metadata storage, deterministic evidence, and the typed
runtime facade remain in scope unless this ADR says otherwise.

## Decision Drivers

- Keep the crate independent of any application, deployment platform, or business data model.
- Give callers a stable authenticated path to any selected node without exposing transport framing.
- Keep payload processing constant-memory and independent of total stream length.
- Converge node and resource metadata without turning the crate into an application database.
- Let operators and providers own deployment capacity while core preserves protocol and state-machine
  correctness.
- Preserve explicit crash, replay, conflict, and overload outcomes without claiming guarantees the new
  boundary cannot provide.

## Decision

### Product Boundary

`radiata` maintains authenticated cluster connectivity and core metadata. A caller may also use it
only as an opaque data portal. The crate does not model an application, deploy an application, store
business objects, provide persistent volumes, coordinate business clocks, or implement a general
replicated application-state database.

The crate has no hard node-count ceiling. Every concrete deployment and observed operation is finite.
Membership, trust, topology, resource, and policy views must therefore be exposed as streams, pages, or
incremental observations rather than APIs that require one whole-population allocation. Concurrent work,
queues, parser allocation, and tasks remain explicitly finite, but their capacities are caller-selected
policy rather than product population limits. The 1,024-node case remains mandatory functional and trend
evidence; it is not an admission boundary or a larger-scale latency claim.

### Identity and Admission

Core owns canonical cluster, node, trace, transaction, and operation identities and the immutable
`NodeId` to Ed25519 public-key binding. Endpoints and TLS certificates are mutable attributes, never
identity.

Core retains the complete admission policy accepted in ADR-0001 and ADR-0006: 32-byte single-use
credentials, ten-minute credential lifetime, one committed subject per generation, fixed pending and
rate ranges, bounded source buckets, and the authentication deadline. Every admitted non-revoked member
has the same authority to issue and accept credentials; no pluggable role or approval framework is part
of `radiata`.

A valid credential does not guarantee completion under overload, provider refusal, cancellation, or an
indeterminate commit. Without a member ceiling, a malicious full member can create unbounded Sybil
growth over time subject only to admission rate and resource controls. Deployments that require roles,
population approval, or organizational policy enforce them above this crate.

### Key Custody

Core owns the crash-safe key-operation protocol, opaque handles, idempotent create/delete reconciliation,
algorithm requirements, and verification that provider public keys match persisted identity bindings.
A `KeyProvider` owns private-key custody, capacity, physical durability, HSM or service configuration,
and capability reporting. Private key bytes never enter ordinary metadata storage.

### Endpoints, Sessions, and Recovery

Core discovers local network-interface candidates and propagates authenticated node-owned candidate
metadata. The caller supplies at least one bootstrap node address and may filter, add, prioritize, or
disable candidates through policy. Core verifies the authenticated `NodeId` after connecting and owns
candidate generations, crossed-dial resolution, session replacement, readdressing, stale-session
rejection, and trust propagation.

Core maintains a reachability graph and continuously retries recovery while known members remain in
mutually unreachable components. Recovery uses caller-configured neighbor, fan-out, and wall-clock
backoff policy. A typed command can request an immediate recovery attempt. Recovery stops when all known
online members are connected by some authenticated path; it does not require a full mesh. A later
connectivity or membership change can reactivate recovery.

Core provides a TLS 1.3 WebSocket implementation and an open authenticated full-duplex transport SPI.
TLS exporter channel binding and transcript authentication remain core security requirements. STUN, NAT
hole punching, rendezvous infrastructure, external relays, and address provisioning remain outside the
crate.

### Wire and Negotiation

Core owns the fixed prelude, deterministic CBOR rules, canonical schema and kind identities,
domain-qualified tags, authenticated feature intersection, required-feature refusal, and malformed-input
rejection. Parser depth, collection, frame, and concurrent-work budgets are finite and configured by the
caller. Core validates nonzero and relational invariants and uses checked arithmetic; it does not impose
business-size ceilings beyond fixed wire-field representations.

Callers register protocols and feature definitions. Core authenticates and selects the exact definition
intersection. It does not sort versions, invent a downgrade, or interpret protocol payloads.

### Packet Streams and Trace Identity

The data-plane unit is an opaque, directed packet stream, not an application request or response.
Creating an outbound packet allocates a core-generated `TraceId` immediately and returns a handle from
which the caller can read that ID before delivery begins. The caller supplies a stream as the packet
body. Core frames, buffers, and forwards the body with constant memory and backpressure; total stream
length is not a public limit.

A target is either an exact `NodeId` or a selector evaluated against node-owned labels. Selector delivery resolves one destination
through a caller-selected load-balancing policy and records the selected node in route status. Core
supports synchronous delivery, which waits for the packet's route or delivery terminal state, and
asynchronous delivery, which returns immediately and exposes route-status queries.

Core does not distinguish a request from a response. An incoming packet exposes its authenticated source,
destination, `TraceId`, metadata, and body stream. A caller can derive another packet by exchanging source
and destination and reusing the same `TraceId`; the caller owns correlation and all application meaning.

Within one established route, core preserves byte order and framing. A route or session interruption
terminates the stream with a typed error. Core does not persist packet payloads and does not transparently
replay or resume a stream after disconnect or restart.

A delivery acknowledgement proves only that the destination authenticated and admitted the packet to its
current-process bounded incoming stream. It does not prove durable payload retention, caller observation,
processing, response, or success. A crash after acknowledgement can lose the payload. A stronger durable
handoff belongs above this API.

Trace storage contains only bounded metadata such as identity, selected destination, route attempts,
stream progress, and terminal state. It never contains payload bytes. The caller configures trace-metadata
retention and capacity. Expiration can remove query and duplicate evidence; active streams are not removed
by a terminal-record retention policy.

### Runtime and Backpressure

Core owns the Tokio runtime lifecycle, single supervisor, sealed typed command/query/event bus, task
cancellation, terminal status publication, and shutdown ordering. Tokio channel and task types do not enter
the public facade.

Every queue, subscription, parser, and task group is finite. Core provides defaults, but callers may select
any nonzero representable capacity that satisfies relational and allocation checks. Queue saturation
returns typed backpressure or delays progress according to the owning operation; it never switches to an
unbounded queue.

### Core Metadata

Core converges only metadata needed to identify, connect, authorize, route, observe, and select cluster
resources. Built-in node records, including identity, endpoint candidates, trust, membership, and
capability labels, are signed by their owning node or explicit cluster authority and use persistent,
strictly increasing owner revisions. A same-revision content conflict is rejected; core does not select a
winner by wall time for owner-only records.

Core also provides a generic resource-metadata catalog. A resource is a stable name plus labels. Reserved
labels identify resource type and resource URI; callers provide their values and may add namespaced custom
labels. The URI points to an upper-layer object or service and does not cause core to store that object.
Selectors query this metadata and can drive packet target selection.

Generic resource keys can have multiple writers. They are timestamp-maximum registers, not causal or
real-time last-write registers. The deterministic winner is the lexicographic maximum of signed system
wall-clock timestamp, canonical writer `NodeId`, removal rank, and canonical record digest. Acceptance of
a write does not guarantee that it becomes or remains the winner. Clock rollback can make a later local
write lose; equal timestamps use deterministic tie-breakers; a future-dated writer can dominate until
wall time catches up or a greater signed tuple appears.

Core does not provide general application records, HLC, peer clock health, future quarantine, business
LWW, CRDTs, or business anti-entropy.

### Time

All protocol-visible timestamps, expiration decisions, resource ordering, retry deadlines, and retention
decisions use the host system wall clock. The caller and operator are responsible for its accuracy.

An executor timer may wake a task to re-read a wall-clock deadline, but the timer is not an ordering or
elapsed-time authority. Wall-clock rollback, freeze, or forward jumps can delay work indefinitely or make
it immediately due. No no-early-expiry, bounded elapsed-time, or clock-health guarantee survives a system
clock discontinuity. Tests may inject or virtualize wall-clock observations internally; there is no public
clock-consensus or HLC API.

### Metadata Storage

The storage SPI is private infrastructure for core metadata, comparable in responsibility to a cluster
metadata store. It is not a public business key-value API. Core fixes immutable snapshot semantics, exact
lookup, unsigned-byte ordered streaming scans, conditional cross-family transactions, base-revision and
per-key conflict checks, atomic receipts, committed/aborted/conflict/unknown outcomes, reconciliation,
capability refusal, corruption handling, and schema migration semantics.

A backend owns snapshot implementations, file or database layout, capacity, quotas, flush policy, and
operational configuration. Core defines no generic key, value, transaction, snapshot, total-entry, or
total-byte maximum. A provider can still return typed resource exhaustion; this is not corruption and no
operation may silently truncate. Snapshot scans stream ordered entries instead of requiring core to
materialize the complete store. Storage is not exposed as a way for callers to persist payloads or
application objects.

The crate retains a JSON test backend, a feature-gated redb production backend, and an open
`StorageFactory` SPI. Both built-in backends and external providers pass the same metadata contract.
Transaction IDs have a canonical validated round trip so external providers can persist receipts and
reconcile after reopen.

### Cleanup, Leave, and Rotation

Core cleanup, revocation, active leave, and identity rotation affect only core-owned metadata and key
intents. They never delete a caller's business data or follow a resource URI. Cleanup uses exact expected
versions or revisions and preserves signed removal evidence where stale metadata could otherwise
reappear. The caller explicitly initiates irreversible operations and receives typed outcomes.

### Observability

Core exposes secret-safe typed errors, structured events and metrics, lifecycle status, route and trace
status, reachability and topology observations, and node/resource metadata queries. Queries over
population-sized data stream or page results. The caller owns log and metric export, persistence, user
interfaces, and alert policy. Payloads, credentials, private keys, provider handles, and unredacted paths
or addresses do not enter generic diagnostics or failure artifacts.

### Verification and Release

The repository owns deterministic simulation, contract tests, native crash and lock tests, security
properties, fuzzing, replayable failure artifacts, Linux native and container CI, and mixed-version/schema
evidence for core wire and metadata formats. Performance and scale measurements are versioned test
profiles, not universal runtime guarantees. The 1,024-node profile is mandatory functional and trend
evidence. Exact 16-node latency samples can remain only after their workload is rewritten around
admission, packet delivery, owner-revision node metadata, and generic resource metadata.

Core owns wire and core-metadata compatibility, feature intersection, storage migration semantics, and
crate release evidence. Providers implement backend-specific migration. Deployment orchestration,
application rollout, business schema compatibility, and business-data migration remain outside scope.

## Superseded Decisions

This ADR supersedes only the following portions of earlier ADRs:

- ADR-0001 and ADR-0006: the 1,024-member admission ceiling and any implication that full admission is a
  configurable role policy. The fixed admission security policy otherwise remains.
- ADR-0002: application request/reply semantics, durable payload acceptance, payload journals,
  transparent retry or resume guarantees, fixed business payload ceilings, and core-owned trace capacity.
  Framing, negotiation, routing safety, and authenticated transport remain.
- ADR-0003: generic application state, HLC, clock sampling and health, future quarantine, business
  tombstone cleanup, relay-owned storage capacity, and wall-clock-independent retention. Conditional
  metadata storage, key-provider reconciliation, JSON testing, redb production, and migration remain.
- ADR-0004: fuzz and evidence targets that exist solely for superseded request, HLC, or business-state
  APIs. The evidence discipline remains.
- ADR-0005: state/HLC/tombstone sample strata and any interpretation of the profile as a universal
  product limit. The controlled-profile method remains and requires a new workload.
- ADR-0006: member ceiling, business-state operation ownership, public clock injection, and the sole
  business `CleanupState` boundary. Typed-bus ownership and manifest governance remain.

When historical prose conflicts with this ADR, this ADR is authoritative. Active roadmap, API manifest,
scenario, threat, gate, and task documents must be migrated before G1 or G2 production work resumes.

## Consequences

### Positive

- The crate has one coherent role: authenticated connectivity plus metadata management.
- Packet size and duration no longer leak transport framing limits into the caller's data model.
- Storage providers can implement native snapshots and operational policy without inheriting relay-wide
  quotas.
- Resource metadata supports service discovery and load-balanced target selection without storing the
  referenced object.
- Evidence at 1,024 nodes remains useful without becoming an artificial product rejection boundary.

### Negative

- Delivery acknowledgement is weaker than durable application handoff.
- Disconnect and restart can lose in-flight payloads, and core cannot resume them.
- Wall-clock anomalies directly affect resource winners, deadlines, retention, and retry behavior.
- A malicious full member can grow membership without a core population ceiling.
- No node ceiling or storage quota means providers and callers must size deployments and may observe
  typed resource exhaustion.
- Existing G1 code and all active planning artifacts require a correction cycle before G2.

## Rejected Alternatives

### Retain application state, HLC, and durable payload delivery

Rejected because it makes `radiata` an application database and message broker rather than a
connectivity and metadata framework.

### Make all behavior provider-defined

Rejected because identity, admission, framing, trust, transaction semantics, and route safety must remain
consistent for independently implemented nodes and backends to interoperate.

### Preserve the 1,024-node product ceiling

Rejected because deployment size is an operator capacity decision. The number remains an evidence point,
not a validation rule.

### Expose storage as an application key-value service

Rejected because resource URIs and packet streams are the extension boundary for application data.

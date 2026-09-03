---
id: ADR-0002
title: Negotiate feature labels and provide bounded durable delivery
status: accepted
date: 2026-08-02
deciders: radiata maintainers
---

# Negotiate Feature Labels and Provide Bounded Durable Delivery

> **Amended by ADR-0007.** Framing, canonical encoding, negotiation, routing safety, and authenticated
> transport remain active. Application request/reply semantics, payload persistence, durable payload
> acceptance, transparent replay/resume, fixed business payload ceilings, and core-owned trace capacity
> are superseded by ephemeral traced packet streams.

## Context

`radiata` needs one bounded wire envelope for authentication, direct requests, trust sync,
routing, and state replication. Mixed binary releases must interoperate by selecting the smallest
common behavior set that both peers actually implement. Product or wire version numbers must not be
used as an ordering, preference, or compatibility oracle.

The routing contract also requires durable multi-hop acceptance. A request keeps one `TraceId` across
one initial send and at most three source retries. Forwarders persist before forwarding; the
destination persists acceptance before ACK. The ACK proves durable receipt, not handler execution or
application success.

Scenarios `SC-G00-P0-03` through `SC-G00-P0-05` are ratified by
`docs/scenario-catalog.toml`.

## Decision Drivers

- Decode hostile input with hard allocation, nesting, collection, queue, and task bounds.
- Keep wire compatibility independent of Rust declaration order and Serde implementation details.
- Negotiate behavior from authenticated feature labels, not release or protocol version arithmetic.
- Detect offer stripping, feature downgrade, divergent dependency rules, and selection mismatch.
- Preserve mixed-binary operation when both endpoints share a sufficient feature set.
- Authenticate routed requests and destination ACKs end to end across untrusted forwarders.
- Bound retries, hops, amplification, durable records, and retention without evicting active work.
- Make crash ambiguity explicit instead of claiming exactly-once socket writes or handler side effects.
- Preserve deterministic simulation and replay through injected clocks and entropy.

## Decision

### Fixed Wire Prelude

Every WebSocket application message is binary and contains exactly one 16-byte prelude followed by
one deterministic-CBOR body:

```text
0..4    magic       ASCII "MRLY"
4..6    schema_id   unsigned 16-bit, network byte order
6..8    kind_id     unsigned 16-bit, network byte order
8..10   flags       unsigned 16-bit, network byte order
10..12  reserved    unsigned 16-bit zero
12..16  body_len    unsigned 32-bit, network byte order
```

`body_len` must equal the remaining WebSocket message length. The implementation checks the prelude,
message class limit, and configured receive limit before allocating the body. Text messages, trailing
bytes, unknown flag bits, nonzero reserved bits, and length mismatches fail closed. WebSocket
fragmentation may be reassembled only under the same aggregate limit. Per-message compression is
disabled before `0.1.0`.

A `schema_id` is an opaque equality discriminator that selects one exact decoder. It has no
major/minor structure, ordering, range, recency, or automatic fallback semantics. Initial schema ID
`0x0001` is the deterministic-CBOR base schema. Once published, a schema ID and its decoding rules are
immutable and never reused.

Compatible behavior evolution occurs through feature labels and optional fields allowed by schema
`0x0001`. An unavoidable incompatible base schema receives an unrelated ID and explicit protocol
epoch. A connection does not retry another schema after an authentication, decoding, required-feature,
or selection failure. Mixed rollout requires a binary to retain the old exact decoder and choose the
schema through explicit local configuration or endpoint policy; it never guesses a lower version.

A `kind_id` identifies one exact message schema in the selected decoder. IDs are immutable and never
reused. The closed correctness-critical registry rejects duplicate IDs and unknown kinds before body
dispatch. Golden vectors record every published schema/kind pair.

### Deterministic CBOR

Bodies use `minicbor` with explicit numeric field and variant IDs. Rust field order, type names, and
enum declaration order are not wire contracts. Encoders produce the RFC 8949 deterministic form:

- definite lengths only;
- shortest integer and length encodings;
- bytewise canonical map-key ordering;
- one occurrence of each field or map key;
- no floats, indefinite items, or semantic tags unless a future feature label explicitly defines them;
- explicit numeric IDs for every field and variant; and
- canonical omission rules for optional fields.

Decoders reject duplicate fields, non-canonical integers, invalid ordering, excessive nesting,
excessive collection sizes, trailing values, and required fields with unknown or invalid values.
Unknown optional fields may be skipped only within the bounded body and never affect authentication,
authorization, feature selection, request digests, or persisted canonical records.

The same canonical encoder produces ADR-0001 authentication transcripts, source-signed requests,
destination-signed ACKs, golden vectors, and request digests. No generic decoded-and-reserialized map
is accepted as equivalent signed data.

### Domain-Qualified Tag Namespaces

Every public registry tag uses this canonical form:

```text
<dns-domain>/<category>/<name>
```

The total tag is 5 through 128 lowercase ASCII bytes. `dns-domain` is a canonical lowercase DNS name
with labels of 1 through 63 characters, no trailing dot, and no empty label. `category` and `name` each
start with `[a-z]` and continue with `[a-z0-9-]`; each is at most 63 characters. Unicode, case folding,
whitespace, empty path elements, repeated slashes, leading/trailing hyphens, and normalization are
rejected.

The built-in public namespace is `radiata.woooo.tech`. Reserved built-in categories include:

- `radiata.woooo.tech/features/<name>` for negotiated behavior labels;
- `radiata.woooo.tech/protocols/<name>` for handler/protocol tags;
- `radiata.woooo.tech/limits/<name>` for negotiated numeric limits;
- `radiata.woooo.tech/resources/<name>` for resource fields and derived views;
- `radiata.woooo.tech/events/<name>` for event kinds; and
- `radiata.woooo.tech/schemas/<name>` for named persisted or payload schemas.

For example, the initial authentication feature is
`radiata.woooo.tech/features/auth-ed25519-session`. The direct request handler tag is
`radiata.woooo.tech/protocols/direct-request`, and the data body limit is
`radiata.woooo.tech/limits/data-body-bytes`.

Extensions must use a DNS domain controlled by their owner and must not register under
`radiata.woooo.tech`. The library validates syntax and duplicate ownership but does not prove DNS
control at runtime; domain ownership is a governance and review requirement. A tag's full bytes are
the identity. Moving behavior to another domain creates a different tag.

Cryptographic domain-separation strings use the related private namespace
`radiata.woooo.tech/crypto/<purpose>`. They are immutable protocol constants, not registry tags.

### Feature Label Registry

A feature label is a domain-qualified tag whose category is exactly `features`. Labels are opaque
equality keys. Numeric suffixes, lexical order, release names, or apparent families have no
compatibility meaning. An incompatible semantic change requires a new descriptively named label;
published labels are never redefined or reused.

The registry entry for each locally implemented feature label fixes:

- its exact behavior contract and immutable 32-byte contract fingerprint;
- an acyclic set of required feature labels;
- a symmetric, irreflexive set of conflicting labels;
- complete definitions for the numeric limit IDs it owns; and
- its domain-qualified protocol handlers and test-contract owner.

A canonical `FeatureDefinition` contains all of those fields. Its `definition_digest` is SHA-256 over
the deterministic-CBOR definition. Changing behavior, fingerprint, dependencies, conflicts, limits,
handler ownership, or authorization consequences creates a new label. Registry construction rejects
duplicate labels, missing local dependencies, dependency cycles, asymmetric conflicts, self-conflicts,
and duplicate limit ownership.

Initial built-in definitions are:

| Feature label | Dependencies | Owned negotiated limits |
| --- | --- | --- |
| `radiata.woooo.tech/features/auth-ed25519-session` | None | None |
| `radiata.woooo.tech/features/session-core` | `auth-ed25519-session` | None |
| `radiata.woooo.tech/features/data-messages` | `session-core` | `data-body-bytes` |
| `radiata.woooo.tech/features/direct-request` | `data-messages` | `in-flight-requests` |
| `radiata.woooo.tech/features/routed-delivery` | `data-messages` | None |

The abbreviated dependency and limit names in this table resolve within `radiata.woooo.tech/features/`
and `radiata.woooo.tech/limits/`. Initial definitions have no conflicts. Their full canonical records
and fingerprints are frozen by the first registry golden fixture.

### Authenticated Feature Selection

Each authentication offer contains canonical, sorted, unique collections:

- `supported`: `(feature label, definition_digest)` pairs implemented and enabled by this endpoint;
- `required`: labels local policy requires for this session, with `required` a subset of `supported`;
- `limits`: the mandatory numeric limits owned by offered labels; and
- the exact base schema ID and message-kind set used to decode the offer.

Offers contain at most 128 supported labels, 128 required labels, and 128 numeric limits. The full
offers from both peers are included in ADR-0001's exporter-bound authenticated transcript. Resource
metadata, cached peer observations, release versions, and a previous session's selection are never
negotiation input.

Both peers independently compute the exact effective feature set:

1. For each common label, reject unless both `definition_digest` values match exactly.
2. Let `C0` be the equality intersection of labels in both `supported` sets.
3. Repeatedly remove a label whose immutable dependencies are absent until a fixed point `C*`.
4. Reject if a conflict pair remains in `C*`; lexical order never chooses a winner.
5. Reject unless `required_local union required_remote` is a subset of `C*`.
6. Reject an unknown required label. Unknown optional labels remain signed but are not selected.
7. Canonically sort `C*`, compute effective numeric limits, exchange the selection bytes, and require
   an exact byte match before either peer signs the final transcript.

There is no highest version, lowest version, minor window, preference score, or silent downgrade. An
authentication, schema, conflict, missing-required-label, limit, or selection failure closes the
connection. Automatic retry must not remove labels, weaken requirements, change schema, or source an
offer from resource labels. An operator may change policy only through a new explicit connection
attempt and an auditable configuration change.

An authenticated peer may intentionally under-offer an optional feature. Callers that require the
behavior must put its label in `required` or configure a persistent administrative requirement.

### Numeric Limit Negotiation

A numeric limit ID is a domain-qualified tag whose category is exactly `limits`. Its immutable
definition fixes an unsigned integer width, unit, legal floor, absolute ceiling, owning feature, and
whether it is mandatory.
Each offered value must be within the local registry range. Missing, duplicate, unknown-required, or
out-of-range mandatory limits make the offer malformed.

For every selected feature limit, both peers compute:

```text
effective_limit = min(local_offer, remote_offer)
```

The complete offered limit maps and canonical effective map are transcript-bound. Local hard ceilings
always apply even if a peer advertises more. Limits do not add or remove features except that an
invalid or missing mandatory limit rejects the connection.

Pre-negotiation decoder and local operational guards are not limit labels and are never weakened by a
peer offer:

| Local guard | Default | Absolute ceiling |
| --- | ---: | ---: |
| Handshake/control CBOR body | 64 KiB | 64 KiB |
| Any data CBOR body | 1 MiB | 8 MiB |
| CBOR nesting depth | 16 | 32 |
| Fields or entries in one collection | 1,024 | 4,096 |
| Feature definitions per offer | 128 | 128 |
| Numeric limits per offer | 128 | 128 |
| Outbound queued messages per session | 256 | 1,024 |
| Outbound queued bytes per session | 8 MiB | 32 MiB |
| Authentication duration | 10 s | 30 s |

Initial negotiated limit definitions are:

| Limit tag | Width/unit | Default | Legal range | Owning feature | Mandatory |
| --- | --- | ---: | ---: | --- | --- |
| `radiata.woooo.tech/limits/data-body-bytes` | `u32` bytes | 1 MiB | 64 KiB-8 MiB | `data-messages` | Yes |
| `radiata.woooo.tech/limits/in-flight-requests` | `u16` count | 256 | 1-1,024 | `direct-request` | Yes |

The abbreviated owner names resolve within `radiata.woooo.tech/features/`. Configuration may lower local
defaults. Data-body and in-flight offers may be raised only within their legal ranges. Queue defaults
may be raised locally only below their absolute ceilings. Queue admission is bounded by count and
bytes. Exceeding a guard or effective limit returns a typed local overload/protocol error and never
partially decodes, persists, or dispatches a new message.

### Session-Scoped Feature Projection

The selected set is pairwise and may differ between two sessions of the same node. It therefore must
not be written as converged user node labels or used by node-wide selectors.

G9 exposes selected features only as a read-only derived resource scoped by
`(local NodeId, peer NodeId, session generation, feature label)`. It is created after mutual
authentication and removed when that session generation ends. Supported features and platform facts
may also be advertised as reserved informational node labels, but those labels never authorize a
message, satisfy a required feature, or feed a future offer. The authenticated session selection is
the only compatibility authority.

### Trace Identity and Signed Request

`TraceId` has canonical form `trace_<21 base62 characters>` using the ADR-0001 alphabet and injected
CSPRNG. It is independent of session, route, attempt, address, and handler correlation IDs.

The source persists one immutable routed request before its first send. Its canonical signed content
contains at least:

- base schema ID and routed-request kind ID;
- cluster ID and `TraceId`;
- source and destination `NodeId` values;
- domain-qualified `<owner-domain>/protocols/<name>` handler tag, with `radiata.woooo.tech` reserved
  for built-in handlers;
- separate required transit-feature and destination-feature label sets;
- opaque payload bytes; and
- fields later declared mandatory by the immutable routed-request schema.

`request_digest = SHA-256(canonical_request_bytes)`. The source signs
`"radiata.woooo.tech/crypto/routed-request-v1" || request_digest` with its ADR-0001 identity key. Every hop verifies
the signature against the persisted source binding. The same `(source NodeId, TraceId)` with another
digest, destination, tag, feature requirement, or payload is a collision/attack and is never
forwarded, dispatched, or ACKed.

### Source-Signed Attempt Authorization

Only the source creates attempt ordinals. For each ordinal it creates canonical authorization content
with schema/kind IDs, cluster ID, source/destination IDs, `TraceId`, request digest, ordinal `0..=3`,
and initial DATA hop limit 15. It signs
`"radiata.woooo.tech/crypto/routed-attempt-v1" || SHA-256(canonical_attempt_bytes)` with its identity
key. Every hop verifies this signature and all bound fields before journal lookup or route work.

A DATA forwarding envelope carries the immutable request, source request signature, immutable attempt
authorization/signature, and mutable remaining hop count. Remaining hops starts at 15, may never exceed
the signed initial value, and decreases exactly once per edge. Zero before destination delivery fails
with a typed route error. Each attempt uses one next hop and never fans out. In a crash-free execution,
four authorized logical attempts produce at most 60 DATA edge writes.

Ordinal mutation, fabrication, reuse with another request digest, or an authorization signed by anyone
other than the source fails closed. Forwarders cannot turn a captured request into a new attempt.

### Durable Attempt and Forwarding State

Only the source creates attempt ordinals. They are exactly `0`, `1`, `2`, and `3`: ordinal zero is the
initial send and ordinals one through three are retries. Every ordinal reuses the same request bytes,
digest, request signature, and `TraceId`, but has its own source-signed attempt authorization.

Before a socket write, the source persists the ordinal, selected next hop, retry budget, deadline, and
`WritePending` state. A successful write transitions it to `Sent`. Restart never resets the ordinal or
budget. Recovery may replay the same `WritePending` ordinal because the process cannot know whether a
crash occurred before or after the kernel accepted bytes. Repeated crashes can therefore produce more
than four physical writes while logical ordinals remain bounded to four. Deduplication contains this
ambiguity; exactly four physical writes are not promised.

A forwarder journals the key `(source NodeId, TraceId, attempt ordinal)`, immutable digest, decremented
hop limit, pinned next hop, and write state before forwarding. Without a crash it writes each ordinal at
most once. Recovery may replay only that same pending ordinal. A later source retry has a new ordinal and
may pass through to trigger destination re-ACK. Forwarders never create ordinals, branch an attempt,
refresh retention, or autonomously retry. Journal lookup precedes route calculation and quota admission.

Each new source ordinal may recompute its next hop after route invalidation. An ordinal's persisted next
hop never changes. Cycles terminate through decreasing hop limit and the forward journal.

### Direct and Routed Dispatch Authorization

Direct dispatch resolves the domain-qualified protocol tag in the local registry and requires its
owning feature plus every request-required feature to be present in the current authenticated
session's selected set.

Routed dispatch has no end-to-end session selection. Every forwarding hop requires
`radiata.woooo.tech/features/routed-delivery` and all source-signed transit requirements in its local
pair-session selection. The destination independently requires the protocol tag to be registered and
enabled, its immutable owning feature to be implemented and enabled locally, and every source-signed
destination requirement to be implemented and enabled locally. Informational resource labels never
satisfy these checks.

An unknown handler, unavailable owning feature, or unavailable destination requirement produces a
durable terminal `RejectedUnsupported` record and a destination-signed delivery rejection. It never
transitions to `Accepted`, invokes a handler, or emits an acceptance ACK. A valid rejection stops source
retries but is not application success.

### Destination Acceptance, Dispatch, and ACK

The destination first looks up `(source NodeId, TraceId)` even when quotas are full. For an identical
retained digest, `Accepted` or `DispatchStarted` causes a fresh signed ACK, while
`RejectedUnsupported` causes a fresh signed rejection with the same retained reason bound to the
duplicate's authenticated ordinal. No retained state changes its accept/reject outcome because of a duplicate. A conflicting digest fails closed.

For a new trace, one transaction persists the immutable request, digest, source signature, first-commit
time, and destination state `Accepted`. Only after commit may the destination ACK or consider handler
dispatch. The ACK means only that this durable acceptance exists.

Handler execution uses at-most-once invocation initiation. The destination atomically changes
`Accepted` to `DispatchStarted` before invoking the registered handler. Recovery may initiate a record
still in `Accepted`; it never invokes one already in `DispatchStarted`. A crash after acceptance but
before the transition can delay execution; a crash after the transition but before invocation can lose
execution; a crash during invocation leaves external side effects ambiguous. Duplicate requests never
invoke the handler. Handler results and application success are outside the ACK contract.

The destination ACK canonical content contains:

- ACK schema and kind IDs;
- exact cluster ID and `TraceId`;
- source and destination `NodeId` values;
- the immutable request digest and triggering source-signed attempt ordinal;
- initial ACK hop limit 15; and
- the exact status `Accepted`.

It signs `"radiata.woooo.tech/crypto/delivery-ack-v1" || SHA-256(canonical_ack_bytes)` with the
destination identity key. The source verifies the signature against the persisted destination binding,
never the immediate session peer. Wrong-key, wrong-cluster, wrong-source/destination, wrong-schema,
unknown-status, ordinal mismatch, or mutated-digest ACKs do not complete delivery. Forwarders cannot
forge success. The destination does not retry an ACK; a source retry causes an accepted duplicate to
be re-ACKed for that authenticated ordinal.

A signed delivery rejection uses the same context fields, triggering ordinal, and hop limit, with a
closed reason such as `UnsupportedFeature` or `UnknownHandler`, under the domain
`radiata.woooo.tech/crypto/delivery-reject-v1`.

### ACK and Rejection Forwarding

A receipt envelope contains the immutable destination-signed ACK or rejection, the triggering attempt
authorization, and mutable remaining ACK hops initialized to 15. It follows the reverse predecessor
chain stored for that DATA ordinal. Each forwarder verifies both end-to-end signatures, requires the
remaining count to be no greater than the signed initial limit, decrements once, and sends to exactly
one persisted predecessor.

Forwarders journal `(destination NodeId, source NodeId, TraceId, request digest, attempt ordinal)` plus
the pinned predecessor and ACK write state. Without a crash, each receipt is forwarded at most once.
Recovery may replay only the same pending write. Forwarders never recompute an ACK route, fan out, or
retry. Zero remaining hops before the source rejects the receipt. Thus an honest crash-free ACK or
rejection path uses at most 15 edge writes; write-boundary crash ambiguity remains the same named
physical-duplicate risk as DATA.

### Retry Schedule and Completion

After each logical send, the source waits an ACK timeout with default 2 seconds, configurable from
250 milliseconds through 30 seconds. If no valid ACK arrives, the next retry uses equal jitter with
these deterministic ceiling intervals:

| Retry ordinal | Delay range |
| --- | --- |
| 1 | 250-500 ms |
| 2 | 500-1,000 ms |
| 3 | 1,000-2,000 ms |

The injected entropy source determines jitter and records it in replay artifacts. A restart preserves
the ordinal and never emits a burst of all overdue retries; it schedules at most the one persisted
pending ordinal, then continues the table. Send/session failure may invalidate the route but does not
skip or add an ordinal.

A valid ACK transitions a pending retained source record to `Accepted`. Exhausting ordinal three
returns a typed delivery-timeout result and transitions it to `TimedOut`. A later valid ACK for the
retained timed-out record may change durable state to `AcceptedLate` for observability, but it does not
change the result already returned to the caller or refresh retention. An ACK for an absent or expired
source record is ignored and never recreates state.

### Retention and Cleanup

Source, forwarder, and destination trace records use a default retention of 24 hours. Configuration may
select any whole duration from 10 minutes through 30 days. The deadline is each node's
`first_durable_commit + retention`; duplicate requests, re-ACKs, retries, route changes, late ACKs, and
state transitions never refresh it.

Only terminal records are deleted at or after the deadline. Active records are never evicted for age or
capacity. Source `WritePending`, source `Sent`, forwarder `WritePending`, and destination `Accepted`
without a dispatch decision are active. Bounded send/dispatch timeouts must eventually move each record
to a terminal or explicit operator-attention state.

Cleanup uses the durable clock policy fixed by ADR-0003. If restart, rollback, or clock discontinuity
makes elapsed time uncertain, automatic cleanup stops and retains records longer. It must never delete
early. Deduplication and at-most-once dispatch initiation are guaranteed only while the trace record is
retained. A duplicate arriving after expiry can be accepted and dispatched again; this is a named
residual risk.

### Trace Quotas and Backpressure

Initial configurable defaults and absolute bounds are:

| Durable resource | Default | Legal range |
| --- | ---: | ---: |
| Global active trace records | 8,192 | 64-65,536 |
| Active records per authenticated source | 1,024 | 16-8,192 |
| Global total trace records | 262,144 | 1,024-1,048,576 |
| Total trace records per authenticated source | 32,768 | 256-131,072 |
| Global trace-journal bytes | 256 MiB | 16 MiB-4 GiB |
| Trace-journal bytes per authenticated source | 64 MiB | 2 MiB-2 GiB |
| Concurrent source/forward send tasks | 256 | 16-1,024 |
| Concurrent handler invocation tasks | 256 | 16-1,024 |

Per-source active and total-count limits must not exceed corresponding global limits; the per-source
byte limit must not exceed the global byte limit. Global and per-source total quotas include active
and terminal records together.

Initial admission atomically reserves the record's maximum encoded lifecycle size, including its
largest terminal state. A state transition updates that same record and consumes no new count or byte
quota. Admission fails before persistence when the full reservation does not fit. Count, reserved-byte,
and task checks apply atomically. A node
first cleans eligible expired terminal records, then performs existing-key lookup, conflict detection,
and duplicate re-ACK before quota admission. Full quota never blocks an existing duplicate or hides a
conflict.

A new trace that cannot fit all required durable bytes and task ownership receives a typed overload
result before partial persistence or forwarding. Active records are never silently evicted to make
room. Per-authenticated-source active/total counts and total reserved bytes prevent one member from
consuming the global journal; global limits cover colluding or numerous members.

## Required Verification

T-G00-02 is documentation-only. Later gates own executable evidence:

- G1: prelude, domain-qualified tag grammar, and deterministic-CBOR golden/property tests reject every
  non-canonical encoding, namespace violation, duplicate, unknown mandatory ID, invalid length,
  unsupported schema, excessive depth/collection, and allocation above the prechecked limit.
- G3: registry tests reject duplicate labels, dependency cycles, missing dependencies, asymmetric or
  self conflicts, duplicate limit ownership, definition-digest mismatch, and semantic mutation of a
  published `radiata.woooo.tech` or extension-domain fixture.
- G3: negotiation properties cover offer ordering permutations, unknown optional/required labels,
  dependency fixed points, conflicts, limit boundaries, exact selection bytes, and no retry fallback.
- G3/G4: mixed binaries in both initiator roles prove optional-feature intersection, required-feature
  rejection, per-session dispatch gating, and cleanup of session-scoped selected-feature resources.
- G6: request, attempt-authorization, ACK, rejection, and reverse-envelope vectors reject wrong key,
  cluster, endpoint, schema, status, digest, ordinal, hop limit, handler tag, feature requirement,
  domain namespace, and payload mutation.
- G6: deterministic model/property tests assert `attempt ordinal <= 3`, source authorization for every
  ordinal, logical sends `<= 4`, one next hop per DATA/receipt ordinal, both hop counts strictly
  decrease, no-crash DATA writes `<= 60`, each receipt path `<= 15`, and no retry-budget reset/burst.
- G6: fault every persist/write/dispatch/receipt boundary in subprocess tests. Prove one destination
  acceptance, at most one handler invocation initiation, unsupported-handler rejection, duplicate
  re-ACK, conflict rejection, and recovery replay only of the same DATA or receipt ordinal.
- G6: quota tests prove existing duplicate re-ACK and conflict detection while full, atomic
  count-plus-reserved-byte admission, lifecycle transitions without quota growth, typed overload for
  new traces, active-record non-eviction, per-source isolation, and bounded send/dispatch tasks.
- G6: retention tests cover exact boundaries, no TTL refresh, conservative clock rollback/restart,
  late ACK transition, ignored expired ACK, and documented post-expiry redispatch.
- G10: prior/current binaries use feature-label intersection rather than version ordering; golden
  vectors and fuzz corpora cover every published schema, kind, label registry, request, and ACK.

Gate closure uses 10,000-case pure properties where applicable, 1,000 deterministic simulation seeds,
real three-hop public-facade E2E, and real subprocess crashes after those harnesses exist.

## Rejected Alternatives

### Ordered Major/Minor Compatibility Negotiation

Rejected because release and protocol numbers do not describe behavioral compatibility. Feature-label
intersection is the authority. Schema IDs only select exact decoders.

### Pairwise Selected Features as Durable Node Labels

Rejected because one node can negotiate different sets with different peers. Selected features are
session-scoped derived resources; durable node labels are informational only.

### Postcard or JSON as the Wire Baseline

Rejected because Postcard couples compatibility more tightly to the Serde data model and declaration
shape, while JSON adds ambiguous duplicate-key and canonicalization rules. Explicit numeric CBOR fields
provide a smaller stable evolution surface.

### Hop-by-Hop ACK Authentication

Rejected because a forwarding member could forge delivery. The destination signs an end-to-end ACK
that the source verifies against durable identity trust.

### Forwarder or Destination Retries

Rejected because independent retries multiply traffic and obscure the four-attempt source budget.
Only the source creates retry ordinals; duplicate source attempts trigger destination re-ACK.

### At-Least-Once Handler Invocation

Rejected because the roadmap requires retained replay not to redispatch. The core provides at-most-once
invocation initiation and explicitly accepts possible loss around a crash. Applications needing durable
execution must build an idempotent operation protocol above delivery acceptance.

### Retain Forever or Evict Active Records

Rejected because infinite retention is unbounded and active eviction breaks in-flight correctness.
Terminal TTL cleanup plus backpressure preserves explicit limits.

## Consequences

- `minicbor` becomes the wire-codec direction; Serde formats remain separate persisted/backend choices.
- Feature compatibility is explicit and pairwise, with no implicit meaning in release numbers.
- New incompatible semantics require a new label and complete contract tests.
- An incompatible base schema requires coordinated rollout because automatic fallback is forbidden.
- Durable delivery consumes bounded storage at every forwarding hop.
- Four logical source attempts can produce extra physical duplicate writes only across crash ambiguity.
- ACK confirms durable receipt but deliberately says nothing about handler invocation or success.
- Pairwise negotiated features cannot be queried as stable node-wide capabilities.

## Residual Risks

- An authenticated peer may under-offer optional features unless local policy requires them.
- A wrong immutable label registry definition can split selection or authorize unintended behavior.
- Repeated crashes in the socket-write ambiguity window can exceed four physical writes, though trace,
  ordinal, digest, hop, quota, and retention bounds still apply.
- At-most-once handler initiation can lose execution after `DispatchStarted`; handler side effects are
  ambiguous if the process crashes during invocation.
- Duplicates arriving after configured retention can be accepted and dispatched again.
- Malicious authenticated members can consume their per-source quota and contribute to global pressure.
- Clock uncertainty can extend retention and storage use, but must never shorten replay protection.
- A coordinated base-schema epoch rollout is operationally harder than ordered version fallback.

## References

- RFC 8949, Concise Binary Object Representation (CBOR).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 2104, HMAC: Keyed-Hashing for Message Authentication.
- `minicbor` and `minicbor-derive` documentation.
- ADR-0001, Bind Node Identity and Admission to a TLS 1.3 Channel.

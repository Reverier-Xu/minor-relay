---
id: ADR-0003
title: Reconcile durable transactions and order replicated state with HLC
status: accepted
date: 2026-08-02
deciders: minor-relay maintainers
---

# Reconcile Durable Transactions and Order Replicated State with HLC

## Context

Identity admission, routed delivery, replicated state, labels, revocation, and active leave all need
one backend-neutral transaction contract. A caller must distinguish a proven abort from an unknown
commit result and reconcile the latter without duplicating a security or data transition.

Replicated records need a strict deterministic LWW order. Raw wall time is not monotonic across clock
rollback, restart, or multiple mutations in one millisecond. Pure logical time loses the physical-time
semantics already required by the roadmap. The state layer therefore needs a persisted Hybrid Logical
Clock (HLC), authenticated peer-time health checks, future-record quarantine, and an explicit cleanup
boundary for tombstones.

ADR-0002 also delegates trace-retention cleanup to this ADR. Peer-adjusted HLC time must not make a
durable record expire early.

Scenarios `SC-G00-P0-06` and `SC-G00-P0-07` are ratified by
`docs/scenario-catalog.toml`.

## Decision Drivers

- Preserve atomicity across record families and reject lost-update races.
- Return `Committed`, `Aborted`, or `Unknown` honestly and reconcile by transaction identity.
- Prove JSON old-or-new recovery on Linux, macOS, and Windows without overwriting a live file.
- Keep JSON test-only while making its semantic contract identical to redb.
- Fail closed on corruption, unsupported schemas, missing durability capabilities, and lock conflicts.
- Keep identity keys outside ordinary storage while reconciling cross-system key-provider operations.
- Produce a strict total LWW order under equal time, replay, reorder, partitions, and restart.
- Bound malicious future timestamps without letting them advance local time or claim convergence.
- Never remove tombstones automatically; make resurrection an explicit local user risk.
- Never use peer-controlled or discontinuous wall time as proof that retention elapsed.

## Decision

### Backend-Neutral Storage Contract

A storage backend exposes private, backend-neutral operations for:

- immutable consistent snapshots;
- exact key lookup;
- unsigned-byte lexicographic ordered scans by domain-qualified record family and key prefix;
- conditional atomic transactions across all record families;
- durable commit and explicit flush;
- transaction-outcome reconciliation;
- capability and schema inspection; and
- integrity-checked open, close, and recovery.

Keys and prefixes are opaque byte strings. Ordering compares unsigned bytes lexicographically. Empty
prefix selects the entire family. Prefix range construction must handle an all-`0xff` prefix without
wrapping or omitting a valid key. A snapshot remains immutable even after later commits.

Every snapshot has one opaque store revision. A transaction starts from an exact snapshot revision and
contains:

- a fresh canonical `TxnId` of `txn_<21 base62 characters>`;
- a deterministic operation digest;
- an expected base store revision;
- zero or more per-key preconditions of `Absent` or `ValueDigest(SHA-256)`; and
- a bounded batch of puts and deletes across record families.

Commit succeeds only if the base revision and every precondition still match. A mismatch returns typed
`Conflict`, writes nothing, and is a proven abort. The whole batch, schema metadata, HLC watermark,
quota counters, and transaction receipt change together or not at all. Blind read-then-write batches
are forbidden.

The contract guarantees strict serializable local transactions, not cross-node transactions.
Concurrent transactions creating the same credential generation, advancing the same trace, or mutating
the same state key produce exactly one commit and one or more conflicts. Disjoint transactions may
still conflict under a backend with a global revision; callers retry from a fresh snapshot under their
own bounded policy.

### Commit Outcomes and Reconciliation

The only successful commit result is:

```text
Committed { txn_id, operation_digest, resulting_revision }
```

A backend returns `Aborted` only when it can prove no commit point was reachable, or after locked reopen
proves that the exact transaction is absent. `Conflict` and validation failures are definite aborts.
Cancellation or an I/O error after commit-point submission returns:

```text
Unknown { txn_id, operation_digest }
```

`Unknown` freezes subsequent writes on that backend instance. The owning state machine quarantines its
operation and must call `reconcile(txn_id, operation_digest)` against a locked reopened store. The
result is the exact committed receipt, a proven absence, a digest conflict, corruption, or still
unknown. The caller never converts unknown to retryable failure based on timeout.

Every committed transaction writes a bounded `TxnReceipt` in the same transaction. A receipt contains
the transaction ID, operation digest, parent/result revisions, and commit schema tag. Reuse of one ID
with the same digest is idempotent while that receipt remains; reuse with another digest is always
`Conflict`.

Receipt cleanup is explicit and uses the conservative-age policy below, with a default minimum age of
30 days. It may remove a receipt only after no durable owner record, pending operation, provider intent,
migration, or unknown-outcome state references the transaction. After cleanup, idempotence for that ID
has expired and callers must never reuse it. Cleanup conflicts rather than guessing when reference
proof is unavailable.

`flush()` succeeds only when every previously reported committed transaction has crossed the backend's
documented durability barrier. It never upgrades an unknown outcome to committed without reconciliation.

### Capability and Error Contract

Capabilities are explicit domain-qualified values under `relay.woooo.tech/storage-capabilities/<name>`.
The contract distinguishes `ProcessCrashAtomic` from `OsCrashDurable`. Every backend must report the
exact level it proves; a consumer requiring the stronger level rejects a weaker backend.

Initial semantic capabilities are:

- atomic conditional cross-family batch;
- immutable snapshot and unsigned-byte ordered prefix scan;
- durable file/data contents;
- process-crash atomic commit metadata;
- optional OS-crash durable directory/commit metadata;
- exclusive single-writer lock;
- transaction reconciliation; and
- transactional schema migration.

A backend that cannot provide a required capability fails open with `UnsupportedCapability`; it must
not silently weaken semantics. JSON is test-only and may be opened under an explicit
`ProcessCrashAtomic` requirement; production consumers require `OsCrashDurable`. Error classes distinguish `Conflict`, `Unknown`, `Locked`, `Corrupt`,
`UnsupportedSchema`, `UnsupportedCapability`, `QuotaExceeded`, `Permission`, and contextual I/O.
Errors and diagnostics never contain private keys, credentials, opaque user values, or full signed
records.

The durability claim covers process crashes and OS crashes under the operating system's documented
file/data and directory-metadata flush contracts. Physical media, controllers, hypervisors, or remote
filesystems that falsely acknowledge flush remain residual risks.

### JSON Generation Store

The default `json` feature is strictly test-only. It rewrites a complete logical snapshot on every
transaction and never overwrites or removes the current generation as its commit point.

A store directory contains:

- one stable, never-renamed lock file;
- immutable final generation files;
- strictly recognized temporary files; and
- no mutable current-pointer file.

The backend canonicalizes the existing parent directory and identifies the store sufficiently to
prevent the same process from opening aliases through symlinks or junctions. It acquires an OS-backed
exclusive lock on the stable lock file before initialization, generation enumeration, recovery,
cleanup, migration, or writes, and holds it for the backend lifetime. File existence is not lock
ownership. Process death releases the OS lock; a stale lock file is retained and reused.

A generation filename contains a zero-padded strictly increasing generation number and `TxnId`; names
are created once and never reused. Its deterministic JSON header contains:

- store UUID and generation number;
- parent generation number and whole-file digest;
- transaction ID and operation digest;
- schema manifest and resulting store revision;
- transaction receipt;
- encoded body length; and
- whole-file SHA-256 checksum.

Map keys are serialized in deterministic byte order. JSON is a persisted test format, not the wire
format. Checksums detect accidental corruption but do not authenticate an attacker with directory write
access.

A commit under the lock performs:

1. validate revision, preconditions, schema, bounds, and operation digest in memory;
2. create a never-before-used same-directory temporary file with create-new semantics;
3. write the complete next generation and flush file contents and metadata;
4. atomically rename it to its never-before-used final generation name;
5. cross the platform directory-entry durability barrier when the selected capability provides one;
   otherwise establish only the explicit process-crash commit point; and
6. return `Committed` only at the selected capability level before delivering the result.

The final-name rename is the process-crash commit candidate. Under `OsCrashDurable`, the directory
barrier establishes reportable durability: locked reopen validates the exact final chain and must
successfully repeat that barrier before returning committed; barrier failure remains unknown. Under
`ProcessCrashAtomic`, a matching complete final generation after process restart proves committed but
makes no OS/power-loss claim. Authoritative absence is aborted; conflicts and unverifiable state fail
closed. Lost result delivery is reconciled from the receipt.

Reopen validates the store UUID, strictly increasing generation sequence, exact parent number/digest,
transaction identities, schema tags, lengths, and checksums. An invalid highest final generation,
duplicate generation, broken parent chain, unknown schema, or conflicting transaction ID returns
`Corrupt` or `UnsupportedSchema`. It never silently chooses an older valid generation.

All valid final generations remain before `0.1.0`, so complete parent-chain validation never depends on
a deleted ancestor. The JSON store has configurable generation-count and total-byte ceilings with
defaults 1,024 and 4 GiB; reaching either returns `QuotaExceeded` before creating a new generation.
Tests that need more history create a fresh store rather than deleting evidence.

Cleanup runs after the logical commit decision and may remove only strictly recognized stale temporary
files under the lock, followed by a directory barrier. It preserves every final generation and every
unrelated file. Cleanup errors after a proven commit barrier return
committed with a typed maintenance warning; errors before durability is proven remain unknown.

On Unix, correctness-critical JSON may claim `OsCrashDurable` only after safe directory-fd fsync passes.
On Windows, the approved safe dependency path does not expose a write-through directory barrier, so
JSON reports only `ProcessCrashAtomic` and remains test-only. Any production/durable consumer rejects
it with `UnsupportedCapability`; redb closes the production Windows requirement at G8. Native process
crash tests still exercise Linux, macOS, and Windows, while OS-crash durability tests run only where the
reported primitive is observable.

### redb Mapping

The future `redb` backend maps one storage transaction to one redb write transaction and maps snapshots
and ordered scans without exposing redb types through unconditional public API. It reports committed
only after the configured durable redb commit succeeds. An error with uncertain commit status follows
the same `Unknown` and reconciliation contract.

JSON and redb must return the same logical records, scan order, precondition outcomes, schema errors,
transaction receipts, and reconciliation results. Backend-specific performance and file layouts are
not contract behavior.

### Key-Provider Operation Protocol

Storage transactions cannot atomically include external `KeyProvider` effects. Every provider uses
opaque handles and idempotent operation IDs and reports `Present`, `Absent`, or `Unknown` during
reconciliation.

Identity creation uses this ordered protocol:

1. persist a conditional `KeyCreationIntent` binding operation ID, intended `NodeId`, record purpose,
   and expected public-key algorithm;
2. ask the provider to create durably under that operation ID;
3. reconcile until the provider returns one exact handle and public key;
4. atomically replace the intent with the exact identity binding after verifying the public key; and
5. retain operation evidence until no unknown storage/provider outcome remains.

Deletion first atomically installs a target-bound `KeyDeletionIntent` after a fresh locked snapshot
proves no identity, migration, creation intent, transaction, or unknown outcome references the handle.
The intent makes every later transaction that would add a reference conflict. The provider then deletes
under the intent's durable operation ID and reconciles `Present`/`Absent`/`Unknown`. A final conditional
transaction replaces a proven-absent intent with a `KeyDeleted` tombstone. The handle is never reused.
Migrations copy handles opaquely and never export key bytes. Every load verifies that the provider's
public key equals the persisted binding before signing.

### Persisted Schema and Migration Graph

Every record begins with an immutable domain-qualified schema tag such as
`relay.woooo.tech/schemas/state-record`. Schema tags are opaque identities with no numeric ordering.
Published tags and decoders are never redefined or reused.

A migration registry contains one immutable implementation for each exact
`(source_schema_tag, destination_schema_tag, migration_tag)`. Migration tags use the owner's
`<domain>/schemas/<name>` namespace. Registry construction rejects duplicate edges, cycles, ambiguous
paths, unknown source or destination schemas, missing target decoders, and implicit numeric ordering.

Migration runs under the backend lock as one ordinary conditional transaction. Data, indexes, schema
manifest, migration receipt, and transaction receipt change atomically. Reapplying at the target is a
no-op only when the recorded migration tag and implementation digest match exactly. Unknown outcomes
use normal transaction reconciliation.

An older binary opening an unsupported schema returns `UnsupportedSchema` without any mutation. No
implicit downgrade or inverse migration exists. "Interrupted migration rollback" means old-or-new
recovery through the transaction commit point, not execution of a reverse migration.

### HLC Representation

A timestamp is:

```text
HlcTimestamp { physical_ms: u64, logical: u32 }
```

`physical_ms` is Unix epoch milliseconds from the internal adjusted clock. The persisted local
watermark is the greatest HLC state the node has emitted or first accepted. It never decreases.

The checked bump operation is:

- `(p, c + 1)` when `c < u32::MAX`;
- `(p + 1, 0)` when `c == u32::MAX` and `p < u64::MAX`; and
- permanent `ClockExhausted` at `(u64::MAX, u32::MAX)`, with no write.

For a local mutation with adjusted physical time `pt` and watermark `(l, c)`:

- if `pt > l`, choose `(pt, 0)`;
- otherwise choose `bump(l, c)`.

For the first accepted unique remote record `(r, d)`, let `m = max(pt, l, r)` and evaluate these
branches in order:

1. if `l == m && r == m`, choose `bump(m, max(c, d))`;
2. else if `l == m`, choose `bump(l, c)`;
3. else if `r == m`, choose `bump(r, d)`;
4. else, `pt == m`, so choose `(pt, 0)`.

Equality with `pt` does not exclude the earlier `l` or `r` branch. Thus `pt == l > r` uses branch 2,
`pt == r > l` uses branch 3, and a three-way tie uses branch 1.
A byte-identical duplicate is idempotent and does not bump the watermark repeatedly. Every first
accepted remote record advances the watermark even when that record loses LWW comparison.

A local mutation and its new watermark commit in one transaction. A first remote acceptance, its
winner/loser or history record, and the merged watermark also commit in one transaction. A crash yields
both old or both new. Restart computes local events from `max(adjusted physical time, persisted
watermark)` through the rules above; wall-clock rollback never reduces HLC.

### Signed State Record

The state-record schema is `relay.woooo.tech/schemas/state-record`. Its deterministic-CBOR signed body
contains:

- record schema tag and cluster ID;
- domain-qualified namespace/schema tag and bounded key bytes;
- HLC timestamp and writer `NodeId`;
- tombstone flag;
- content type/schema tag and exact opaque bytes for a value, or canonical absence for a tombstone; and
- immutable fields later added only under a new state-record schema tag.

The writer signs
`"relay.woooo.tech/crypto/state-record-v1" || SHA-256(canonical_signed_body)` with its ADR-0001
identity key. Bounded canonical decoding, trusted writer-key lookup, `writer == signer`, and strict
signature verification happen before quarantine, HLC merge, winner comparison, digest calculation, or
persistence. Mutation or omission of any signed field fails closed.

A record requires an exact nonconflicting writer binding. ADR-0006/G9 defines revoke as a connection
and authorization boundary, not content erasure: after a writer is durably revoked, its correctly
signed state/resource history remains eligible for deterministic anti-entropy even when another node
first observes it later. The revoked identity cannot establish a session or submit a new online
operation. Unknown or conflicting writer bindings remain rejected, not quarantined; removing historical
content requires the explicit cleanup API.

### Strict LWW Order

Records are comparable only when namespace and key are identical. The winner is the lexicographic
maximum of:

```text
(
  physical_ms,
  logical,
  canonical_writer_node_id_bytes,
  tombstone_rank,
  SHA-256(canonical_signed_body)
)
```

`tombstone_rank` is `0` for a value and `1` for a tombstone, so deletion wins only in the otherwise
impossible equal-HLC/equal-writer collision. The signature bytes are excluded from the final digest.
An identical tuple/body is idempotent.

The same writer and HLC with different body digests is signed equivocation. Nodes still converge by
the digest tie-breaker but emit one bounded, deduplicated equivocation event keyed by writer/HLC/key.
No automatic revoke, cleanup, or metadata mutation follows.

The comparator and merge must prove totality, antisymmetry, transitivity, commutativity, associativity,
and idempotence over all record permutations.

### Peer Clock Sampling and Health

The library never changes the operating system clock. It maintains an internal offset and uncertainty
through nonce-bound samples over mutually authenticated direct sessions. A request records local UTC
and monotonic send times. The response echoes the nonce and carries responder receive/send UTC times.
The requester records local UTC and monotonic receive times and computes the NTP-style delay and offset.

A sample is accepted only when its nonce/session generation matches, monotonic delay is nonnegative and
at most one second, processing interval is valid, arithmetic does not overflow, absolute offset is at
most 60 seconds, and sample age is at most 60 seconds. Sample uncertainty is
`ceil(monotonic_delay / 2) + 1 millisecond`. Only the newest valid sample per distinct trusted
`NodeId` participates. Replayed, stale, unauthenticated, revoked, or malformed samples are rejected.

Clock constants are:

| Setting | Default | Legal range |
| --- | ---: | ---: |
| Maximum sample RTT | 1 s | Fixed before `0.1.0` |
| Maximum sample age | 60 s | Fixed before `0.1.0` |
| Maximum absolute sample offset | 60 s | Fixed before `0.1.0` |
| Agreement uncertainty | 250 ms | 10 ms-1 s |
| Local UTC/monotonic discontinuity | 1 s | 100 ms-5 s |
| Maximum internal-offset slew | 500 ms/s | 10 ms/s-1 s/s |

For deterministic median calculation, sort signed millisecond offsets by value and then `NodeId`.
Include local offset zero as one vote. An odd vote count selects the middle value; an even count uses
the checked arithmetic midpoint of the two central values, rounded toward zero.

Active peers are distinct trusted peers with a current authenticated session. The required fresh peer
inlier count is `min(3, active_peer_count)`. A peer is an inlier exactly when
`abs(sample_offset - median) + sample_uncertainty <= agreement_uncertainty`. Consensus uncertainty is
the maximum left-hand side across required inliers. One peer cannot provide multiple votes. The
internal offset target is the median,
but a target outside `max_future_skew` is unhealthy rather than silently clamped. Valid target changes
slew at the configured maximum and never step the OS clock.

A local clock discontinuity compares UTC elapsed with monotonic elapsed; a difference above the
configured bound invalidates all samples. Clock health is:

- `HealthyIsolated` when there are no active peers and the local clock has no discontinuity;
- `Healthy` when the required distinct peer inliers exist, consensus uncertainty is within the bound,
  the target is within `max_future_skew`, and no discontinuity or arithmetic error exists;
- `Degraded` when active peers exist but fresh agreeing evidence is insufficient and no hard bound was
  violated; and
- `Unhealthy` after an absolute-offset violation, discontinuity, target outside the allowed skew,
  offset arithmetic/slew saturation, or HLC exhaustion.

Healthy, isolated-healthy, and degraded nodes may accept remote records under quarantine rules. A node
with active peers accepts new local state mutations only while healthy; degraded or unhealthy returns a
typed `ClockUnhealthy` result without writing. An isolated-healthy partition may accept local writes,
but unreachable peers pause the SLO and reconnection starts a new interval after clock sampling.

The median tolerates outliers only under the stated distinct-voter assumptions. Three colluding peers
can control a larger cluster's median inside the accepted bound, and a two-node cluster cannot identify
which endpoint clock is wrong without an external authority. These are residual risks.

### Future-Skew Quarantine

`max_future_skew` defaults to five seconds and is configurable from 500 milliseconds through 60
seconds. The absolute future horizon is 24 hours and is not configurable before `0.1.0`.

After signature and size validation, a record timestamp is classified against adjusted physical time:

- at or below `now + max_future_skew`: admissible;
- above that bound and at or below `now + 24 hours`: future quarantine; or
- above the absolute horizon: hard rejection.

Quarantine has durable defaults and hard maxima:

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| Global records | 4,096 | 65,536 |
| Records per writer | 512 | 8,192 |
| Global bytes | 64 MiB | 1 GiB |
| Bytes per writer | 16 MiB | 256 MiB |

The quarantine key includes writer, namespace, key, HLC, and signed-body digest. An identical duplicate
does not consume quota or change time. Quarantined records persist across restart, are never evicted to
admit new records, return a distinct non-acceptance result, and are excluded from the winner, local HLC
watermark, deltas, authoritative digests, and convergence acknowledgement. Full quota rejects a new
future record before partial persistence.

The normal clock/anti-entropy tick re-evaluates quarantine without requiring reconnect. When a record
becomes admissible, one transaction removes it from quarantine, merges it as a first remote acceptance,
advances the watermark, and stores winner/history/equivocation evidence. Offset movement backward never
promotes a record early. A source continues bounded anti-entropy while authoritative digests differ.

### Conservative Durable Age

HLC and peer offset are never the elapsed-time oracle for retention. Each runtime has a random boot ID
and injected monotonic clock. For a definitely committed record in the current boot, proof starts no
earlier than observed `Committed`. For an unknown outcome, proof starts only at successful committed
reconciliation. Submission, rename visibility, and an unresolved outcome accrue no retention age.

A record from a prior or unknown boot may expire automatically only after the current process has run
continuously for at least the full configured retention duration. Wall time, peer offset, HLC, restart
metadata, or a forward clock jump cannot shorten this wait.

A monotonic discontinuity discards every accumulated current-boot age proof. Cleanup remains suspended
through clock recovery, then each retained record starts a fresh full-retention monotonic interval. No
pre-discontinuity elapsed time is reused. This intentionally over-retains by up to one full retention
interval after restart, reconciliation, or discontinuity.

This lower-bound age policy satisfies ADR-0002: uncertainty can extend storage use but can never expose
an early trace replay window.

### Tombstones and Explicit Cleanup

Delete creates a normal signed state record with no value bytes, `tombstone_rank = 1`, and a fresh HLC.
Tombstones replicate and participate in anti-entropy indefinitely. Connectivity, liveness, storage
maintenance, TTL cleanup, migration, and compaction never remove one automatically.

Local cleanup requires all of:

- exact namespace and key;
- the complete expected winning tombstone version tuple and signed-body digest;
- a non-default typed acknowledgement `AcceptStaleReplicaResurrection`; and
- a conditional transaction proving the current winner is still that exact tombstone.

The transaction removes the exact winning tombstone and every local accepted value/tombstone winner or
history record plus every future-quarantine record for that namespace/key. It may retain unrelated
bounded equivocation audit evidence. It does not reduce the HLC watermark, create an absence version,
emit a replicated delete, or modify unrelated metadata. A stale expectation or concurrent newer
put/delete returns `Conflict` and writes nothing. Crash recovery is old-or-new through the normal
transaction contract.

Absence never wins anti-entropy. A surviving peer tombstone may return and suppress stale values. If a
user explicitly removes every reachable tombstone, an offline stale value may later become the winner
and propagate. Cluster-wide cleanup is repeated explicit local operation, not a coordinator, quorum,
or consensus protocol. The API cannot know about every offline copy and reports this residual risk.

Metadata cleanup uses the same exact-record CAS and typed acknowledgement pattern. Revocation and
active leave remain separate explicit operations. Maintenance code has no access to cleanup authority.

## Required Verification

T-G00-03 is documentation-only. Later gates own executable evidence:

- G1/G2: snapshot immutability, unsigned-byte prefix ordering including empty/all-`0xff`, base-revision
  and per-key precondition conflicts, cross-family all-or-nothing batches, TxnId idempotence/conflict,
  and exact committed/aborted/unknown reconciliation.
- G2: JSON native subprocess kills and faults before/after write, file flush, unique rename, directory
  barrier, result delivery, cleanup deletion, and cleanup barrier. Assert old/new recovery, fail-closed
  highest-generation corruption, lock alias/contention/release, unrelated-file preservation, and no
  referenced key deletion.
- G2/G8: capability refusal, JSON/redb contract parity, conditional conflicts, transaction receipts,
  unknown reconciliation, provider operation intents, and secret-safe diagnostics.
- G8: migration graph duplicates/cycles/ambiguity/no-path/downgrade, every edge twice, unknown outcomes,
  unsupported older reader, and byte-identical logical JSON/redb results.
- G7: every HLC local/remote branch, duplicate idempotence, logical/physical exhaustion, rollback,
  restart, concurrent mutation, and subprocess crash at mutation/watermark boundaries.
- G7: signed-record mutation/omission/wrong-key/cluster/writer/schema tests and comparator algebra over
  equal HLC/writer, tombstone/value, equivocation, duplicate, reorder, and all permutations.
- G7: nonce/session sample replay, RTT/age bounds, asymmetric delay, distinct-peer median, one malicious
  outlier, collusion, partitions, stale samples, slew/saturation, two-node ambiguity, and unhealthy-write
  rejection.
- G7: quarantine exact boundaries, duplicate/full quota, per-writer isolation, restart, offset movement,
  hard horizon, maturation without reconnect, authoritative digest mismatch, and eventual convergence.
- G6/G7: conservative age exact boundary, current/prior boot, rollback/forward jump, restart, monotonic
  discontinuity, uncertain commit, and proof that uncertainty only extends retention.
- G7/G9: cleanup stale CAS, race with newer put/delete, old/new crash, surviving-tombstone restoration,
  all-copy cleanup plus offline stale resurrection, and proof that maintenance never invokes cleanup.
- G7: 8+8 partitions and 16-node tests cover accepted/quarantined mixtures, duplicate/reordered pages,
  restart mid-sync, cleanup during sync, maturation on normal tick, bounds, and SLO admission rules.

## Rejected Alternatives

### Raw Wall Clock or Pure Lamport Time

Raw wall time is not monotonic across rollback/restart and cannot distinguish same-millisecond local
mutations. Pure Lamport time loses the physical-time behavior required by the roadmap. Persisted HLC
provides both properties.

### Last Valid JSON Generation on Corruption

Rejected because a malformed highest final generation passed the commit-name boundary and indicates
corruption. Silently selecting an older file would turn corruption into unreported rollback.

### Mutable JSON Current Pointer or In-Place Replacement

Rejected because replacement semantics differ across platforms and can require deleting the current
file first. Immutable unique generations make the old/new commit candidates explicit.

### Blind Batches Without Preconditions

Rejected because they allow lost updates in credential, trace, watermark, and cleanup state machines.

### Automatic Tombstone Expiry

Rejected because an unknown offline stale replica can resurrect deleted data. Cleanup is explicit,
local, conditional, and risk acknowledged.

### HLC as Retention Age

Rejected because peer offset and wall-clock discontinuity can move HLC forward and delete deduplication
records early. Current-boot monotonic lower bounds are the only automatic age proof.

### Quarantine Eviction or Future-Time Clamping

Rejected because eviction hides non-convergence and clamping changes the writer's signed order.
Bounded rejection plus later exact re-evaluation preserves semantics.

### Reverse Migration

Rejected because inverse transformations may be lossy. Migration interruption recovers old or new
through one commit point; it never executes an automatic downgrade.

## Consequences

- All correctness-critical mutations use conditional transactions and reconcile unknown outcomes.
- JSON is portable and crash-auditable but intentionally inefficient and test-only.
- Native filesystems must expose required durability and locking capabilities or backend open fails.
- Storage checksums detect accidental corruption, not malicious directory modification.
- HLC state is a persisted correctness record and participates in every local/remote state transaction.
- Signed state records prevent forwarders from forging writers but not trusted writers from choosing
  any timestamp inside the admissible window.
- Future quarantine consumes bounded durable capacity and can delay convergence without claiming it.
- Restart may conservatively extend trace retention by one full configured interval.
- Tombstone cleanup is an irreversible R3 local operation that can enable stale resurrection.

## Residual Risks

- Physical media, controllers, hypervisors, or remote filesystems may lie about flush durability.
- An attacker with store-directory write access can alter files and checksums; host integrity is outside
  the backend contract.
- OS locks coordinate compliant processes but cannot stop administrative deletion or hostile tooling.
- Provider implementations may offer weaker durability/deletion semantics and must report capability
  failure rather than be trusted implicitly.
- LWW is not causal, linearizable, or consensus ordering.
- A malicious admitted writer can deliberately win with any timestamp inside the allowed future window.
- Small clusters cannot identify which clock is wrong without an external authority.
- Digest collision risk and compromised identity keys remain cryptographic residuals.
- Quarantine and conservative retention may increase storage pressure while preserving correctness.
- Explicit cleanup cannot discover unknown offline tombstones or values and intentionally permits
  resurrection after acknowledgement.

## References

- Kulkarni, Demirbas, Madappa, Avva, and Leone, Logical Physical Clocks and Consistent Snapshots in
  Globally Distributed Databases.
- RFC 8949, Concise Binary Object Representation (CBOR).
- ADR-0001, Bind Node Identity and Admission to a TLS 1.3 Channel.
- ADR-0002, Negotiate Feature Labels and Provide Bounded Durable Delivery.

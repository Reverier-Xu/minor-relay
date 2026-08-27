# minor-relay Verified Findings (G3-era review, 2026-08)

> **G7 re-review 2026-08-25 (main, four fresh reviewer lanes +
> orchestrator):** G7 verdict **PASS-WITH-GAPS**; all six verify-g07-\*
> lanes PASS; Q suite green on rerun (first run had one parallel-load
> flake: routed_packets handshake `AuthenticationFailed: handshake
> closed`, 3/3 green in isolation — harness lacks connect retry).
> All P0/P1 findings spot-checked against source.
>
> ### P1 — verified
> 1. session/stream.rs:1118 unbounded `pending_acks` HashMap; entries
>    removed only on ack/session end; liveness_observer (:613) exempts
>    sessions with pending work from idle close → a peer that accepts
>    opens but never acks keeps sessions alive while origin memory grows
>    linearly with sends. Cap concurrent pending admissions per session
>    (typed Overloaded) and/or deadline-bound the has-work hold-off.
> 2. Cursor-pagination loop ×5 with ALREADY-DIVERGENT end-of-stream:
>    routing.rs:377-417 peeks one extra entry (honest has_more);
>    supervisor.rs page_members/page_topology use `items.len() < limit`
>    heuristic that can emit a trailing cursor whose next page is empty;
>    membership/page.rs + resource/page.rs emit_page_ctx are two more
>    copies. Extract one shared scan_paged helper.
>
> ### P2 hotspots (top of backlog)
> - membership/sync.rs ↔ resource/sync.rs systemic duplication:
>   drain_body+MAX_SYNC_BYTES, alive_peers/peers_fingerprint,
>   send_payload — security-relevant validation paths fixed twice.
> - Page envelope codec duplicated membership/page.rs:46-146 vs
>   resource/page.rs:50-121 (capacity/canonical/fingerprint).
> - Subprocess crash-matrix scaffolding triplicated (json/crash.rs,
>   resource/crash.rs ×2 lanes, json/native.rs) with hardcoded
>   crash-point numbering.
> - resource/retention.rs sweep_removed_ctx materializes every removal
>   record then applies cap post-hoc, O(n·m) freshness filter, full
>   namespace scan every 2s unconditional — violates boundedness rule
>   at the 262,144-record cap (contrast trace lane's counter gate).
> - transport→session domain cycle: registry.rs:206,236 calls
>   session::handshake_frame_rules; frame rules belong in protocol.
> - node/builder.rs:48-59 WSS hardcoded as dial/listen transport;
>   registry extensibility decorative at node level.
> - supervisor.rs recovery_tick N+1 snapshot per unreachable member.
> - simulation/* incl. artifact fs capture compiles into non-test builds.
> - storage/receipt.rs:412 outcome classified by operations.len()==2.
> - Magic literal 64 in supervisor paging + neighbor degree vs named
>   consts; "limits" category literal compared in 3 places; tag.rs:139
>   hardcoded reserved (domain,category) pair duplicating feature.rs
>   policy; records.rs record_digest duplicates signature::body_digest;
>   handshake decode_wire reimplements decode_canonical_strict.
>
> ### Evidence gaps for the G7 gate record
> - SC-G07-P0-18 (revised 16-node SLO workload covering admission+
>   packets+node revisions+resources ≤10000 ms): NO test exists;
>   resource/e2e.rs:386 comment defers it to a dedicated G10 harness.
>   Either write the G7 sample or amend the catalog/plan row.
> - E2E-06 covered at store+sync layer only (resource::e2e); no real-
>   session/public-facade resource convergence integration test exists
>   in tests/ (membership_sync covers metadata but not resources).
> - SC-G07-P0-11 restart/readdress mid-resource-repair exercised only
>   indirectly via partition-healing e2e; no dedicated case.

> **G6 re-review 2026-08-25 (main @ b9cd349, five fresh reviewer lanes +
> orchestrator):** G6 verdict **PASS-WITH-GAPS**; Q suite and all five
> verify-g06-\* lanes green; planning validator green (69/226/10/29).
> All P0/P1 findings below spot-checked against source. Hotspots:
>
> ### P0 — leftover debug output in the G6 hot path
> - `eprintln!("DEBUG …")` ×10: session/forward.rs:70-81,101,197;
>   runtime/supervisor.rs:771,840,871; session/stream.rs:1084.
>   Prints NodeIds/routes to stderr on every routed open/pump. Delete or
>   convert to `tracing::trace!` before gate closure evidence freeze.
>
> ### P1 — should-fix (all verified)
> 1. membership/page.rs:74 `descriptor.encode().unwrap_or_default()` —
>     swallowed encode failure ships an empty descriptor that fails remote
>     decode; propagate the error.
> 2. identity/trust.rs:585 silent `continue` on malformed binding rows +
>     magic binary format (`len<33 || bytes[0]!=1`) + stringly snapshot key
>     parsed back with `rsplit('/')…unwrap_or(0)` (trust.rs:472,512) —
>     violates fail-closed rule 8; use a schema-tagged CBOR record and a
>     binary composite key.
> 3. Canonical decode re-encode check inconsistently applied: present in
>     identity/records.rs:98, protocol/handshake.rs:841, routing/trace.rs:285,
>     protocol/offer.rs:134, storage/pending.rs:379; ABSENT in
>     membership/sync.rs:89 and page.rs:86. Security-adjacent divergence —
>     add one `decode_canonical_strict` in protocol/cbor.rs.
> 4. transport/connection.rs receive loop duplicated verbatim between
>     Connection::receive (:223) and ConnectionReader::receive (:366), send
>     likewise (:197 vs :329); already drifted (trace logging only in one).
> 5. Forwarding-table take/across-await/restore race: session/forward.rs
>     relay_chunk (:113-130) removes the hop during unbounded backpressure
>     await; close_for_peer (:160-180) misses it and restore can resurrect a
>     terminated route (leak; downstream never gets end).
> 6. runtime/supervisor.rs member()/page_members() hand-roll descriptor→
>     MemberView mapping twice (carried over from 2026-08-24 backlog — still
>     unfixed at G6).
>
> ### Evidence gaps for the gate record
> - SC-G06-P0-18: trace retention tested with monotonic forward clock only;
>     no rollback/freeze case in routing/trace.rs (candidates.rs/recovery.rs
>     have the pattern to copy).
> - SC-G06-P0-13/14: no wire-level duplicate-open consumer-twice test; ACK
>     "admission-only" semantics asserted only implicitly via E2E ordering.
>
> ### Recurring cross-gate patterns (fix once, everywhere)
> - epoch-millis conversions duplicated ≥4 sites; CommitOutcome four-arm
>     mapping ×3-4; AckStatus↔ErrorKind mapping ×3 with catch-all
>     StreamInterrupted in packet/mod.rs:573; trace kind_from_code silently
>     maps unknown codes → Internal (trace.rs:136) contradicting its own
>     fail-closed doc; host-clock `now_millis` bypasses injected WallClock
>     (stream.rs:1363); god-functions run_outbound (~200 ln), sync_tick,
>     Supervisor::new, send_packet.

> **Post-closure spot review 2026-08-25 (main @ cc984d8, two fresh
> reviewer agents + supervisor-run verify lanes):** evidence chain
> COMPLETE — all five verify-g06-* scripts PASS locally; task/scenario/
> impact registration consistent; all nine development-gates G6 Verify
> bullets covered. Code verdict NEEDS-WORK → remediated same day:
>
> ### Fixed in the remediation pass
> 1. relay_chunk dropped the hop's relay lock before its backpressure
>    await (contradicting its own comment), letting a concurrent
>    close_for_peer enqueue End ahead of an in-flight chunk — strict
>    chunk-then-end order (SC-G06-P0-09) could break under load. The
>    guard now spans encode + send_waiting; regression test
>    closing_session_end_queues_after_the_last_in_flight_chunk pins it.
> 2. ForwardingTable had no concurrent-route cap: any authenticated peer
>    could open unbounded trace_ids. New routes beyond
>    TraceMetadataLimits::active() now fail closed with AckStatus::Overloaded.
> 3. MemberView construction de-duplicated: membership::member_view now
>    takes the ConnectivityStatus directly and routing.rs candidate reads
>    plus supervisor label mutation flow through it (was three inline
>    constructions contradicting the "single mapper" doc).
> 4. ParserLimits TODO(G6) resolved: NodeConfig::parser_cbor_limits feeds
>    every packet-frame decode (decode_open/chunk/end/ack take limits);
>    public knob is no longer write-only.
> 5. Terminal trace persistence bounded by a 16-permit semaphore inside
>    TraceSink; retention-sweep skip-gate counter now tracks successful
>    persists minus sweep removals instead of counting total packets ever.
>    take_existing alias folded into take.
>
> ### Still open (carried)
> - Policy invoked before envelope validation in forward::open (minor).
> - SC-G06-P0-18 rollback/freeze clock cases and wire-level
>   duplicate-open consumer-twice test remain unwritten.
> - Fresh backlog (2026-08-24) P1 items unchanged.

> **Re-review 2026-08-24 (main @ post-ADR-0008, four fresh agents +
> orchestrator):** G5 verdict PASS-WITH-GAPS; Q suite and all twelve
> g04/g05 lanes green. Session-trust migration (ADR-0008) verified
> consistent code-to-doc. New backlog below supersedes the remediation
> order at the bottom of this file.
>
> ## Fresh backlog (2026-08-24)
>
> ### P1 — should-fix
> 1. Revision-gap convergence contradiction: the store accepts only
>    exact-next revisions, so a peer that misses one descriptor revision
>    diverges permanently while page.rs:6-8 / SC-G05-P0-07 claim repair.
>    Fix: relay intermediate revisions, accept strictly-greater remote
>    applies (tombstone rule still blocks downgrades), or amend the
>    scenario text.
> 2. `RecoveryPolicy.neighbors` dead field; `plan_neighbors` has no
>    runtime caller; file-level `allow(dead_code)` masks both. Wire or
>    delete, and narrow the allow.
> 3. SC-G05-P0-22 counting-transport observation absent (dial path
>    bypasses the transport registry); P0-29 SLO sampled at eight nodes
>    vs sixteen-node catalog text — sample a sixteen-node run or amend
>    the catalog.
>
> ### P2 — nice-to-have
> - Supervisor recovery tick still scans the full binding namespace once
>   (needs the member set; acceptable) — sync.rs sites resolved 2026-08-24
>   (early-exit count + count short-circuit).
> - RESOLVED 2026-08-24: snapshot revisions pruned on persist;
>   paged_trust_ctx streamed without whole-population materialization.
> - Page sends now fingerprint-gated (content + peer set) with a 32-tick
>   resend backstop; steady-state anti-entropy traffic is zero.
> - Multi-thread packet race: NOT reproducible after the wait_for harness
>   fix (17/17 green x5 under multi_thread); closed as harness bug.
> - Supervisor `member()`/`page_members()` hand-roll descriptor paging;
>   expose a bounded paged read on the membership store instead.
> - `sync_tick` two-regime god-function with duplicated peer-dispatch
>   blocks; split around the membership-regime check.
> - Test-only factory-handle wrappers behind allow(dead_code)
>   (read_descriptor/store_descriptor/emit_page/apply_page/trust
>   wrappers) — move to test support; drop the 10s magic timeout.
> - Binding raw-byte format sniffed in persist_binding_ctx vs decoded
>   IdentityBindingV1 in adopt_binding_ctx — decode both.
> - Snapshot key `{issuer}/{revision:020}` written/formatted in one
>   place, reverse-parsed in another — extract an encode/decode pair.
> - Multi-thread-runtime packet-delivery race was worked around by
>   keeping join lanes current_thread (2bc3b38); the underlying race is
>   UNINVESTIGATED — reproduce with multi_thread attributes before G6.

Verified against the codebase on 2026-08-22 (main @ c8f0394). P1 = should-fix,
P2 = nice-to-have. All line numbers are from that revision and drift.

## Resolution status (updated after the P1+P2 fix pass, 2026-08-22)

- **All seven P1 findings are fixed** (base62/hex/condition sharing, error
  projection, test harness consolidation, typed-bus dispatch, constant
  single-sourcing).
- **All twenty P2 findings are fixed**, including two that grew beyond the
  original plan: `connect_member` now pins member reconnects to the
  join-time leaf SPKI (the join hint carries it; documented as a wire
  format addition), and hostname/IP grammar is delegated to `domain` 0.11
  and `std::net` with lowercase normalization for storage/comparison.
- `docs/implementation-plan.md` records the `domain` dependency amendment;
  `docs/roadmap.md` lists which gate consumes each reserved config field.
- Remaining known follow-ups: M6 moves the routing-domain code out of
  `session/stream.rs` (marked `TODO(M6)`); M9 wires `NodeHandle::events`
  (marked `TODO(M9)`); G5 wires the anti-entropy config fields (marked
  `TODO(G5)`).

## G4 status (2026-08, gate in progress)

- T-G04-01..06 all registered with verify lanes (`verify-g04-01..06`), all
  lanes PASS on the working tree; full suite 392 tests, zero warnings.
- Delivered: transport/discovery registries with the built-in WSS registered
  by default; identity-scoped endpoint candidates with wall-clock expiry;
  deterministic crossed-dial session ownership with drain; bounded session
  queues (count+bytes) and wall-clock liveness (idle + keepalive); signed
  trust snapshots with fail-closed verification, durable persistence, and
  paged observations; credential-free member reconnect (E2E-01/02/03).
- Handoff to G5: the member-to-member trust propagation protocol (SC-G04-P0-17/18
  dissemination and offline catch-up) needs the membership sync/anti-entropy
  channel that G5 builds; the G4 components it consumes (trust store,
  binding persistence, member-mode reconnect) are in place and unit-verified.
- TODO markers added for G4-06 wiring that the reconnect E2E consumes:
  `WssConnection::into_split/inner/join_hint`, `WssTransport::with_hint`,
  `Connection::ping/pong_last_seen` pre-split forms.

## G4 fresh re-review (2026-08, four independent reviewer agents)

Fresh-context reviewers confirmed the G4 evidence (392 tests, six verify lanes)
and surfaced four P1 bugs, all fixed and committed (364c564):

1. **Dead session entries blocked reconnection** — the crossed-dial
   replacement decision ignored `previous.alive()` and teardown never removed
   the table entry, so a reconnect from the non-winning direction was dropped
   at both endpoints forever. Fix: only live entries compete under the
   ownership rule; teardown removes the registered dead entry.
2. **Bounded queue admission was racy under concurrent senders** —
   check-then-act on count/bytes could exceed the byte budget. Fix: one
   mutex-protected critical section for admission+reservation.
3. **`latest_snapshot` ignored the issuer** — it scanned the whole namespace
   and picked the max revision across all issuers, so another issuer's higher
   revision shadowed the trusted one. Fix: scan with the issuer key prefix.
4. **Keepalive never observed the pong** — the timeout measured time since
   the locally-sent ping, closing a peer that answers every ping but sends no
   binary traffic. Fix: reflect peer pongs into the injected clock's activity
   mark and require no response for the full deadline.

P2 fixes (3e11e46): PageCursor/EndpointCandidate manifest accessor names,
single-parse typed transport tag, SessionPolicy::from_config single-sourcing,
writer-failure session teardown, snapshot_digest delegation.

Deferred with TODO markers (G4-06 wiring / G7): `WssListener::close` is a
no-op until the supervisor consumes the registry listener (needs a shared
cancel signal); `Supervisor::new` keeps four `unreachable!` invariants;
`WallClock` still lives in `storage::receipt` (move to node when G7 lands);
transport pong timestamps use host seconds while session liveness uses the
injected clock (reconcile units when G4-06 wires keepalive for real).

Health check outcome: the G4 transport/session/trust additions are
structurally sound — open registries per manifest, injected wall clock, no
production unwrap/expect/unsafe, and the crossed-dial ownership rule is a
total order verified by unit and integration tests.

## G5 status (2026-08, gate in progress)

- T-G05-01..05 (descriptors, pages, neighbors, recovery, seeded sim) all
  registered with verify lanes (`verify-g05-01..05`), all lanes PASS; full
  suite 399 tests, zero warnings.
- Delivered: owner-signed node descriptors with strict-next revisions and
  signed removal markers; bounded anti-entropy pages (emit/apply with
  fail-closed dishonest-page rejection); deterministic sparse neighbor
  planning with a maintenance limiter; the continuous recovery state
  machine (activation/backoff/fan-out/quiesce/reactivate/immediate); a
  seeded recovery simulation that replays exact decisions.
- Handoff for the remaining batch: T-G05-05's 16-node facade E2E
  (SC-G05-P0-21/22) and T-G05-06 readiness/scale closure (SC-G05-P0-23..29:
  15+1 readiness, exact 32-session/degree-4/diameter-3 topology, membership
  failure matrix, 10s metadata SLO, 1,024-node trend) need a 16-node
  facade harness and public topology/membership views; the controller,
  planning, and page components they consume are in place and unit-verified.
- Wired from NodeConfig: `anti_entropy_interval` (page ticks) and
  `RecoveryConfig` (recovery policy) remain TODO(G5) until the facade
  harness consumes them.

## G5 batch 2 (public views + 16-node core, 2026-08)

- Public membership/topology views shipped per the api manifest:
  `PageSpec`, `MemberView`, `MemberPage`, `TopologyEdgeView`,
  `TopologyPage`, `ConnectivityStatus`; `GetMember`/`PageMembers`/
  `PageTopology` queries through the typed bus.
- A node lazily publishes its own signed descriptor (revision 1); views
  read the descriptor store through the metadata store and annotate
  connectivity from the session table without re-opening storage.
- A sixteen-node join harness proves all fifteen authenticated edges are
  visible through the public topology view.
- G5 is complete: the session-carried membership sync protocol streams
  signed descriptor pages and the issuer-signed trust snapshot over
  authenticated sessions; members relay the highest verified snapshot so
  the grant set propagates across the sparse topology; the recovery
  controller heals edge loss among ever-connected members, never dials
  intentionally disconnected peers until a deliberate reconnect, and
  quiesces at connected-path connectivity.
- Sixteen-node E2E passes: reciprocal trust (15 and 16), exact 28-edge
  induced CQ4 and exact 32-session/degree-4/diameter-3 topology, node 15's
  grant on all members, descriptor readiness, partition healing, and the
  metadata SLO lane (8-node: <10s). A 1,024-node functional/trend unit
  lane covers the seed.
- Fresh three-reviewer pass (2026-08-22): P1 recovery-pending monotonic
  counter fixed (atomic in-flight bound released by the detached dial);
  core protocol registration moved before ready (typed conflict, no
  spawned-task panic); SLO lane times the full admission window and the
  harness cross-checks exact NodeId-to-key and descriptor-digest agreement;
  failure-matrix header/scenario citations narrowed to what is tested;
  single canonical descriptor decoder; shared trusted-anchor resolver;
  snapshot version and binding key substitution fail closed; the driver
  threads the page cursor across ticks so descriptor sync converges beyond
  sixteen members; plan_neighbors walks the cycle without a whole-
  population allocation; the recovery simulation is cfg(test)-gated.
- Residual gaps recorded: the counting-transport observation (SC-G05-P0-22)
  is unit-only (the dial path does not consume the transport registry);
  the failure matrix exercises duplicate delivery and partition healing
  (reorder/endpoint-change/restart covered by descriptor-store unit tests
  and the secure-join restart lane).

## Historical findings (pre-fix baseline)

## P1 — should-fix (verified in real code)

1. **TypeId if-else "typed bus" dispatch** — `src/node/handle.rs:64-120`:
   `command()` has 7 sequential `if id == TypeId::of::<X>()` branches and
   `query()` has 4, using `downcast_input`/`cast_output` `Any` machinery
   (handle.rs:132-150). `Command`/`Query` are sealed marker traits with zero
   methods (`src/operation.rs:9-16`), so the compiler cannot enforce
   exhaustiveness: a new command compiles and silently becomes `Unsupported`.
   Fix: add `async fn run(self, runtime: &RuntimeClient) -> Result<Self::Output>`
   to the sealed traits (impl per command), or a closed enum bus.
2. **Hex encoding duplicated in production** — `src/identity/deletion.rs:285-296`
   (`deletion_purpose` hand-rolls nibble→hex) vs `src/storage/json/document.rs:241`
   (`hex_encode` lookup table). Same lowercase-hex of a byte slice. Test-only
   copies in 8+ files (identity/testing.rs:583, lifecycle.rs:861,
   protocol/{credential,feature,handshake,selection}.rs, storage/pending.rs:840).
   Fix: one `crate::hex` codec (encode+decode); `Digest` could render its own hex.
3. **base62 ID validation duplicated** — `src/identity/id.rs:149-166`
   (`validate_id` + `is_base62`) vs `src/provider.rs:654-670`
   (`validate_key_operation_id` + identical `is_base62`). Fix: one shared
   `validate_prefixed_base62(value, prefix, context)`.
4. **Oracle-dup hazard: condition evaluation twice** —
   `condition_matches`/`expectation_matches` byte-identical in
   `src/storage/contract.rs:368-406` (reference oracle) and
   `src/storage/json/store.rs:487-526` (adapter under test). A bug in both
   copies cancels out and the contract can no longer catch condition
   regressions. Fix: share one `pub(crate)` definition.
5. **Mirror error enums with hand-written table** — `ErrorKind`
   (`src/error.rs:6-28`) vs `ProviderErrorKind` (`error.rs:33-49`) mapped by a
   12-arm `provider_error_kind` table (`error.rs:217-233`); each variant maps
   1:1. `ErrorKind::Revoked` has no constructor/producer anywhere. Fix: derive
   the mapping from data or collapse; remove `Revoked` until a gate produces it.
6. **Test harness duplicated** — `src/identity/lifecycle.rs:484-727`
   re-implements `SequenceEntropy`/`KeyCall`/`ScriptedKeys` from
   `src/identity/testing.rs:38-191` (drift already: lifecycle's entropy
   rejects non-16-byte fills; `KeyCall::Sign` lacks the message payload).
   Fix: parameterize `identity/testing.rs` and delete the lifecycle copy.
7. **Constant triplication** — `PENDING_NAMESPACE`
   ("relay.woooo.tech/metadata/pending-transaction-v1") in
   `identity/testing.rs:32`, `identity/lifecycle.rs:503`,
   `storage/pending.rs:40`; built-in feature tag strings in
   `protocol/feature.rs:45-49` (private consts), `protocol/offer.rs:320-326`
   (`BUILTIN_FEATURES: [&str; 5]`), `protocol/selection.rs` tests; and
   `storage/pending.rs:789-790` re-declares `LOCAL_IDENTITY_NAMESPACE`/
   `CLUSTER_GENESIS_NAMESPACE` from `identity/records.rs:30,33`. Fix: export
   from the owner module (`feature.rs` consts `pub(crate)`; `records.rs`
   namespaces) and import everywhere.

## P2 — notable (verified)

- **`src/storage/contract.rs` is a 4124-line god file** mixing reference
  provider (32-407), contract runner (410-890), engine tests (894-1787),
  unknown-fault tests (1789-2400), receipt-ref tests (2448-3357), journal
  tests (3359-4124). Split along those seams. The reference provider is
  `pub(crate)` test-support living in production `src/` (imported by
  identity/{admission,deletion,genesis,lifecycle}.rs tests) — the
  `test-support` crate is the intended home.
- **Routing-domain logic parked in `src/session/stream.rs:421-625`**
  (`run_outbound`, `RouteTable`, `insert_route`) — roadmap assigns routing to
  its own module (M6). Mark for the move.
- **Handshake kind tables duplicated** — `probe`/`position_sender`/
  `position_arity` (`protocol/handshake.rs:802-840`) hardcode kind→position,
  position→role, position→arity that `protocol/wire.rs:33-58`
  (`HandshakeKind` registry) should own. Also `MAGIC "MRLY"` twice
  (envelope.rs:3 bytes, handshake.rs:67 text) and `BASE_SCHEMA_ID` in two
  types (wire.rs:18 u16, handshake.rs:68 u64).
- **Duplicate commit/reconcile control flow (7 copies)** —
  identity/{lifecycle,genesis,deletion,admission}.rs all repeat the
  `match store.commit() { Committed | Unknown => reconcile … | Aborted }`
  shape; `commit_admission`/`adopt_admission` (admission.rs:72-256, 272-397)
  are ~150-line god-functions sharing a skeleton. Extract a
  `commit_with_reconcile` helper.
- **String-concatenated durable purpose strings** — `purpose: String` in
  `KeyCreationIntentV1`/`KeyDeletionIntentV1` (records.rs:299-311, 372-384)
  built by concatenation at 6 call sites ("key-delete-" + hex, "admission-" +
  hex, "local-identity", "cluster-genesis"). Typed `JournalPurpose` enum
  would make them exhaustive; they become durable storage values.
- **Dead/speculative public surface** — `NodeHandle::events` returns
  `Err(Error::unsupported("node events"))` unconditionally (handle.rs:123-128)
  while `node/event.rs` ships full `EventOptions`/`EventSubscription`
  machinery; `member_client_config` (`transport/tls.rs:70-79`) is
  `#[allow(dead_code)]` with a stale "production wiring arrives with G3-04"
  comment although `connect_member` already exists; ~18 `#[allow(dead_code)]`
  accessors (Selection::features/limits, FeatureOffer::limits,
  FeatureDefinition::fingerprint, LimitWidth::U64, …) await G3-04 consumers.
- **Unwired config defaults** — `anti_entropy_interval`, `RecoveryConfig`,
  `session_queue_bytes`, `ParserLimits`, `TraceMetadataLimits.terminal/
  retention` are validated-but-unconsumed; `ParserLimits` (config.rs:101-122)
  duplicates `CborLimits` (protocol/cbor.rs:11-27) semantics. Wire them or
  delete until their gates land.
- **Stringly routing policy** — `DIRECT_ROUTING_POLICY: &str` (packet/
  mod.rs:30) compared by string at node/handle.rs:48; every other registry
  keys on typed tags. Typed `RoutingPolicy` enum or `QualifiedTag` const.
- **`hex` purpose-key loops in production** — `adoption_purpose`/
  `admission_purpose` (admission.rs:450-457, 542-549), `deletion_purpose`
  (deletion.rs:285-296), `generation_hex` (transport/ws.rs:71-77) — four
  copies of the same nibble loop with different prefixes.
- **Scenario topology defined twice** — `run_fault_matrix_seed`
  (simulation/network.rs:530-560) and `ScenarioFixture::network_fault_matrix`
  (simulation/fixture.rs:29-52) register the same 4-node/8-link matrix
  independently; renaming desynchronizes failure-artifact aliases.
- **`EventKey` redundant fields** — `ordinal`/`reorder_rank`
  (simulation/event.rs:42-57) are pure functions of `frame`; `EventPhase` has
  3 of 4 variants constructed only in tests.
- **`condition` also duplicated in receipt→pending outcome mapping (4 sites)**
  — `CommitOutcome` four-arm matches in storage/mod.rs:150-175,
  receipt.rs:496-505, receipt.rs:415-428, pending.rs:656-664.

## Healthy (do not "fix" these)

- Facade: `lib.rs` re-exports deliberately, `compile_fail` privacy doc-tests
  enforce the boundary; `extension`/`adapters` submodules are coherent.
- `extension_registry.rs` and `protocol/feature.rs` both key on typed tags —
  the approved extension pattern; the stringly `DIRECT_ROUTING_POLICY` is the
  only inconsistency.
- `protocol/cbor.rs` canonical encoding (shortest-arg, map order, depth caps,
  bounded writer) is exemplary; secrets are zeroized/redacted; constant-time
  HMAC; golden-byte fixtures pin transcripts and records.
- `#[cfg_attr(not(test), deny(clippy::unwrap_used, expect_used))]` in
  `src/lib.rs` is why production unwraps stay out; the `unwrap()`s found by
  naive greps in storage/contract.rs etc. are all test-double/test-module code.

## Remediation order

1. Shared hex codec + shared `condition_matches` + shared base62 validator +
   constant exports (kills the highest-divergence duplicates).
2. Replace the TypeId bus with per-command `run` methods.
3. Split `storage/contract.rs` along its six seams.
4. Export namespace/feature constants; de-duplicate lifecycle test harness.
5. Wire or gate the speculative public surface (events, member_client_config,
   config defaults) before 0.1.0.

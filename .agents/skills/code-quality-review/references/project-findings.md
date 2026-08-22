# minor-relay Verified Findings (G3-era review, 2026-08)

Verified against the codebase on 2026-08-22 (main @ c8f0394). P1 = should-fix,
P2 = nice-to-have. All line numbers are from that revision and drift.

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

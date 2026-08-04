---
id: ADR-0001
title: Bind node identity and admission to a TLS 1.3 channel
status: accepted
date: 2026-08-02
deciders: minor-relay maintainers
---

# Bind Node Identity and Admission to a TLS 1.3 Channel

> **Amended by ADR-0007.** The identity, key binding, channel binding, and fixed admission policy
> remain active. The 1,024-member rejection boundary is superseded; 1,024 is now evidence coverage.

## Context

A node initially joins with only a receiver address and a receiver-owned join credential. It has no
PKI trust anchor, pinned certificate, or prior receiver public key. After admission, credentials must
not participate in member authentication. Addresses are endpoint candidates and never identities.

A self-signed TLS connection protects against passive observation but does not authenticate the
receiver to the joiner. Sending a join credential directly through such a connection would expose it
to an active TLS-terminating attacker. The bootstrap therefore needs application authentication that
binds the credential and both durable identities to the exact completed TLS connection.

The accepted product contract also requires a newly admitted `NodeId` and public key to reach every
cluster member. A node that loses its original connection must reconnect to any member that has the
signed admission record, without presenting a join credential again.

Scenarios `SC-G00-P0-01` and `SC-G00-P0-02` are ratified by
`docs/scenario-catalog.toml`.

## Decision Drivers

- Resist active interception, replay, reflection, downgrade, identity misbinding, and key substitution.
- Keep the external join inputs to receiver address plus join credential.
- Make credentials generated secrets rather than human passwords.
- Bind every established session to durable asymmetric identity keys.
- Permit one member to admit a node cluster-wide without replicating the credential.
- Recover safely when a final admission response or a connection is lost.
- Propagate new public-key bindings to online members and catch up members that were offline.
- Fail closed on key loss, identity collision, trust-store loss, or conflicting signed records.
- Keep secrets and channel-binding material out of logs, wire records, and replicated state.

## Decision

### Identity Syntax and Binding

`NodeId` is a case-sensitive ASCII string with this canonical form:

```text
node_<21 base62 characters>
```

The suffix alphabet is exactly `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`.
The total encoded length is 26 bytes. Parsing rejects every other prefix, separator, length,
character, case transformation, surrounding whitespace, and non-canonical representation. New IDs
use 21 uniformly sampled base62 characters from an injected cryptographically secure entropy source.
The suffix provides approximately 125 bits of entropy.

A `NodeId` is randomly generated and is not derived from an address, certificate, public key,
cluster, label, or storage location. Identity is the immutable pair `(NodeId, Ed25519 public key)`.
The durable identity binding records its format version and key algorithm. A node proves possession
of the corresponding private key on every session.

A binding already trusted for a `NodeId` is immutable. The same `NodeId` with another public key is a
collision or impersonation attempt and fails closed. The implementation never selects a winner and
never rebinds automatically. A local pre-admission collision generates a new ID; a cluster-detected
collision requires a new identity and a fresh credential-based join. Re-observing the same pair is
idempotent only after a valid proof of possession.

### Identity Key Lifecycle

The durable identity algorithm is Ed25519. Private keys are generated with the operating system
CSPRNG through an injected entropy boundary. The core stores only the `NodeId`, public key, algorithm
tag, and opaque key-provider handle in ordinary storage. Raw private-key bytes must never enter the
backend-neutral storage records, protocol frames, debug output, metrics, or failure artifacts.

A `KeyProvider` is responsible for durable creation, loading, signing, and deletion. It must return a
durable handle and public key before the core commits the identity binding. A definitely aborted
binding transaction leaves an unused handle that may be treated as an orphan. An indeterminate commit
outcome quarantines the handle: the core reopens storage and reconciles the exact `(NodeId, public key,
handle)` binding before signing, networking, retrying creation, or deleting anything. The provider may
delete an orphan only after authoritative storage reads prove that no committed binding references it.

Restart loads the recorded handle and verifies that the provider returns the recorded public key.
A missing handle, corrupt key, or different public key returns an identity-unavailable error and
stops networking. The node must not generate a replacement key under the old `NodeId`.

Private-key loss creates a new key, a new `NodeId`, and a fresh join. In-place identity-key rotation
is not supported before `0.1.0`; active leave later implements explicit identity replacement. A copied
private key is cryptographically indistinguishable from the original and remains a named residual risk.

### Cluster Genesis

`ClusterId` uses the same case-sensitive base62 rules as `NodeId` and the canonical form
`cluster_<21 base62 characters>`. A freshly persisted identity is standalone until it either creates
or joins one cluster.

Cluster creation is allowed only when authoritative storage reads show no cluster record, trust
record, or unresolved cluster transaction. It atomically commits a versioned `ClusterGenesis`, the
creator's immutable trusted identity binding, and the local cluster pointer. `ClusterGenesis` contains
the cluster ID, creator `NodeId` and public key, format version, and a creator signature under the
`relay.woooo.tech/crypto/cluster-genesis-v1` domain. It is the initial trust record, not a network observation.

A definite abort leaves the identity standalone. An indeterminate result blocks create/join and is
reconciled by reopening storage: the exact genesis transition either exists in full or is absent.
The node never creates a second cluster to hide an unknown outcome. A joiner adopts the receiver's
cluster ID only after validating the receiver's credential and identity proofs.

### Join Credential Lifecycle

A join credential is exactly 32 uniformly random bytes rendered as unpadded base64url with the
sensitive textual prefix `join_`. Users cannot choose, shorten, normalize, or supply the random body.
HKDF does not turn a human password into an acceptable credential; supporting passwords would require
a separately reviewed PAKE and is outside this protocol.

Each receiver has at most one active credential generation. A generation is:

- valid for ten minutes of the receiver's injected monotonic clock;
- memory-only and invalid after process restart;
- invalidated immediately by explicit rotation;
- reserved by at most one in-progress commit; and
- consumed by exactly one successfully committed new identity.

A receiver may rotate at any time. Rotation creates a new independent value and invalidates the old
one. Credential text, derived proof keys, and proof values are never persisted, replicated, logged,
or included in an admission grant. A non-secret random generation ID may be persisted to support
idempotence and audit correlation.

Credential consumption and the receiver's durable admission commit form one logical transition.
Concurrent attempts with the same generation can commit at most one distinct identity. A failed proof,
collision, or definitely aborted transaction returns the generation from reserved to active while it
remains unexpired. Success erases the secret.

Cancellation or an error after transaction submission can have an indeterminate outcome. The receiver
then quarantines the generation and must not reuse, rotate, release, or report a definitive admission
result. It reopens storage and reads the durable `CredentialUse` and `AdmissionGrant`. An exact record
means consumed; authoritative absence permits release only when the storage contract proves the
transaction aborted; a conflicting record fails closed as issuer equivocation. Process crash erases
the memory-only secret, while the durable outcome remains recoverable through member authentication.

Admission attempt resources use ADR-0006's fixed defaults: four pending attempts per normalized
source, 64 pending globally, 16 attempts per source and 256 globally per fixed minute, 1,024 expiring
source buckets, one verified committer per credential generation, and a ten-second authentication
deadline. Configurable ranges are recorded in `docs/decision-register.toml`; limits cannot be disabled.
All failures exposed to an unauthenticated peer are generic and use constant-time proof checks.

### TLS Bootstrap

All bootstrap and member sessions use TLS 1.3. Both modes disable TLS 0-RTT and session resumption
before `0.1.0`. No application frame is accepted before TLS Finished and application authentication
complete.

The receiver uses a dedicated ephemeral TLS certificate key, separate from its durable identity key.
The certificate is not a node identity or trust record and may change on restart. A joining client
relaxes certificate-chain and hostname trust only. Its TLS verifier must still validate the TLS 1.3
`CertificateVerify` signature and supported signature scheme; unconditional certificate or handshake
signature acceptance is forbidden.

After TLS completes, each endpoint independently computes exactly:

```text
cb = TLS-Exporter("EXPORTER-Channel-Binding", "", 32)
```

This is the RFC 9266 `tls-exporter` channel binding. `cb` is read from the local TLS connection,
never received as a wire field, never logged, and never treated as a secret. Early exporters and a
custom exporter label are not used.

### Canonical Authentication Transcript

The final canonical, length-delimited transcript contains at least:

1. protocol magic and opaque handshake schema ID;
2. explicit `join` or `member` authentication mode and, in join mode, the non-secret credential
   generation ID;
3. fixed initiator and responder roles;
4. cluster ID;
5. both `NodeId` values and Ed25519 public keys;
6. one independently generated 32-byte nonce from each endpoint;
7. both complete ordered supported/required feature-label offers and numeric-limit maps;
8. the deterministic dependency-closed feature intersection and effective numeric limits; and
9. the locally derived 32-byte `cb`.

The wire ADR fixes the canonical encoding and full negotiation fields. Proofs are not valid until the
complete transcript is available. Unknown fields, duplicate fields, non-canonical encodings,
identical identities in both roles, unexpected clusters, conflicting expected keys, out-of-order
messages, or non-deterministic negotiation results fail closed.

The transcript digest is SHA-256 over the canonical bytes. All labels below are exact ASCII and are
included with unambiguous length separation.

### Credential and Identity Proofs

For join mode only, derive credential proof keys as follows:

```text
prk = HKDF-Extract-SHA256(salt = cb, IKM = credential_bytes)
responder_key = HKDF-Expand-SHA256(prk, "relay.woooo.tech/crypto/bootstrap-v1-responder", 32)
initiator_key = HKDF-Expand-SHA256(prk, "relay.woooo.tech/crypto/bootstrap-v1-initiator", 32)
proof = HMAC-SHA256(role_key, transcript_digest)
```

The responder sends its full 32-byte proof first. The initiator sends no proof or identity signature
until the responder proof verifies in constant time. It then returns the initiator proof and its
Ed25519 signature. Role-separated proofs prevent reflection. Captured proofs are offline credential
verifiers, which is acceptable only because credentials have 256 bits of generated entropy.

Both modes require strict Ed25519 verification over role-separated inputs:

```text
"relay.woooo.tech/crypto/session-v1-responder" || transcript_digest
"relay.woooo.tech/crypto/session-v1-initiator" || transcript_digest
```

Join mode enrolls the presented key only after the credential proof and signature both pass. Member
mode has no credential proof: it requires the expected trusted key or a valid signed admission grant,
fresh nonces, a fresh exporter, and both identity signatures. A trusted identity must never fall back
from failed member authentication to credential admission on the same connection.

A TLS-terminating relay creates a different exporter on each leg and cannot translate the proofs or
signatures. A transparent byte tunnel remains possible but cannot read or modify authenticated
traffic. Core `minor-relay` does not terminate relay TLS connections.

### Admission Commit and Grant

After all join proofs pass, the receiving member commits one storage transaction containing the
immutable identity binding, a versioned `CredentialUse`, and a versioned `AdmissionGrant`. Only then
is the joining node admitted and only then may the receiver report success or dispatch application
traffic.

`CredentialUse` has the durable unique key `(issuer NodeId, credential generation ID)`. Its value is
the exact admission ID and subject `(NodeId, public key)` binding. `AdmissionGrant` contains the same
cluster ID, admission ID, subject binding, issuer `NodeId`, credential generation ID, record version,
and issuer signature. The signature uses `relay.woooo.tech/crypto/admission-grant-v1` and covers every field. No
record contains a credential, proof, exporter, private material, or full handshake transcript.

Any currently trusted, non-revoked member may issue a grant. Acceptance by one member is cluster-wide
authorization. Replaying the identical use/grant pair is idempotent. A reused admission ID with other
fields, a reused `(issuer, generation)` with another admission or subject, the same subject ID with a
different key, an invalid signature, or an untrusted issuer fails closed. A conflicting signed record
is issuer equivocation and requires explicit reconciliation; the core selects no winner. Revoking an
issuer does not silently cascade to identities it previously admitted.

The transaction result has `committed`, `aborted`, or `unknown` semantics. `Unknown` quarantines the
credential generation and triggers the reconciliation defined above. It must not be translated into
a retryable unauthenticated error.

The joining node records a durable `JoinPending` checkpoint containing its local identity, cluster ID,
receiver binding, and generation ID before it sends its final proof. It stores no credential. Receipt
of the signed grant transitions that checkpoint to admitted trust. A lost final response is recovered
by attempting member authentication with the same identity key. If the receiver committed, it accepts
the proof and returns the stored grant. If it definitely aborted, member authentication fails and the
user must provide an active credential for another join attempt.

### Reconnection and Public-Key Propagation

After admission, every connection, reconnection, address change, crossed dial, and process restart uses
member mode and fresh channel/identity proofs. Join credentials are not consulted. Session acceptance
requires reciprocal trust: each endpoint must establish the other's exact public key independently.
A one-sided grant is never enough.

The admitting receiver durably enqueues the new node's grant for normal trust synchronization. Every
online member persists the grant before acknowledging it and exposes the exact subject
`NodeId -> public key` binding through the manifest-defined read-only trust view. Members that were
offline during admission acquire it through normal trust anti-entropy after restart; reconnection is
not a special merge trigger.

For clusters with existing peers, the issuer provides the new node a bounded, versioned
`SignedTrustSnapshot` over the authenticated issuer session. It covers the cluster ID, issuer identity,
snapshot revision, exact ordered member bindings, record version, and issuer signature under
`relay.woooo.tech/crypto/trust-snapshot-v1`. The new node accepts it only from the
credential-authenticated issuer and persists every non-conflicting binding before treating alternate peers as trusted. The snapshot
contains no liveness claim and later normal sync supersedes stale membership coverage.

The new node may present its signed admission grant to a peer that already trusts the issuer but has
not received the grant. The peer persists the grant before accepting the session. In the other
direction, the new node authenticates that peer only from its persisted signed snapshot or an already
trusted binding. Both sides then verify fresh member-mode signatures over the same TLS-bound transcript.
Conflicting snapshot bindings fail closed.

Trust synchronization is idempotent, bounded, credential-free, and does not infer identity from the
source connection or address. A peer that lacks a trusted binding, a valid grant, or the reciprocal
binding needed to authenticate its counterpart rejects member mode.

## Required Verification

T-G00-01 itself is documentation-only. Later gates must own the following executable evidence:

- G2: restart preserves the exact local `NodeId`, public key, and key-provider handle; definite and
  indeterminate identity commits reconcile without deleting a referenced key; missing or mismatched
  private keys fail closed; private material is absent from ordinary storage and logs.
- G2: empty-store cluster genesis is old-or-new across every crash boundary; a restart never creates a
  second cluster; `ClusterGenesis`, `CredentialUse`, and `AdmissionGrant` uniqueness properties pass.
- G3: real loopback TLS join rejects a terminating MITM, wrong exporter, replayed nonce/proof,
  reflection, wrong cluster/key/base schema, feature-offer downgrade, malformed identity,
  expired/rotated/consumed credentials, and two concurrent successes for one generation.
- G3: inject definite-abort, committed-response-loss, and unknown outcomes at every admission commit
  boundary; prove reconciliation never admits two subjects for one `(issuer, generation)`.
- G3: after a successful join, rotate the credential, disconnect both nodes, and reconnect using only
  fresh exporter-bound Ed25519 member proofs.
- G3: kill or drop the final admission response and prove the same identity recovers through member
  authentication when the receiver committed, without reusing the credential.
- G4: in an existing three-or-more-node cluster, admit a new node through one member and verify every
  online member persists the exact new `NodeId -> public key` binding.
- G4: disconnect the new node from its issuer and prove it connects to another member without a
  credential. Before accepting the session, assert both endpoints independently persisted and verified
  the other's exact public key; also cover the grant-carrying path before background sync completes.
- G4: keep one member offline during admission, restart it, run normal trust sync, and prove it learns
  the binding and then authenticates the new node.
- G5: under the accepted 16-node SLO profile, trust synchronization converges without unbounded fan-out
  and remains correct across readdressing, partitions, duplicate grants, and restart.

Failure artifacts must contain scenario and seed identifiers but redact credentials, private keys,
proofs, exporter bytes, and unredacted transcripts.

## Rejected Alternatives

### Trust Any Self-Signed TLS Certificate and Send the Credential

Rejected because an active TLS-terminating attacker can impersonate the receiver and capture the
credential.

### Require a Receiver Certificate Fingerprint

Rejected because it adds an external bootstrap input and conflicts with the accepted address plus
credential interface.

### Use TLS Certificate Keys as Durable Node Identity Keys

Rejected to avoid cross-protocol key use and coupling identity persistence to the TLS certificate
lifecycle. Application signatures explicitly bind a dedicated identity key to the TLS exporter.

### Use a Human Password or PAKE

Rejected for the initial protocol. The library generates 256-bit credentials, so offline exhaustive
search is infeasible. A future low-entropy password mode requires a separate PAKE ADR and protocol tag.

### Reuse a Credential Until Manual Rotation

Rejected because one leaked credential could admit multiple identities and amplify Sybil attacks.
Each generation admits at most one identity.

### Derive NodeId from the Public Key

Rejected because the product contract requires a prefix-nanoid identity independent of its key
representation. The immutable signed binding provides the security association and permits explicit
collision handling.

## Consequences

- Bootstrap uses a small application authentication state machine in addition to TLS.
- The custom rustls certificate verifier is security-critical and must be isolated, audited, and
  tested against unconditional handshake-signature acceptance.
- Credential loss before use requires rotation; credential loss after commit does not affect members.
- New member trust is represented by a signed, credential-free record suitable for propagation.
- Addresses and ephemeral TLS certificates may change without changing identity.
- Private-key loss is intentionally unrecoverable as the same identity.
- G3 cannot pass on a two-node happy path alone; it must prove disconnect and credential-free recovery.
- G4 cannot pass until all-node public-key synchronization and alternate-peer reconnect tests pass.

## Residual Risks

- Theft of an unused credential permits receiver impersonation and one unauthorized admission because
  the joiner has no independent receiver-key pin.
- Theft or copying of a durable private key permits full impersonation until explicit revocation;
  cryptography cannot identify the original copy.
- Transparent tunneling, traffic analysis, connection blocking, resource exhaustion, and denial of
  service remain possible within configured bounds.
- A malicious admitted member may issue an unwanted grant because any member is authorized to admit.
- Memory disclosure, core dumps, insecure `KeyProvider` implementations, and compromised operating
  systems can disclose credentials or private keys.
- Loss of both the trust store and a usable backup cannot be repaired by accepting an untrusted peer;
  recovery fails closed or creates a fresh identity and join.
- The exporter/HMAC/signature composition requires focused protocol review before production release.

## References

- RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3.
- RFC 9266, Channel Bindings for TLS 1.3.
- RFC 9257, Guidance for External Pre-Shared Key Usage in TLS.
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 2104, HMAC: Keyed-Hashing for Message Authentication.
- rustls `ConnectionCommon::export_keying_material` and `ServerCertVerifier` documentation.
- ed25519-dalek strict verification documentation.

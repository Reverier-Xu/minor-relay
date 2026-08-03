# minor-relay Threat Model

## Authority

The machine-readable source is [threat-model.toml](threat-model.toml). `THR-001` through `THR-029`
are immutable. The scenario catalog owns executable predicates; this document explains boundaries and
accepted residual risks.

## Protected Assets

- Node and cluster identity bindings, private-key-provider authority, and admission credentials.
- Authenticated TLS sessions, feature selections, request/receipt authenticity, and delivery journals.
- Durable identity, trust, membership, clock, trace, state, resource, migration, and transaction records.
- Availability bounded by frames, queues, tasks, fan-out, retries, storage, quarantine, and rate limits.
- Failure artifacts, corpora, CI attestations, release candidates, eligibility tokens, and packages.

## Adversaries

- An unauthenticated network client with arbitrary malformed input and many transport source addresses.
- A peer with a stolen credential but no admitted identity key.
- A malicious or colluding admitted member with its own valid signing key.
- A peer replaying, delaying, duplicating, reordering, dropping, or reflecting protocol messages.
- A corrupt or unavailable storage/key/network provider.
- A compromised evidence producer attempting command injection, secret retention, budget reduction,
  sample replacement, rerun masking, or release substitution.

## Trust Boundaries

TLS proves channel security, but NodeId/public-key trust is established only by the exporter-bound
application handshake. Addresses and certificates are not identity. Application protocol, transport,
storage, discovery, policy, codec, clock, entropy, and key-provider extensions execute in-process and
are trusted code; registries are extension boundaries, not sandboxes.

The operating system, hypervisor, process memory reader, debugger, application holding a join
credential, and application retaining key-provider authority are outside the core confidentiality
boundary. The library still redacts its own errors, logs, and artifacts.

## Admission Abuse Boundary

Every listener applies the accepted admission defaults before expensive proof or persistence work:
4 pending attempts per source, 64 globally, 16 attempts per source and 256 globally per fixed minute,
1,024 source buckets retained for ten idle minutes, one verified committer per credential generation,
and a ten-second authentication deadline. These controls cannot be disabled and never define identity
or trust.

## Malicious Members and Revocation

A trusted member can submit valid signed operations and consume its bounded quota. Signatures establish
who authored data, not that the content is benevolent. Equivocation is ordered deterministically and
reported; it is not automatically revoked or deleted.

Revocation is prospective for connectivity and authorization. A committed revoke closes and rejects
sessions and new admission authority for the exact NodeId/key. It does not invalidate signed replicated
content, because a partitioned system without consensus cannot establish a global before/after cutoff.
Valid historical or delayed state/resource records remain convergence-eligible. Explicit cleanup is the
only content-removal authority.

## Scale and Availability

Membership is configurable from one through 1,024. Protocol work remains bounded at every size.
Functional scale tests cover the ceiling, but only the one-to-sixteen ADR-0005 population has a
quantified ten-second latency SLO for `0.1.0`. Partitions, cross-host delay/loss, overload, crash, and
larger populations retain functional tests without inheriting that latency claim.

## Evidence and Release Boundary

Failure replay is a closed executable ID plus literal argv, never shell text. Corpus provenance and
secret review happen before hashing or minimization. Every attempt is retained. A product failure cannot
be superseded by a successful rerun; only independently attested infrastructure failure creates a new
lineage.

The publication candidate exists before final evidence. The external eligibility token binds the exact
candidate SHA, Cargo.lock, complete attempt ledger, package version, and artifact digests. The token is
not committed into the SHA it attests.

## Release Rule

Every P0/P1 threat must be `accepted` with a concrete mitigation and either an empty residual or a named
accepted residual. Release fails on an open threat, missing owner, missing scenario, unknown scenario,
ambiguous evidence-impact rule, incomplete attempt, or token/candidate mismatch.

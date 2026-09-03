---
id: ADR-0008
title: Trust membership sync through the authenticated session
status: accepted
date: 2026-08-23
deciders: radiata maintainers
---

# Trust Membership Sync Through the Authenticated Session

## Context

Every membership sync entry — node descriptors, trust snapshots, removal markers, and the pages that
carry them — carried an application-layer Ed25519 signature, and every receiver re-verified every
signature on every page delivery even when the content was already stored. A measured sixteen-node
convergence run spent the overwhelming majority of its wall clock in this redundant verification
storm: per-tick cluster cost grows quadratically with membership while the payload itself is tiny.

The verification is redundant by construction. A membership page only ever travels across a WebSocket
session whose two endpoints proved their identities to each other at establishment time (TLS 1.3
exporter binding plus the six-position handshake transcript). While that connection stays up, the
transport already provides integrity, authenticity, and confidentiality for everything carried on it.
Re-proving the sender's identity once per entry duplicates what the session proves once per
connection. There are no external users and no deployed wire format, so removing the entry-level
signatures breaks nothing that exists.

## Decision

1. Membership metadata received over an authenticated session is trusted for as long as the record
   lives in local storage. The trust anchor is the session handshake, not a per-entry signature.
2. Membership sync entries carry an owner `NodeId` marking and a persistent strictly increasing
   revision, nothing more. Descriptors, trust snapshots, removal markers, and pages lose their
   signature fields, signing paths, and verification paths entirely; the obsolete design is deleted,
   not deprecated.
3. The revision rules keep their correctness roles and lose their authenticity role: same-revision
   and older updates are rejected, any strictly higher revision replaces the record (so anti-entropy
   heals skipped intermediate revisions after a lost delivery), and tombstones defeat replayed
   older entries. Bounded page, byte, queue, and cursor capacities are unchanged.
4. The join admission and session handshake cryptographic evidence (credentials, admission commits,
   exporter binding, handshake transcripts) is unchanged. This ADR covers only the metadata sync
   path introduced in M5; other record families keep their current design until revisited at their
   own gates.

## Consequences

- Sync cost drops from quadratic re-verification to incremental ingestion: an unchanged membership
  set costs one bounded read per tick instead of a signature storm, which removes the measured
  sixteen-node convergence stall.
- An authorized malicious member can inject arbitrary membership entries into peers it holds
  sessions with, until revocation closes its sessions and purges its reachability. THR-012 residual
  risk absorbs this trade-off; revocation remains the containment boundary.
- Stored metadata after a process restart is trusted because the store is local and private, not
  because each row carries proof. Offline catch-up over a new session re-syncs from the current
  cluster state.
- Golden descriptor fixtures shrink to canonical decode vectors; wrong-signature and field-mutation
  scenarios are replaced by marking, revision-lineage, and tombstone scenarios with the same stable
  SC IDs.

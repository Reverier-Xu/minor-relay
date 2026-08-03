---
id: ADR-0005
title: Measure the sixteen-node SLO in an unimpaired OCI bridge profile
status: accepted
date: 2026-08-02
deciders: minor-relay maintainers
---

# Measure the Sixteen-Node SLO in an Unimpaired OCI Bridge Profile

## Context

The roadmap qualifies one-to-sixteen-member clusters under this profile; it does not make sixteen a
product membership limit. The release oracle requires every accepted mutation in the exact 16-node run
to converge within ten seconds. Functional `0.1.0` does not claim that SLO under injected latency,
loss, bandwidth restriction, reorder, partition, cross-host scheduling, or clusters above 16 members.
Those faults remain mandatory simulation, E2E, crash, and soak evidence, but are outside this release
latency oracle.

The first controlled oracle uses OCI containers on one Linux host. Each node is a separate process with
its own identity, redb directory, Tokio runtime, TLS 1.3 WebSocket server, and public facade. Node
traffic uses an ordinary local bridge with no impairment. A private benchmark driver may expose a
control endpoint, but it can invoke only public `minor-relay` API and cannot carry replication data.

Scenarios `SC-G00-P1-03` and `SC-G00-P1-04` are ratified by
`docs/scenario-catalog.toml`.

## Decision Drivers

- Make every host, container, topology, network, clock, storage, payload, and sample condition explicit.
- Exercise production TLS WebSocket, identity/trust, topology, anti-entropy, HLC, and redb paths.
- Prevent the controller from becoming a replication shortcut or reading private state.
- Measure new-node public-key propagation as well as descriptor and LWW state convergence.
- Use a conservative timer and require every raw sample to pass, with no percentile escape.
- Predeclare all run IDs and prohibit post-start exclusion, replacement, or rerun masking.
- Publish exact-commit, image, engine, resource, preflight, warm-up, sample, and cleanup evidence.
- State clearly that same-host healthy networking is the only latency population being attested.

## Decision

### Scope of the Claim

Under the exact profile below, every measured admission/trust, descriptor, put, and tombstone sample
must complete in at most ten seconds. The limit is inclusive:

```text
elapsed <= 10_000 milliseconds
```

The release gate applies to all 125 predeclared measured samples. It is not a p95, p99, mean, confidence
interval, availability percentage, or estimated failure rate. Descriptive statistics may be published,
but only each stratum maximum and the all-samples maximum determine pass/fail.

The profile does not claim ten-second convergence under:

- injected or natural cross-host latency;
- packet loss, bandwidth shaping, reorder, duplication, or network partition;
- multiple physical hosts, cloud regions, overlay networks, service meshes, or proxies;
- clock-skew injection, unhealthy clocks, or future-record quarantine;
- concurrent same-key conflicts, high write concurrency, sustained queue pressure, or quota saturation;
- process crash, storage recovery, rolling upgrade, or container-engine failover during a sample; or
- cold host page cache as an independent population.

Those behaviors still must satisfy their functional bounds and dedicated evidence; they simply do not
inherit this latency promise.

### Harness Boundary

A private workspace harness crate has `publish = false` and depends on `minor-relay` as an external path
dependency. It builds two release binaries:

- `slo-node`, run once in each of 16 node containers; and
- `slo-controller`, run in one controller container.

The external dependency boundary makes private modules inaccessible. `slo-node` may expose a bounded
control endpoint for these exact operations only:

- create or join through the public builder/facade;
- register the fixed synthetic benchmark handler;
- query public trust, membership, topology, clock-health, state, and resource views;
- submit the fixed descriptor/state mutation;
- report public queue/task/resource metrics already exposed by production observability; and
- request graceful public shutdown.

The control endpoint cannot import a trust record, write storage, alter a clock, inject network data,
read a private module, invoke a test-only feature, forge readiness, or carry node-to-node replication.
All cluster traffic, including trust, descriptors, clock samples, deltas, anti-entropy, reads, and
requests, uses the production TLS 1.3 WebSocket path on the data network.

The controller connects only to the control network and has no data-network interface. Each node has
one control interface and one data interface. The control protocol is allowlisted, bounded, mutually
authenticated for the harness, and excluded from the library's public API.

### Host Class

The release oracle runs on one dedicated or exclusively reserved host with:

| Property | Required value |
| --- | --- |
| OS/architecture | Linux x86_64 |
| Kernel | 6.6 or newer, exact version recorded |
| CPU | At least 12 logical CPUs, x86-64-v3 or newer |
| Memory | At least 16 GiB physical RAM |
| Storage | Local SSD/NVMe, ext4 or XFS, no remote/overlay backing for redb volumes |
| Cgroups | v2 |
| Swap | Disabled for the attempt |
| CPU governor | `performance` or an attested equivalent fixed-frequency policy |
| Time source | Host UTC/monotonic healthy; containers share host kernel time |

The attestation records CPU model, physical/logical core and SMT layout, microcode, RAM, storage model,
filesystem/mount options, kernel, cgroup mode, governor, thermal/throttle counters, and virtualization
status. A dedicated VM is permitted only when all virtual CPUs and local storage are exclusively
reserved and the hypervisor class is recorded; results do not generalize to another host class.

Before image preflight, the host must show for 60 continuous seconds:

- total CPU busy at most 10 percent outside the harness;
- at least 12 GiB available memory;
- zero swap in/out;
- storage utilization at most 5 percent outside the harness; and
- zero thermal, cgroup throttle, OOM, or filesystem error event.

Failure aborts the complete attempt before measurement and remains in the attempt ledger.

### OCI Engine and Image

One complete release lineage selects exactly one compatible Docker Engine or Podman version and one
OCI runtime. Mixing engines inside a lineage is forbidden. A separate full lineage may qualify another
engine, but passing one does not claim engine portability.

The node/controller image is built from the exact release-candidate commit and Cargo.lock with Rust
1.97.1 in release mode. Its OCI manifest, config, layer, and base-image digests are pinned and attested.
The image is read-only, contains no source secrets, and is scanned before preflight. No image pull,
package download, registry access, or other external network access occurs after preflight.

Each node container has:

- cgroup-v2 `cpu.max = "50000 100000"` (0.5 CPU);
- 512 MiB memory and no swap;
- 128 PID limit;
- 4,096 file-descriptor limit;
- read-only root filesystem;
- 64 MiB tmpfs for non-durable scratch;
- all Linux capabilities dropped and `no-new-privileges`; and
- one fresh bind-mounted redb directory with a 1 GiB quota on the required local filesystem.

The controller has cgroup-v2 `cpu.max = "200000 100000"` (2 CPUs), 1 GiB memory, no swap,
and a 256 PID limit. The attestation verifies the normalized `cpu.max` values after engine startup
rather than trusting Docker/Podman CLI spelling. Container OOM, throttle, PID/file limit, disk quota,
read-only-root, or security-policy violations after measurement starts fail the attempt.

### Storage Profile

Every node uses redb in its production durable commit mode for identity, trust, clock, membership,
trace, state, and resource records. The 16 directories are distinct, empty at run start, bind-mounted
from the host local SSD/XFS or ext4 filesystem, and never use tmpfs, container overlay storage, a shared
database, or a network filesystem.

The five run directories are never reused. The attestation records redb version, filesystem/device,
mount options, directory allocation, free space, and cache-history policy. The profile allows ordinary
host cache history and explicitly does not claim cold-cache independence. Raw redb and key-provider
volumes are never uploaded.

### Data Network Profile

The data network is one engine-native Linux bridge with:

| Property | Required value |
| --- | --- |
| Address family | IPv4 |
| MTU | 1,500 bytes |
| DNS/service mesh/proxy | None on the data path |
| Host networking | Forbidden |
| Overlay network | Forbidden |
| Injected netem/qdisc impairment | None |
| Configured application loss | Zero |
| Minimum measured WSS throughput | 100 Mbit/s |
| Maximum measured public WSS echo RTT | p99 <= 5 ms and median <= 2 ms |

Node containers receive no `NET_ADMIN`. The harness records `tc -j`, bridge, route, MTU, and network
plugin state and rejects any shaping or unexpected qdisc before warm-up.

Attempt-level preflight verifies the image, host, bridge, routes, MTU, qdisc, engine, storage, and
security configuration before any measured cluster starts. The disposable full-topology warm-up cluster
then runs the echo probes over all 64 directed final-session paths, including node `15`'s four links,
and runs the throughput probes over the four fixed edges `{0,1}`, `{4,5}`, `{8,9}`, and `{12,13}`.
This qualifies the full topology and node-15 admission data paths before the release attempt measures
them.

Immediately before each measured run's admission, its induced 28-edge graph performs 100 sequential
64-byte public WSS echo requests in each of 56 directions and repeats the four fixed throughput-edge
probes. After measured admission forms the final graph, all 64 final directions repeat the echo probes
before descriptor/state warm-up. Every echo must succeed; aggregate p99/median must satisfy the table.
Each throughput edge transfers 16 MiB sequentially in each direction and must sustain at least 100
Mbit/s. Probes use the registered public handler, not ICMP or a side channel.

A disposable-cluster or `run-0` induced-graph probe failure aborts before the first measured sample and
is retained as infrastructure/preflight evidence. Once `run-0` records its first `request_started`, any
later induced/final probe failure, loss, RTT/throughput breach, unexpected route, or network change is a
non-excludable release-attempt failure. It cannot invalidate or replace an individual run. This profile
defines an unimpaired local bridge; it is not a network fault SLO.

### Final Topology

Node labels are fixed integers `0..15` for harness purposes and are not product identities. The final
undirected active-session graph contains exactly these edges for each `i` modulo 16:

```text
{i, (i + 1) mod 16}
{i, (i + 4) mod 16}
```

After deduplication this is 32 edges, degree 4, and diameter 3. Every node is directly reachable on the
bridge, but maintenance must establish only policy edges; no hidden full mesh or controller relay is
allowed.

The measured run begins with nodes `0..14` using the induced final graph: 28 edges, degree 3 or 4, and
diameter 3. Node `15` joins through node `0`. Its only final edges are to `0`, `14`, `3`, and `11`.
Admission may trigger ordinary maintenance, but no harness call manually imports trust or creates an
extra session. Before descriptor/state samples, the public topology view must show exactly all 32 final
sessions and no extra or recovery session.

### Runtime and Clock Configuration

All nodes use the same release configuration:

- one Tokio multi-thread runtime with `worker_threads = 1`, `max_blocking_threads = 4`, and all Tokio
  drivers enabled;
- a controller Tokio multi-thread runtime with `worker_threads = 2`, `max_blocking_threads = 8`, and all
  Tokio drivers enabled;
- normal trust/membership/state delta dissemination enabled;
- normal anti-entropy tick exactly 250 milliseconds;
- no debug logging on hot paths beyond bounded production observability;
- ADR-0002 default frame, queue, request, retry, and retention bounds;
- ADR-0003 HLC and `max_future_skew = 5 seconds`;
- agreement uncertainty 250 milliseconds;
- no injected clock offset, rollback, discontinuity, or future record; and
- no quarantined benchmark record at sample start.

Before and after every measured state sample, all 16 public clock views must be `Healthy`, peer samples
must be fresh under ADR-0003, agreement uncertainty must be at most 250 milliseconds, and no benchmark
record may be quarantined. A degraded/unhealthy transition after measurement begins fails the sample.
Clock-fault behavior remains covered outside this SLO.

### Deterministic Workload

The release attempt predeclares five run IDs `run-0` through `run-4`. Each run creates a fresh cluster.
All IDs and payloads use ASCII. The canonical candidate value is the lowercase hexadecimal Git object
ID exactly attested as `candidate_sha`, without a prefix or newline.

Seed and payload generation is fixed as follows; `||` is byte concatenation and integers are unsigned
big-endian:

```text
sample_seed = SHA-256(
  "relay.woooo.tech/crypto/slo-seed/v1" || 0x00 ||
  u16(len(candidate_sha)) || candidate_sha ||
  u8(run_id) || u8(operation_kind) || u8(operation_index)
)

chunk[c] = SHA-256(
  "relay.woooo.tech/crypto/slo-payload/v1" || 0x00 || sample_seed || u32(c)
)
payload = chunk[0] || ... || chunk[127]
```

`operation_kind` is `0=descriptor`, `1=put`, `2=delete-seed`, `3=tombstone`,
`4=warm-descriptor`, `5=warm-put`, or `6=warm-delete`. The 128 chunks produce exactly 4,096 bytes.
There is no PRNG, compression, encoding, or platform-native integer. Every payload SHA-256 digest is
precomputed into the sample manifest and checked by every writer before submission. The namespace is
`relay.woooo.tech/schemas/slo-payload`.

Each run measures:

1. one admission/trust sample for node `15`;
2. four descriptor samples, owned by nodes `0`, `4`, `8`, and `12`; and
3. twenty state samples: 16 puts followed by four tombstones.

A put uses a fresh ASCII key `run-<r>-put-<n>`, writer node `n`, `operation_kind = 1`, index `n`,
and the exact 4,096-byte payload above.

Before measured state samples, per-run warm-up creates and fully converges four separate keys
`run-<r>-delete-0..3`, using writers `0`, `4`, `8`, and `12`, `operation_kind = 2`, and indices `0..3`.
The final four measured samples delete those keys through the same writers with `operation_kind = 3`.
Tombstone completion requires every node to return the exact signed tombstone/version digest; `None`
is not success.

Each measured descriptor mutation updates only the owner's signed
`relay.woooo.tech/resources/slo-counter` value to ASCII `measured-2`, uses the exact next revision, and
has operation indices `0..3` in owner order. It does not change endpoints, topology, labels used by
feature negotiation, or liveness. Completion requires all 16 public membership views to expose the
exact signed revision and digest.

Samples are sequential. No second measured mutation starts before the prior sample completes and the
cluster quiesces. This profile does not claim concurrent-write latency.

### Warm-Up, Readiness, and Quiescence

Before the five measured runs, one disposable 16-node cluster executes, in this exact order, one
node-15 admission; four descriptor updates by nodes `0`, `4`, `8`, `12` to ASCII value
`disposable-1` at the exact next revision; 16 puts by nodes `0..15` to `disposable-put-<n>`; four seed
puts by nodes `0`, `4`, `8`, `12` to `disposable-delete-<j>`; four tombstones of those keys; public reads
after each operation; one quiescence check; and graceful shutdown. Puts use `operation_kind = 5` and
seed puts use `operation_kind = 6`; every value payload is 4,096 bytes from the canonical generator
with run byte `255`, matching index, and candidate SHA. These samples are marked warm-up and excluded.
The host/image/device cache state they create is recorded.

Within each measured run, nodes `0..14` first become ready and quiescent. Node `15` admission is the
first measured sample. After admission and final-graph probes, the run performs, in exact order: four
warm descriptor updates by nodes `0`, `4`, `8`, `12` to value `warm-1`; 16 warm puts by nodes `0..15`
to `run-<r>-warm-put-<n>`; four warm seed puts by nodes `0`, `4`, `8`, `12` to
`run-<r>-warm-delete-<j>`; four tombstones of those warm-delete keys; and four measured-delete seed puts
to `run-<r>-delete-<j>`. Each operation uses the matching canonical operation kind/index and a 4,096-byte
payload when it has a value. Every operation reaches its exact public completion predicate and
quiescence before the next begins. The run then quiesces before the four measured descriptors and 20
measured state samples.

Readiness requires public evidence that:

- all expected identity bindings and signed descriptors are exact and reciprocal;
- every session is mutually authenticated with the expected feature-definition intersection;
- topology equals the required induced or final graph;
- clocks meet the required health state;
- baseline/warm-up state winners agree; and
- no container resource/security limit has fired.

Quiescence requires three unchanged observations spaced by one complete 250 millisecond anti-entropy
interval. The following domain-qualified public counters must equal zero in every observation:

```text
relay.woooo.tech/resources/inflight-requests
relay.woooo.tech/resources/pending-connects
relay.woooo.tech/resources/pending-recovery
relay.woooo.tech/resources/pending-sync
relay.woooo.tech/resources/pending-dispatch
relay.woooo.tech/resources/storage-transactions
relay.woooo.tech/resources/unknown-transactions
relay.woooo.tech/resources/quarantined-records
```

`relay.woooo.tech/resources/long-lived-tasks` and the public session-generation digest must equal the
induced-topology baseline before admission, then the final-topology baseline captured after node `15`
forms all four sessions. Exact semantic public views, not byte/transaction counts, own durable deltas:
admission changes aggregate latest trust/descriptor bindings from the exact 15-node view to the exact
16-node view; descriptor replacement does not change descriptor cardinality; each fresh put adds one
latest state key per node; and each tombstone replaces, but does not remove, one latest state key per
node. Durable commit totals and allocated bytes may increase implementation-dependently and are
attested as resource observations, never compared for equality or used as a quiescence shortcut.

All three observations also require stable topology/version digests, exact public view agreement, the
operation-specific durable cardinality above, no benchmark quarantine, and no cgroup/resource event.
These counters come from production observability owned by G10; the helper never reads internals.

### Measurement Boundaries

The controller uses one Linux monotonic clock. For every sample it records:

- `request_started`: immediately before sending the allowlisted control request;
- `mutation_accepted`: the node's public facade acceptance response as observed by the controller;
- every node's first exact observation; and
- `all_observed`: completion of the first concurrent read round in which all required views match.

The normative elapsed value is conservative:

```text
all_observed - request_started
```

It includes control request/response and polling overhead and starts no later than the product's
accepted-mutation interval. The controller polls all relevant node drivers concurrently every 20
milliseconds. A sequential poll is invalid.

Admission ends only when nodes `0..14` expose node `15`'s exact `NodeId -> public key` grant and node
`15` exposes all 15 prior exact bindings. Descriptor completion uses the exact signed revision/digest.
State completion uses the exact signed winner HLC/writer/tombstone/content digest. Public `None`, stale
versions, local-only acceptance, queued work, or digest-only anti-entropy agreement is insufficient.

A mutation rejected after readiness, facade/control error, wrong value, crash, timeout, topology/session
change, clock degradation, OOM/throttle/limit event, forced shutdown, or non-convergence is a failed
sample and release attempt even when no mutation-accepted timestamp exists.

### Sample Count and Statistics

The exact measured strata are:

| Stratum | Samples per run | Runs | Total |
| --- | ---: | ---: | ---: |
| Admission/public-key propagation | 1 | 5 | 5 |
| Signed descriptor convergence | 4 | 5 | 20 |
| 4 KiB put convergence | 16 | 5 | 80 |
| Tombstone convergence | 4 | 5 | 20 |
| **All** | **25** | **5** | **125** |

Every raw value, request-start/accept/end timestamp, and per-node observation offset is published. The
report gives count, minimum, median, p95, p99 where defined, and maximum for each stratum and all samples,
but every one of the 125 values must be at most ten seconds.

Samples within a run are sequential and correlated. The five recreations share one host class, image,
engine, device, and cache history. The evidence is a finite deterministic release demonstration and
makes no population reliability, confidence, independent-sample, or failure-rate claim.

### Exclusions and Attempt Lineage

The five run IDs are declared before image preflight. A host, provider, engine, image, storage, or
network precheck failure before the first measured admission aborts the entire attempt and emits a
failed/infrastructure attestation. It does not authorize replacing one run inside that attempt.

After `request_started` for the first measured sample, no result is excluded. Every rejection, crash,
timeout, wrong observation, resource event, harness assertion, cleanup issue that affects evidence, or
latency above ten seconds is retained as a product/harness failure. Failed samples and runs are never
replaced or averaged away.

An independently classified provider outage may start a new attempt lineage under ADR-0004. The prior
attempt, predecessor digest, classification, and all artifacts remain in the complete ledger. A product
failure cannot be reclassified as infrastructure to obtain another result.

### Attestation and Cleanup

The ADR-0004 attempt attestation additionally records:

- SLO profile/schema ID and all 125 predeclared sample IDs;
- OCI engine/build/runtime and image manifest/config/layer digests;
- source commit, Cargo.lock, SBOM, compiler, package, redb, TLS, and harness digests;
- normalized container configuration, security options, cgroups, host/kernel/CPU/microcode/memory;
- filesystem/device/mount/cache policy and per-node redb directory allocation;
- bridge/routes/MTU/qdisc state and every latency/throughput probe;
- topology edge sets, feature definitions, runtime/clock/SLO constants;
- warm-up/readiness/quiescence observations;
- all raw samples and per-node observation offsets; and
- resource baselines, peaks, quiescent values, shutdown, artifact capture, and cleanup status.

The harness has no external network after preflight. On every exit, it first captures bounded normalized
logs, public views, cgroup/network snapshots, and attempt manifests through ADR-0004's allowlisted
serializer. It never uploads raw redb/key volumes, environment, addresses, paths, payloads, or unscreened
logs.

It requests public graceful shutdown, waits at most 30 seconds, then force-kills remaining containers.
Forced shutdown after measurement starts fails the attempt. Cleanup removes only resources carrying the
exact attempt label and never runs global engine prune. Upload or cleanup failure remains in the attempt
ledger and cannot erase sample results.

## Required Verification

T-G00-05 is documentation-only. Later gates own executable evidence:

- G5: reusable public trust/descriptor/topology readiness assertions for the 15-node induced graph,
  node-15 reciprocal trust, exact final 32 sessions, signed descriptor revisions, and no hidden edges.
- G7: public HLC/state/quarantine readiness and exact winner/tombstone completion predicates.
- G10: production observability for public quiescence/resource baselines without private harness reads.
- G10: private publish-false harness crate, node/controller images, two-network isolation, negative
  shortcut tests, engine/resource/storage/network preflight, deterministic workload, and cleanup.
- G10: publication-ready candidate commit first; then one exact five-run/125-sample external ledger on
  that SHA; then complete-ledger validation, external eligibility token, guarded tag, and publish.
- G10: tests prove a failed sample, post-start exclusion, replacement run, missing raw value, wrong
  topology, private state access, controller data path, network shaping, or mismatched image/commit fails
  release eligibility.

## Rejected Alternatives

### Injected Network Faults in the Initial SLO

Rejected by explicit maintainer scope. Latency, loss, bandwidth, reorder, and partition remain required
functional/fault evidence but are not part of the initial ten-second release profile.

### Shared Hosted CI as the Release Oracle

Rejected because host scheduling, CPU, storage, and network class are uncontrolled. Shared CI may run a
trend profile but cannot attest release latency.

### Multi-Host Oracle

Deferred. It better represents deployments but adds network, clock, cost, and reproduction variables
outside the initial scope.

### One In-Process Sixteen-Node Test

Rejected for the release oracle because separate container processes and redb directories expose more
realistic runtime, socket, storage, and resource boundaries.

### Percentile-Only Pass or Outlier Exclusion

Rejected because the product requirement applies to every sample under the accepted profile. All 125
must pass.

### Private Test Hooks for Readiness or Replication

Rejected because they could make the measured system differ from the public product path. The helper is
an external public-API consumer and production observability is the only counter source.

## Consequences

- The initial ten-second claim is deliberately narrow: healthy same-host OCI bridge, no impairment.
- Release evidence is more operationally complex than an in-process benchmark.
- The conservative controller timer includes harness overhead and is stricter than acceptance-to-read.
- redb/storage and TLS costs are included; image build and container startup are excluded.
- Five recreations and 125 samples demonstrate the exact release candidate but do not estimate a broad
  deployment reliability distribution.
- Network, clock-fault, partition, overload, crash, and mixed-engine behavior keep separate gates.

## Residual Risks

- Different CPUs, kernels, engines, filesystems, SSDs, virtualization, or cache histories may produce
  different latency.
- Container bridge behavior does not represent cross-host networks.
- A host may satisfy prechecks but experience an unobserved transient during measurement; the raw sample
  still fails rather than being excluded.
- The control plane adds conservative overhead but is not production application traffic.
- Correlated samples can miss rare schedules and failures despite five cluster recreations.
- OCI engine support can drift after release; the attestation applies only to the recorded engine/image.

## References

- ADR-0001, Bind Node Identity and Admission to a TLS 1.3 Channel.
- ADR-0002, Negotiate Feature Labels and Provide Bounded Durable Delivery.
- ADR-0003, Reconcile Durable Transactions and Order Replicated State with HLC.
- ADR-0004, Fix the Toolchain Feature Policy and Evidence Budgets.

# Installed Continuity aggregate-capacity resource baseline

This checkpoint executes the existing maximum-payload capacity and original-owner
recovery workload against installed crate archives at source
`539845d573ac0af5fe104aabed2f96a86f9eac8b`. No product code, resource limit,
policy requirement, allocator selection or protocol/storage format is changed.
It advances installed resource evidence; it does not freeze a product budget.

## Source, installation and workload

The observer consumes nine SDK archives from producer `6084f3bf`, with report
SHA-256 `d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885`,
and the independently packaged candidate at `21e00e9c`, archive SHA-256
`1326dbd2ba1c93f950a5f582e11af1514a017f0275d643812b7072da90ba54a9`.
SDK workspace identity and every candidate member match current source. Cargo
resolves those ten product crates only from the outside-checkout installation;
its 174 external packages retain versions, registry origins and checksums from
the root/candidate lockfile union. Installed dependencies are excluded from
workspace membership. Complete source inventories are checked before and after
the build, with the same observer/binary checked around every runtime.

The observer reuses the measured workload from the historical
[persistent secret encoding correction](../20261017-secret-encoding/README.md).
Its fixture reference now selects the installed candidate's current public
`owned_connection.rs` fixture. Two fixed-size iterator expressions are updated
for current strict Clippy. The cryptographic and persistence implementations are
the original archives. The Release observer passes build and Clippy with warnings
denied, using Rust 1.98.1, optimization level 3, thin LTO, one codegen unit and
overflow checks. Its binary SHA-256 is
`73271b3a8fca2bcad2119b1dd248a61cecfcfd9c6cc457b1d211b0ffac1972c2`.

Each fresh process creates two enrolled owners, OneTimeBoth prekeys and a session
using real authenticated hybrid TLS. Policy and credential validity is one hour,
with a signed send budget of 1024; real clocks are used. Local-only and mandatory
signed-TCP Witness are separate explicit protection profiles. Neither profile
falls back to the other.

Every cohort retains 64 maximum-sized epoch-zero outboxes, confirms a real PQ
rekey, then retains 60 epoch-one outboxes. Plaintext is 16 KiB and associated data
is 1 KiB. The next operation reaches the existing 2 MiB aggregate image bound,
returns Capacity and closes the journal. Two original-owner reopens retain the
same absent next ID and capacity refusal. Authenticated consumption of one old
message frees space for that same ID. All 125 original ciphertext replays cross
real TLS and produce exactly 125 independently checked durable business effects.
The historical capacity reader accepts all four results without relaxing its
exact 124/60 boundary, original-ID, ciphertext-length or business-byte checks.

## Actual observations

The machine is **Apple M4 Max, 16 logical CPUs, 48 GiB RAM**, macOS **26.7.2**
(Darwin 25.6.0). This differs from the historical M1 Max/macOS 27 captures.
Other applications, thermal state and power settings are uncontrolled and
unchanged. No task build or broad test overlaps a measured process.

| Cohort | Peak whole-process RSS | Physical footprint 15 s after owner closure | Process wall time | User + system CPU time |
| --- | ---: | ---: | ---: | ---: |
| Local 1 | 156.55 MiB | 108.05 MiB | 44.87 s | 13.92 s |
| Witness 1 | 157.17 MiB | 61.70 MiB | 59.94 s | 23.68 s |
| Witness 2 | 159.81 MiB | 63.89 MiB | 60.13 s | 23.79 s |
| Local 2 | 154.67 MiB | 104.63 MiB | 44.07 s | 13.75 s |

Each wall-time total includes setup, capacity/refusal/recovery, delivery, shutdown,
observation overhead and 15 seconds of explicit post-close idle waits. These are
not throughput estimates. Memory includes both peers, the Witness when selected,
provider/database allocations and the observer. It is not per-client SDK memory.
VM-region sampling is non-atomic and includes shared mappings; tag totals cannot
be substituted for per-task physical footprint.

The sender database is **12,455,936 bytes (11.879 MiB)** at capacity in every
cohort. The logical 2 MiB encoded-image limit is neither a database-file nor a
process-memory budget. Lower post-close footprint in the Witness cases does not
establish that requiring a Witness reduces memory; these are different process
allocation histories with uncontrolled host conditions.

Each Witness cohort records **3,937 signed request/reply exchanges**, totaling
**28,901,517 framed bytes**. This includes setup, fill/status observations, rekey,
refusal/reopening, replay, delivery and acknowledgement. It excludes TCP overhead
and application TLS traffic. It must not be divided into a claimed ordinary-send
network budget without separating those phases. The reader verifies every
duration sum, the capacity observation's exact prefix and the 7,341-byte
bidirectional frame accounting.

The subsequent [phase-accounting reread](../20261105-resource-phase-accounting/README.md)
separates the retained capacity prefix from recovery/delivery, checks the
operation-tag census and reconciles both intervals with the original totals.
It adds no runtime measurement or ordinary-send budget claim.

Per-cohort observed nearest-rank p50/p95 **local durable commit** times are
70.08/91.21 ms and 68.94/90.66 ms for the local cases, and 99.80/122.72 ms and
103.55/126.80 ms for Witness. Each contains 125 ordered commits while the journal
fills; these samples are not stationary independent latency trials. The interval
excludes later application TLS delivery, slot/status observation and payload
construction. These are not production tail guarantees or a comparison with the
older complete-send timings.

## Method and qualification limits

The two opposite-order blocks were recorded as the schedule after the first local
observation. That first result remains included; no runtime or outlier was
discarded. This was not a preregistered statistical comparison.

A mid-collection environment observation found inherited **`MallocNanoZone=0`**.
The driver passes inherited allocator controls through and the task did not change
them. Earlier cohorts do not have separate per-process allocator-environment
receipts. The exact observation time and this limitation are retained in
`HOST_ALLOCATOR_ENVIRONMENT.json`. Do not call these runs an unconfigured/default
allocator experiment or infer a causal improvement over historical captures.

The remaining resource qualification must select and measure the declared
application workload, multi-session/account fanout and maintenance/revocation
paths, including applicable installed-platform and representative mobile resource
and energy evidence. These existing release requirements are not replaced by this
single-session capacity workload. No resource limits are reduced or accepted
solely because these four processes finish.

## Verification and retained failures

The independent readback checks **500 business files** and rejects **548** altered
sample, lifecycle, original-ID, VM-counter and Witness-accounting controls. It
retains raw Darwin CPU/RSS counters, all 20 memory stages per process, source and
tool identities, complete command receipts, and all synthetic public effects.

The first setup attempt failed before compilation because the diagnostic driver
serialized a `(registry, checksum)` tuple as a lockfile checksum. The second
attempt compiled but strict Clippy rejected two old `chunks_exact` expressions.
Its final metadata filename `BUILD.json` also collided with the `build.json`
command receipt on this case-insensitive filesystem. Both original failures and
the failed observer sources are retained. The third build uses a distinct report
name, fixes the two observer expressions, and passes both strict checks. No SDK
guard, timeout, assertion, dependency pin or warning level was weakened.

`CAPTURE.zip` contains **673 public members**, 15,083,553 uncompressed bytes.
Every member was reread against `SHA256.json`, and all four capacity/business/
resource results were revalidated directly from the archive. Its SHA-256 is
`60fb59b6d6b55a7f964cdbdc6ac3e28b5f185033fffce6c0be8b17c5aa19832e`.
Private keys, stores and installation state are excluded; original temporary
private cohorts remain preserved. This is not cross-host interoperability, device
qualification, a physical power-loss result, PCS proof, external security review
or formal release qualification.

At 13:11:21 UTC, the current-head CI set reports **263 successes, 60 queued,
seven failures and two skipped jobs**. PR #117's Apple Silicon root-winner job
`126445762591` has completed successfully. The older independent run at `adaaeb49`
now has two successes and two running jobs, and remains separate from the
current-head and genuinely installed-Rust qualification. No new wave, push,
rerun or cancellation was requested.

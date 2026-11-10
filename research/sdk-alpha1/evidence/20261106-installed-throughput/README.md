# Complete-interval installed workload throughput

Sixteen predeclared repeated cohorts now measure complete ordinary-workload
intervals at source `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`, including
surrounding status queries and independent PQ updates. The previous
[operation baseline](../20261106-resource-repeats/README.md) did not measure
that denominator. This supplies an observed serial throughput baseline for
these installed workloads; an acceptable product budget remains to be decided
and verified against the declared load.

## Workloads and measurement

The same ten installed SDK/candidate archives, endpoint helpers and workload
bodies are retained. Only the isolated observer changes: a shared monotonic
clock timestamps each operation and three complete phases (epoch zero, epoch
one, and the enclosing two-epoch workload). The original assertions, durable
effects, retained-outcome reads, retirement, exact retry after orderly reopening,
and pre-cancellation remain. [INSTRUMENTATION.json](INSTRUMENTATION.json) pins
the original and instrumented workload sources. Both new Release test targets
build and pass strict Clippy before actual execution.

Four functional pilots pass, then [PROTOCOL.json](PROTOCOL.json) fixes four
balanced orders before sixteen repeated cohorts run. Each case appears once in
each position and uses a fresh fixture. Pilots are retained separately and
excluded from the repeated statistics. No cohort fails or is replaced.

- Single-session cohorts use two installed owners, 48 ordinary confirmed
  deliveries across two epochs and one traffic-independent PQ update.
- Fanout cohorts use three installed owners and a peer account with two current
  signed-roster recipients. Twelve ordinary aggregates deliver 24 recipient
  copies. Each aggregate includes two retained-outcome reads, explicit retirement
  and a durable status check. Both sessions receive independent PQ updates.
- Each case runs locally and with the required signed-TCP Witness. All endpoints
  are in one process on this Mac, using real hybrid TLS and durable synthetic
  application effects. Account-login and registry workloads are outside these
  pre-provisioned fixtures.

Payload/associated-data lengths are 64/0, 1,024/32 and 16,384/1,024 bytes,
balanced within each epoch. A delivery counts a confirmed recipient copy;
fanout also reports retired aggregates separately. Plaintext goodput counts
delivered bytes per recipient and excludes associated data and wire overhead.

Complete phases include the original data preparation, status checks and
observation overhead. The enclosing phase includes inter-epoch PQ control and
epoch reporting. Its end follows the existing workload loop: single-session
includes the final epoch memory sample, while fanout ends before its subsequent
ordinary-batches memory sample. Setup, establishment and the later recovery and
cancellation scenarios execute successfully but lie outside this denominator.
Nested epoch and whole-workload intervals are never added together.

The host is Apple M4 Max, Mac16,5, 16 CPUs, 48 GiB RAM, macOS 26.7.2; the
observers use Rust 1.98.1 Release. The repeats run on 2026-11-06 from
04:58:36 to 05:07:29 UTC. `MallocNanoZone=0` is inherited. Boundary power reports
show AC power, and one-minute load averages range from 3.167 to 5.031. No other
qualification process appears in the captured boundary or runner censuses.
Desktop applications, caches and clock frequency remain uncontrolled. The
thermal report records no warning/status; it is not a temperature measurement.
No power, allocator or security setting is changed.

## Observed whole-workload rates

Each row pools four repetitions by dividing total completed counts by total
complete-phase time. It does not average inverses of individual operation
latencies. Values are rounded here; [PHASE_SUMMARY.json](PHASE_SUMMARY.json)
retains exact reduced rational rates, individual samples and all twelve
epoch/profile/workload groups.

| Serial installed workload | Deliveries/s | Delivered plaintext KiB/s | Retired aggregates/s |
| --- | ---: | ---: | ---: |
| Single-session local | 5.816 | 33.076 | — |
| Single-session required Witness | 3.312 | 18.836 | — |
| Two-recipient fanout local | 5.368 | 30.530 | 2.684 |
| Two-recipient fanout required Witness | 2.932 | 16.673 | 1.466 |

Across four repeats, the complete single-session intervals total 33.014862498 s
locally and 57.973164749 s with Witness. The fanout intervals total
17.883946418 s locally and 32.746588375 s with Witness. Adding only the measured
operation spans would omit 0.375257663, 0.969321744, 0.085151248 and
0.214427971 s respectively, overstating the corresponding observed rates by
1.150%, 1.700%, 0.478% and 0.659%. The new denominator retains those intervals.

Per-repeat delivery rates range from 5.760–5.954/s for local single-session,
3.282–3.349/s for Witness single-session, 5.236–5.490/s for local fanout and
2.893–2.955/s for Witness fanout. With only four separate repetitions per
case, no production tail, confidence bound or saturation capacity is inferred.
The existing per-operation latency baseline remains separate.

Each single-session Witness whole phase contains exactly 1,243 exchanges,
including 48 outside the operation spans; each fanout phase contains 914,
including 12 outside the spans. The full cohorts, including setup and recovery,
retain the original 1,410 and 1,203 exchanges. All sixteen full cohorts total
10,452. Phase CPU is whole-process CPU, including endpoints, Witness and
observer; it is not per-client CPU or energy.

## Validation and captured-source reproduction

The repeated campaign retains 1,560 operation spans, 48 nested phase intervals,
600 public business files and 400 new altered-observation rejection checks.
The four additional pilots bring the complete capsule to 1,950 spans,
60 intervals, 750 files and 500 checks.

The reader projects only the new timestamp/phase fields away to reuse the
original workload validators. It additionally verifies raw stream equality,
timeline order, exact phase bounds and nesting, delivery/byte/control/retirement
counts, CPU containment, Witness prefixes, and complete-time conservation.
Each cohort rejects 25 altered timing/accounting/raw-evidence inputs. These are
the new controls; the old observer-specific negative suites are not claimed as
rerun by this campaign.

[CAPTURE.zip](CAPTURE.zip) has 1,199 members and 17,351,456 bytes, SHA-256
`febe57f043c78f09a77ec36a2694cdb156b3e184e287ff62871712f54b1ebdde`.
It contains both actual binaries, instrumented observer sources, ten consumed
archives, build/Clippy logs, the protocol and controller sources, every pilot
and repeat, host observations, analysis and synthetic business bytes.
[FILES.json](FILES.json) pins every member. Private keys and runtime stores
are excluded.

[ARCHIVE_READBACK.json](ARCHIVE_READBACK.json) and
[STANDALONE_REPLAY.json](STANDALONE_REPLAY.json) describe one successful replay
from nine captured reader files. It revalidates all twenty cohorts, reexecutes
all 500 new controls, reproduces twelve repeated phase groups using the
captured analysis source, and separately checks exact rate cross-products.
This is source reproduction, not a second independently implemented statistics
algorithm. It accesses no private runtime and does not rerun native workloads.

Invoke [replay-capsule.py](replay-capsule.py) through the repository's isolated
`sh artifact/python-run.sh`, with absolute capsule/manifest paths and a fresh
work directory. Keep `CAPTURE.json` beside the capsule. The exact successful
captured-reader invocation is retained in [REPLAY_COMMAND.json](REPLAY_COMMAND.json).

Declared-load acceptance, revocation/replacement, maintenance and capacity,
representative mobile resources/energy and frozen budgets remain separate
work. These serial single-host observations do not establish a maximum load,
cross-host network performance or release qualification.
`performance_qualified=false` and `release_claim_eligible=false` remain explicit.

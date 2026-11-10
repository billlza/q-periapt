# Repeated installed lifecycle and fanout resource observations

Sixteen predeclared cohorts complete after the current host-JNI qualification
finishes, using the unchanged installed Release observers at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. All cohorts and slower samples are
retained: 1,560 measured spans, 600 durable synthetic business files and 432
altered-input rejection receipts. The public capsule reproduces all sixteen
original reader results and independently recomputes every operation and memory
summary.

This is a repeated baseline for the recorded host and workloads. It does not
freeze an acceptable product budget, establish production tails or qualify
mobile energy and the maximum supported capacity.

## Method and scope

[PROTOCOL.json](PROTOCOL.json) was written before execution. Four cases are run
sequentially: single-session local, single-session required Witness, two-recipient
peer-account fanout local, and the same fanout with required Witness. Four
balanced orders put each case in each position once. Each of the four repetitions
per case uses new private fixture directories and two or three device owners.
The previously qualified workloads remain unchanged:

- The [single-session observer](../20261105-installed-operation-observer/README.md)
  delivers 48 ordinary messages over two epochs, performs an independent PQ
  update, then tests a lost application result, exact retry after orderly owner
  reopening and pre-cancellation. Each cohort has 49 effects and 106 spans.
- The [fanout observer](../20261106-installed-fanout-observer/README.md) delivers
  twelve ordinary two-member aggregates over two epochs, updates both sessions
  independently, then recovers a thirteenth aggregate after one lost application
  result. Each cohort has 26 effects and 89 spans. The full target roster, original
  IDs, consumption results and explicit retirement are retained.

Both use actual extracted SDK/candidate archives, real hybrid-TLS endpoints,
durable application effects and, when selected, the required signed-TCP Witness.
Every installed package file and observer source/binary identity is checked by
the original runners before and after each cohort. Fresh application fixtures
are not production account-login or registry workloads.

The host is Apple M4 Max, Mac16,5, 16 CPUs, 48 GiB RAM, macOS 26.7.2. Rust 1.98.1
Release observers retain their original strict build and Clippy evidence.
`MallocNanoZone=0` is inherited; no allocator, power or security setting changes.
The run spans 2026-11-06 03:18:24–03:28:30 UTC, including the recorder interruption
described below. Recorded power reports show AC power. The thermal command
reports that no warning/status has been recorded; this is not a temperature
measurement or proof of an unthrottled CPU.

No other qualification process appears in the before/after process censuses or
the original runner's census. Desktop applications, filesystem caches and clock
frequency are not controlled. Boundary one-minute load averages range from
2.477 to 7.256. No high-load or slow sample is excluded. These controls and limits
support a scoped baseline, not a fully isolated performance experiment.

## Representative observed durations

Values below are milliseconds. The ordinary-message rows use epoch one,
1,024-byte plaintext and 32-byte associated data; the full payload/epoch matrix
and CPU samples are in [OPERATION_SUMMARY.json](OPERATION_SUMMARY.json).

| Observed operation | Samples | Local median / maximum | Witness median / maximum |
| --- | ---: | ---: | ---: |
| Single-session establishment | 4 per profile | 400.37 / 408.06 | 772.25 / 835.64 |
| Independent PQ update, single session | 4 per profile | 251.39 / 275.85 | 493.42 / 498.71 |
| Ordinary single-session delivery | 32 per profile | 157.24 / 173.54 | 272.87 / 287.48 |
| Original-message retry after reopen | 4 per profile | 60.36 / 65.00 | 118.77 / 123.42 |
| First fanout member delivery | 8 per profile | 163.72 / 177.88 | 298.84 / 325.33 |
| Second fanout member delivery | 8 per profile | 126.43 / 130.90 | 224.66 / 242.80 |
| Ordinary aggregate retirement | 48 per profile | 21.33 / 27.09 | 41.01 / 48.47 |

The representative ordinary single-session empirical p95 is 172.78 ms locally
and 285.34 ms with Witness. The calculation uses the nearest-rank sample
statistic, with all 32 observations retained. Observations within a cohort share
state and are not independent experimental replicas. No production p95/p99 or
confidence bound is inferred. Groups with fewer than twenty observations report
their median and maximum, without a p95 value.

An ordinary delivery includes this transport's actual connection and consumption
path and durable state/application work. Its inverse is not reported as bulk
throughput. The observer's surrounding status checks and setup are separately
identified; adding selected spans would not establish a complete sustained
pipeline's throughput. A dedicated throughput interval remains to be measured
for the eventual workload contract.

The epoch-one 1 KiB single-session span has median process user/system CPU of
26.29/6.88 ms locally and 89.92/12.28 ms with Witness. CPU counters include both
endpoints, the Witness where present, and observer work. They are not isolated
sender CPU or an energy measurement.

## Network, memory and storage observations

All four single-session Witness cohorts contain exactly 1,410 exchanges each;
all four fanout Witness cohorts contain exactly 1,203. The total is 10,452.
The original readers reconcile the exact operation-prefix accounting and retain
surrounding queries separately. Per-operation counts remain those of the two
observer checkpoints, including three Witness queries for a retained fanout
result even when its application exchange count is zero.

The largest resident-size and physical-footprint values among the five recorded
stages in all four repeats are:

| Whole process | Resident bytes | Physical-footprint bytes |
| --- | ---: | ---: |
| Single-session local | 15,368,192 | 9,404,800 |
| Single-session Witness | 16,990,208 | 10,944,896 |
| Fanout local | 15,663,104 | 9,781,608 |
| Fanout Witness | 17,973,248 | 11,993,448 |

These are maxima of sampled stages, not continuous process peaks or per-client
memory bounds. The observer retains its measurement records in the same process.
Raw `/usr/bin/time -l` output is preserved separately. Zero allocator counters
are not interpreted as zero peak allocation.

The single-session sender/receiver journal maxima over recorded stages are
393,216/405,504 bytes. The fanout sender and two recipient maxima are
851,968/462,848/462,848 bytes. [MEMORY_SUMMARY.json](MEMORY_SUMMARY.json) retains
every stage and repeat. These finite workloads do not establish long-term
retention, maintenance, worst-case image size or the full declared roster limit.

## Recorder failure and evidence validation

The first controller completed the first two native runs and their independent
readbacks, then tried to write its shared `PROGRESS.json` a second time.
The repository JSON writer uses exclusive creation and rejected that write.
The traceback, driver, one-step progress and two-cohort failure receipt are
retained. This was a recorder failure after successful native measurements.

The resumed controller verifies both existing cohorts' recorded hashes, preserves
them, and runs exactly the remaining fourteen cohorts in the original order.
Each subsequent step gets its own exclusively created progress file. No workload,
sample, assertion, timeout or order changes, and no successful cohort is rerun
to replace an observation. The interruption and resumed timestamp remain visible.

Each cohort first passes its original independent reader, including the altered
input controls: 20/22 for local/Witness single-session cohorts and 32/34 for
local/Witness fanout cohorts. Archive replay then revalidates all actual spans
and business files and verifies the integrity of all 432 original rejection receipts. It does not
claim to reexecute those negative controls in the archive pass.

The archive pass independently reconstructs 90 operation groups and 20 memory
groups. It compares every raw sample, median, minimum, maximum, eligible p95,
round count, Witness-count distribution and sampled memory/database maximum with
the analysis output. All results agree.

## Reproducible public capsule and remaining work

[CAPTURE.zip](CAPTURE.zip) contains 971 members, 16,969,130 bytes, SHA-256
`9aca437ce57943e146b50cbe71eb0085207851e6adf0637c905ce107f0045ecb`.
It retains both actual observer binaries and sources, the ten consumed archives,
all sixteen public cohorts, the protocol, controller failure/resume, host
observations, analysis, readers and 600 synthetic business files. Private keys
and runtime stores are excluded. [FILES.json](FILES.json) pins every member.

[ARCHIVE_READBACK.json](ARCHIVE_READBACK.json) and
[STANDALONE_REPLAY.json](STANDALONE_REPLAY.json) record the same single replay
using only seven captured reader files and the public capsule. No private runtime
is accessed and no native workload is rerun. The [replay driver](replay-capsule.py)
can be invoked through the repository's isolated `artifact/python-run.sh` with
absolute capsule/manifest paths and a fresh work directory; `CAPTURE.json` must
remain beside the capsule.

The prior cohorts that overlapped JNI retain their original qualification scope
and are not pooled into these repeats. The repeat baseline supplies better scoped
data for choosing acceptable budgets. Declared-load throughput, maintenance,
revocation/replacement, capacity and mobile resource/energy evidence still need
their existing acceptance work. No contract is narrowed, no budget is silently
frozen, and `performance_qualified=false` and `release_claim_eligible=false` are
preserved.

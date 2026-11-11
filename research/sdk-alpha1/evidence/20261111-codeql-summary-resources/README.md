# SummaryStats resource outcome and fixed join-plan candidate

## Completed allocation experiment

The two evaluator jobs in [run 42822797947](https://github.com/billlza/q-periapt/actions/runs/42822797947)
completed their five-hour allocations. Each produced **38 fresh BQRS files**;
their decoded semantics agree with all 38 retained results and with the other
arm. The full `queries/summary/SummaryStats.ql` remained in its Stage4 fixed
point when the process supervisor reached the 18,000-second boundary.

`API_READBACK.json` records the API observation at 2026-11-11 03:23 UTC. Both
evaluator jobs had failed and uploaded their evidence successfully. Aggregate
job `130217499454` was still queued. The unchanged default comparator was also
run locally against both original `RESULT.json` files; `LOCAL_COMPARISON.json`
retains its failed full-result admission. No completed 39-query result is
attributed to this run.

| Identity | heap-1536 | heap-2048 |
| --- | --- | --- |
| Job | `129852302609` | `129852303046` |
| Artifact | `13813588831` | `13813748616` |
| Artifact bytes | 25,584,177 | 25,627,939 |
| ZIP SHA-256 | `43768e3f4346d2ca169ae2f9bc23f631d56a14dd30e51927005b35a64b1cc05e` | `b5a7f3f90b7c40b5abf68e62d7007458a8692c3a9b358c33eb5f02d9559d5a2f` |
| Source commit | `748edb36681827c09fe327717b6478089e28548a` | same |
| Evaluator seconds | 18,001.061 | 18,000.022 |
| Fresh results | 38 of 39 | 38 of 39 |
| Missing query | full `SummaryStats.ql` | full `SummaryStats.ql` |

Both archives were downloaded in full and their byte counts and SHA-256 digests
matched the API records. The original JSON receipts and query stderr are retained
under the two arm directories. `SEMANTICS_RECHECK.json` independently recomputes
the fresh BQRS byte digests and the semantic digests of the fresh and retained
decoder outputs read from those archives. It records equality for the 38 queries
actually present. Tuple normalization preserves columns, values and multiplicity.

The starting identities agree exactly: CLI **2.27.2**, Rust queries **0.1.44**,
the authenticated 98,247,028-byte tool bundle, all 39 query sources and compiled
plans, the database inventory, its 1,437 retained evaluator-cache files, and the
38 retained result files. `INITIAL_READBACK.json` contains these matching pins.
The analyzed database remains bound to commit
`56f191f04a57806869b8a03078ee4d27ffe900ab`; it is not reinterpreted as a database
created from the later diagnostic commit.

## Where evaluation spent the budget

The resource sampler completed normally in both jobs. The evaluator continued
to use CPU, read storage and advance its fixed point until supervision stopped
it. The raw process samples are retained losslessly as
`heap-*/PROCESS_RESOURCES.jsonl.gz`, with the original raw-byte digests in
`SEMANTICS_RECHECK.json`.

| Measurement | heap-1536 | heap-2048 |
| --- | ---: | ---: |
| Process samples | 8,975 | 8,964 |
| Observed own-process CPU seconds | 28,195.90 | 35,038.11 |
| Mean CPU cores over sampled Java interval | 1.566 | 1.947 |
| Maximum sampled tree RSS, GiB | 13.315 | 12.224 |
| Java `read_bytes` increase, GiB | 692.217 | 551.377 |
| Java `write_bytes` increase, GiB | 152.249 | 147.218 |
| ARRAY eviction pauses | 66,033 | 69,236 |
| Maximum logged Stage4 iteration | 282 | 282 |
| Final ten-minute mean CPU cores | 0.995 | 2.288 |
| Final ten-minute Java reads, GiB | 21.425 | 35.043 |

`RESOURCE_WINDOWS.json` provides each hourly interval and its actual sample
endpoints. RSS is a non-atomic sampled process-tree sum; CPU uses each process's
own counters. Storage counters above belong to the single observed Java process,
not a sum of parent and child I/O. The one missing final Java I/O observation in
the 1536 arm is recorded explicitly in the raw sampler receipt.

`EVALUATOR_PHASES.json` matches timestamped predicate starts to their completed
delta records. The largest matched intervals are:

| Stage4 predicate | heap-1536 matched seconds | heap-2048 matched seconds |
| --- | ---: | ---: |
| `fwdFlowRead/11` | 10,292 | 10,160 |
| `fwdFlow0/7` | 4,049 | 3,669 |
| `fwdFlowThrough/7` | 1,304 | 1,376 |
| `fwdFlow1/7` | 657 | 685 |

These are sums of matched wall-clock intervals at the log's one-second
resolution, rather than exclusive CPU times. Unmatched start records are retained
as parsing observations; they do not all identify unfinished work. The last
predicate start in each original log does identify the remaining operation:
`fwdFlow0/7`, iteration 282, in the 1536 arm; `fwdFlowRead/11`, iteration 282,
in the 2048 arm. The largest completed `fwdFlowRead` delta has 158,521,862 and
143,463,351 rows respectively. The final twenty fixed-point rounds commonly take
several minutes each.

The logs also sum to 20,100.247 and 20,287.789 GiB of **logical VITAL array
evictions**. This counts repeated eviction of live arrays and is distinct from
the kernel storage-byte measurements above. The combination of growing large
relations, repeated live-array eviction and continuing storage traffic locates
the execution cost in the full summary's recursive joins and intermediate tables.
Increasing the native allocation within these two tested splits did not complete
that work. `EVALUATOR_EXCERPTS.txt` preserves selected original log lines with
their original line numbers; full evaluator-log byte identities remain in the
unmodified observation receipts and workflow archives.

`reproduce_evaluator_phases.py` regenerates the phase report from the two original
ZIPs after checking their independent byte-count and SHA-256 pins. Store them as
`13813588831.zip` and `13813748616.zip`, then pass their directory with `--archives`
and a new JSON output path with `--output`. The retained raw process samples and
hourly endpoints independently expose the CPU, RSS and I/O calculations.

## Source-preserving candidate plan

The next control targets the full summary's execution plan. It keeps the
original source and reuses the authenticated CLI to compile with dynamic join
ordering enabled by `--dynamic-join-order-mode=all`. The retained `plan-admission/`
records establish the following:

1. The exact CLI accepts `none`, `non-recursive`, and `all`. The two full-summary
   compilation keys are `46a58f9971dcf45e8c0bc8d65b761ea4` for `none` and
   `209f28c6b9e8d5465a3f8417573e42d6` for `all`.
2. An execute-flag change alone loaded the existing bundled QLX, with no
   compilation event. Explicit source compilation is necessary to obtain the
   candidate used here.
3. Two successful source compilations in different pack locations produced
   different binary output. The chosen compilation used an isolated environment,
   a supervised 180-second bound, a 3,072 MiB JVM/compilation budget and two
   compilation threads. It completed in 107.838 seconds.
4. One fixed capsule contains the resulting QLX and all 15 stage files named by
   its header. The 620,068-byte ZIP has SHA-256
   `ce21381b3bec721aab246b26b84c00834959871235e1e82354addca8a40dcef7`.
   Its effective full-summary QLX has SHA-256
   `bb7a4ea7ec0910b62f34efc0e9e25a3e23e7f57d3dadde9799069ed1e824875f`.
   The original full-summary source retains SHA-256
   `7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67`.
5. The candidate installer was exercised against a separate, freshly extracted
   authenticated bundle. All **39 original queries loaded their admitted QLX
   files**, with **zero implicit query compilations**, and completed on an empty
   Rust schema in 9.012 seconds. Post-execution hashes confirm all 39 source
   files, the other 38 original QLX files, and the fixed candidate closure.
   The decoded full-summary result agrees with the bundled plan on this fixture.

The empty-schema execution validates relocation, complete runtime dependencies,
the installer and precompiled-plan selection. The retained project database is
the separate workload on which the new plan's completion and performance will be
measured. The five-hour limit and all full-result admission rules remain in force.

Earlier local admission failures are retained as well: the CLI rejected a
threat-model flag supplied to `query compile`, and its documented no-TRAP import
form raised an internal exception. The successful compiler command omits that
unsupported compile option; an explicitly empty TRAP directory supplies the
empty-schema fixture. Those probe errors are distinct from the hosted evaluator
timeouts above.

## Verification and execution selection

`candidate-control-tests.log` records **131 passing tests** across the capsule,
allocation controller and resource sampler. They include missing or modified
stages, symlinked members/parents, capsule tampering, mode confusion, implicit
compilation, missing full-summary results, semantic mismatch, and a real
supervised evaluator timeout accompanied by a secondary missing-stage error.
The timeout remains the primary recorded failure.

The default control and manual dispatch still select `none`. A push on the
dedicated `diagnostic/codeql-summary-joins` branch selects the fixed `all` capsule;
its branch-specific concurrency group is independent of the older cache control.
Both original allocation arms receive the same capsule bytes. Each has a
same-allocation historical counterpart in run 42822797947, with the summary plan
as the common treatment change. Completion still requires 39 fresh results in
both arms, full cross-arm semantic equality and agreement with the original
38 results. Production CodeQL settings and SARIF publication are unchanged.

The local readback began from repository revision
`8bdb36698c9d955de8c71a41179d11d224f696e0`. The original hosted experiment is
identified separately above. `FILE_HASHES.json` inventories the retained audit
files. The [controller documentation](../../../../artifact/codeql-summary-control.md)
describes the fixed inputs, capsule admission and execution contract.

## Primary interfaces

- [CLI execute queries](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/execute-queries)
  documents precompiled execution, evaluator options and structured logs; exact
  version-specific advanced help is retained under `plan-admission/`.
- [Original full SummaryStats source](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/SummaryStats.ql)
  and [taint-reach configuration](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/TaintReach.qll)
  identify the unchanged full-summary computation.

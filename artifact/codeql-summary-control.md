# Retained SummaryStats allocation control

This diagnostic tests whether a larger native table cache completes the original
Rust security-extended suite within the existing five-hour evaluator budget.
It changes only the heap/off-heap split between two arms. Production CodeQL
configuration, query selection, extraction, macro coverage, and SARIF publication
remain governed by the existing workflow.

## Evidence motivating the control

[Run 42554273879](https://github.com/billlza/q-periapt/actions/runs/42554273879)
analyzed merge commit `56f191f04a57806869b8a03078ee4d27ffe900ab` from head
`3254c81066af26cd23a2881198010fb616ce6b7a`.
The native and macOS-origin/Linux-evaluator jobs completed 38 of the 39 original
queries and reached the controlled 18,000-second deadline while evaluating
`queries/summary/SummaryStats.ql`.
The WASM job completed all 39 in 17,279.678 seconds.
The query logs show repeated native cache evictions while the full summary
query's `TaintReach` fixed point was still growing. The macOS-origin evaluator
log contains 83,417 memory-pause events, including 83,414 eviction pauses;
the native log contains 84,508 eviction pauses. These counts establish sustained cache pressure. They do not measure
the performance gain of either proposed allocation.

The original effective query command requested a 3,362 MiB JVM heap and
9,329 MiB off-heap cache from a 14,000 MiB total budget. The control compares:

| Arm | JVM heap (MiB) | Off-heap (MiB) | Remaining budget (MiB) | Threads | Evaluator wall limit |
| --- | ---: | ---: | ---: | ---: | ---: |
| `heap-2048` | 2,048 | 10,643 | 1,309 | 4 | 18,000 seconds |
| `heap-1536` | 1,536 | 11,155 | 1,309 | 4 | 18,000 seconds |

Neither arm repeats the known failed allocation. These are experimental
allocations, not established production defaults. JVM `PrintFlagsFinal`
records its actual `MaxHeapSize`; the evaluator startup log records its
accepted off-heap argument. Completion admission checks both against the selected
arm. A short real-bundle JVM admission runs before the long query, so unsupported
flag passthrough or an unexpected heap report fails early. Raw logs,
pause/eviction counts, query completion counts, fixed-point
iterations, and wall time are retained for successes and controlled failures.

## Authenticated input

Both jobs independently restore the same macOS-origin database and its retained
evaluator cache. They execute on Linux, matching the failed analysis host.
The source archive retains its historical package identity; changes to the
current repository or release package do not reinterpret this database.

| Input | Exact identity |
| --- | --- |
| Source run | `42554273879` |
| Source job | `129050160100` |
| Diagnostic artifact | `13677417145`, 288,417,501 bytes |
| Artifact SHA-256 | `cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d` |
| Inner member | `qperiapt-codeql-macos/diagnostics/database.zip` |
| Inner ZIP | 269,008,328 bytes |
| Inner SHA-256 | `c8bdc47f5cbb0b6d83c0d60c63e8ff9f80ad63683c58cdf32311dd8bb6c9dbf1` |
| Database inventory SHA-256 | `aafbc13d377d69fa4428ffd705a08eb77cfe40f2d4fe3fae02995fe9f839d33d` |
| Cache inventory SHA-256 | `2e972c45962dc468698ac7db6cf3fcde6a17bb3b3bc954af06a9166eab3bdbe0` |
| Cache file count | 1,437 |
| Retained BQRS count | 38 |
| CLI / Rust query pack | `2.27.2` / `0.1.44` |
| Rust CLI bundle SHA-256 | `acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea` |

The script additionally pins the database metadata and retained-result inventory
digests, all 39 query-source hashes, and the full SummaryStats source hash.
It admits all 39 compiled-plan hashes against a fixed inventory digest
(`f5d87c717575c9243272e3b1c8abdc1f5f12d93a193ffd2d3b1ba10df6de43d9`)
and independently pins the launcher digest. These identities and the BQRS output
layout were verified against artifact `13650498839` from the successful arm of
[run 42537088671](https://github.com/billlza/q-periapt/actions/runs/42537088671),
which used the identical authenticated CLI bundle. That artifact's SHA-256 is
`1c97989285747932d47b8581f10c3977cc7bc5a06e71b5f6c1da0812648d60d9`.
Bundle extraction uses the
exact authenticated Rust CLI archive; the tool, database, and common-cache
directories are private and fresh. The evaluator receives an isolated home,
temporary directory, and environment without the artifact-download credential.

Archive consumers parse a private copy of the same regular-file bytes used to
calculate the admitted digest. Member names, types, counts, declared sizes,
metadata identity, free space, and extraction time have explicit bounds.
Every restored file's bytes, mode, and timestamp participate in the recorded
inventory. Both arm receipts must match the independent fixed input pins, in
addition to matching one another.

## Cache and result semantics

This is a **warm-cache control**. It preserves the authenticated database's
1,437 intermediate evaluator cache files without deleting or fabricating cache
metadata. The evaluator may reuse compatible intermediate relations. The
separate common cache, which holds pack and compilation caches, starts empty.

The 38 existing BQRS files are decoded before evaluation and retained as a
semantic reference. They are not copied to the fresh query-output directory.
As documented for [execute queries](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/execute-queries),
`--no-rerun` only skips a query if its BQRS already exists in the selected
output location. The new output location is empty at launch, so all 39 original
queries must produce new BQRS there, including both full and reduced summary
queries. No query is omitted, replaced, or accepted solely from an old result.

The comparison requires:

1. The independently pinned database, retained cache, source, CLI bundle, pack,
   query sources, and compiled plans to agree.
2. The same experiment commit and fixed command layout, with exactly the two
   memory arguments differing between the arms.
3. A zero exit status and complete new results for all 39 queries in each arm.
4. Semantic equality of all new query results across the arms.
5. Semantic equality of the original 38 results with their new results.

BQRS and decoded JSON are both retained. Decoding uses a private snapshot of the
same BQRS bytes whose digest is reported. Tuple order is normalized, while
columns, values, and tuple multiplicity remain part of the semantic digest.
Binary-container hashes may differ when decoded semantics agree.

## Interrupted evaluation evidence

[Run 42634713742](https://github.com/billlza/q-periapt/actions/runs/42634713742)
reached the existing 18,000-second evaluator deadline in both allocation arms.
Each log records 38 completed queries, with the full `SummaryStats.ql` remaining
in its taint-reach fixed point. The
[source-bound outcome](../research/sdk-alpha1/evidence/20261109-codeql-summary-control-outcome/README.md)
retains both original artifact identities, input checks, progress observations,
and the failed full-suite comparison.

That run exposed a diagnostic retention defect: fresh BQRS were written under
`results/`, while the always-run upload retained `evidence/`. Copying and decoding
fresh BQRS happened only after a successful evaluator return, so the interrupted
arms uploaded the 38 original reference results but no fresh result files.
Failure retention now covers the fresh output paths as well.

After the supervisor has stopped the evaluator, the controller copies available
results for the 39 pinned queries into `evidence/partial-fresh-bqrs/`. It takes
stable regular-file snapshots of all available results before starting decoders.
Snapshot admission rejects symlinks, changing files, and files above 64 MiB;
copied data also has a 512 MiB aggregate bound. The authenticated query paths
form the capture allowlist. Unrelated output files and the original database's
retained results are outside this capture.

Copying and partial decoding share one 120-second work budget, checked during
copying and before each decode. A decoder receives the remaining whole seconds;
the process supervisor retains its bounded shutdown procedure. Budget exhaustion
leaves already captured BQRS in place, with undecoded entries marked
`not_attempted`. Successful decodes use the same semantic normalization as the
complete-result path, and record equality or mismatch against each available
original reference result. Decoder errors retain the raw BQRS and bounded
stdout/stderr. Ambiguous evaluator cleanup skips capture; ambiguous decoder
cleanup stops further decoding.

`PARTIAL_RESULTS.json` and the `partial_results` field in `RESULT.json` record
captured, missing, rejected, decoded, and unattempted queries separately. Their
`analysis_completed` flag stays false even if every expected BQRS was copied.
The original evaluator failure remains the primary failure if capture or decoding
also fails. These partial records support diagnosis; the existing comparison
continues to require a successful evaluation and complete fresh results for all
39 queries in each arm. The prior run's fresh files were outside its uploaded
artifact; this repair supplies that evidence on subsequent runs.

An incomplete arm or missing artifact leaves a failed aggregate comparison.
No SARIF is uploaded and no release qualification is asserted by this workflow.
A successful pair establishes complete, equivalent results for this retained
database under the two tested warm-cache allocations. Selection of a production
default still requires the current source's full CI analysis from its normal
database-creation path.

## Independent process resource samples

The allocation receipts above record requested and accepted JVM/off-heap budgets.
The interrupted two-arm run did not sample resident memory. The controller now
records Linux `/proc` observations during the evaluator invocation, so a subsequent
run can relate actual process counters to the retained fixed-point and eviction
logs. The sampler runs identically in both arms and leaves the query command,
query-source and compiled-plan pins, five-hour deadline, and full-suite comparator
unchanged.

`PROCESS_RESOURCES.jsonl` records each observed process's PID and start-time
identity, parent, original query root, approximate RSS, own user/system CPU ticks,
and available raw storage I/O counters. The controller and its pre-existing child
subtrees are excluded. Once a descendant has been observed, its same identity
remains in scope after reparenting; a reused PID does not inherit its membership.
The JSON summary records maxima separately for the direct query roots and the
observed tree, together with sample counts, missing observations, elapsed sampling
time, sampler CPU time, and shutdown status. A run with no observed evaluator
process retains null RSS maxima.

The default interval is two seconds. Each census admits at most 8,192 process
entries, each selected tree at most 512 live processes, and a run at most 4,096
observed identities, 10,000 samples, and 32 MiB of sample output. Reads are bounded
to 16 KiB per proc file. Census and selected-process work check a 0.75-second
deadline between reads; shutdown waits at most two seconds. Reaching a bound,
unsupported platforms, unavailable procfs, read/write failures, and incomplete
shutdown are explicit diagnostic outcomes. An evaluator success, nonzero exit,
or supervised timeout retains its original outcome if sampling also fails.

These counters have precise interpretation. RSS from `stat` is approximate;
summing it across processes can count shared pages multiple times. A maximum of
non-atomic samples is a **sampled tree RSS maximum**, not the actual job memory
high-water mark or proportional set size. Brief processes and between-sample
peaks may be missed. CPU totals use only each identity's own user/system ticks,
avoiding the separate waited-child CPU fields. I/O remains per process because
those counters may incorporate waited-for children; the controller does not sum
them into a claimed tree I/O total. The measurements are diagnostic evidence and
do not satisfy the independent requirement for 39 complete fresh query results.

The regression tests launch real allocating parent/child processes, exclude a
real background child, exercise a real one-second supervised timeout, and check
PID reuse, reparenting, missing procfs, sample-count and byte bounds, exclusive
outputs, and secondary diagnostic failures. They validate the measurement path;
they do not provide new CodeQL workload performance results.

## Execution

The workflow `.github/workflows/codeql-summary-control.yml` runs on a push to
`diagnostic/codeql-summary-cache` that changes one of its five implementation
files. It also has a manual dispatch entry point. Opening its PR does not trigger
a second copy of the five-hour matrix. Each evaluator job has a six-hour hard
limit, a five-hour supervised evaluator limit, and an always-run evidence upload.
The aggregate job always attempts to compare the two receipts.

Local admission and failure-path checks:

```sh
sh artifact/python-run.sh -m unittest -v test_codeql_summary_control test_codeql_process_resources
```

These tests exercise source binding, safe restoration, old-versus-fresh result
admission, semantic equivalence, actual-allocation observation, process failure,
partial-result retention, and pair comparison. Partial-result fixtures contain
explicit synthetic BQRS bytes; the timeout regressions use real supervised child
processes. The tests do not execute the hosted Rust queries.

## Primary technical references

- [CodeQL CLI resolve ram](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/resolve-ram)
  explains separate JVM/off-heap allocation and database-dependent overhead.
- [CodeQL CLI execute queries](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/execute-queries)
  specifies output-location reuse, intermediate caches, threads, and evaluator
  options. Its per-layer `--timeout` is not a total runtime limit; this control
  retains the repository's process supervisor for the five-hour wall limit.
- [Pinned full SummaryStats](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/SummaryStats.ql)
  retains full statistics, including the global taint-reach computation. The
  reduced query is a distinct member of the suite, not a replacement.
- [Linux kernel procfs documentation](https://docs.kernel.org/filesystems/proc.html)
  defines process counters, asynchronous RSS accounting, and the RSS/PSS distinction.
- [Linux man-pages: proc_pid_io](https://man7.org/linux/man-pages/man5/proc_pid_io.5.html)
  specifies the inclusion of waited-for children in per-process I/O accounting.


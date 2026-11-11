# Fixed SummaryStats join-plan outcome

The two allocation arms in [run 42956070561](https://github.com/billlza/q-periapt/actions/runs/42956070561)
each produced **38 fresh query results with matching decoded semantics** before
the scheduled five-hour evaluator boundary stopped the full SummaryStats
computation. Independent readback confirmed those 38 results against the
retained references, the other arm, and the corresponding fresh results from
run 42822797947. The fixed source-preserving `all` plan was loaded in both arms
and retained its exact identity through evaluation.

The resource readback locates the remaining cost in the Stage4 `fwdFlowRead`
and `fwdFlow0` relations. It also records a substantial local reduction in
matched `fwdFlow1` intervals. The complete workload did not finish within the
existing budget. [COMPARISON.md](performance/COMPARISON.md) explains the
observed phase changes, host differences, and the next specific algebraic
optimization candidate identified from the pinned upstream implementation.

## Original execution and archive identities

The experiment commit is `e54c9d12223a72973b956acb15ff7b1597140e4f`.
The two original workflow ZIPs were downloaded in full and matched their API
byte counts and SHA-256 digests. They are separately retained inputs to this
packet. This directory contains their public artifact identities and the
selected original receipts.

| Observation | heap-1536 | heap-2048 |
| --- | --- | --- |
| Job | 130311363269 | 130311363427 |
| Artifact | 13844887141 | 13844956987 |
| ZIP bytes | 32,594,384 | 33,632,338 |
| ZIP SHA-256 | `e9122b21b1a80b9768936843eb43aec6054113777ff6f3a1170de6be00e46326` | `b47d98097c9869861305ff452a1cbee39c7c092d2f0944b39c7f42f7b470a035` |
| Evaluator seconds | 18,001.191254521 | 18,001.126614768 |
| Original stop reason | supervised timeout | supervised timeout |
| Cleanup ambiguity | false | false |
| Fresh results captured and decoded | 38 / 38 | 38 / 38 |
| Post-stop capture and decode seconds | 21.334773385 | 15.012762937 |
| Actual admitted QLX loads | 39 | 39 |
| Implicit query compilations | 0 | 0 |

The only missing result is `queries/summary/SummaryStats.ql`. Both capture
paths completed within their existing 120-second budget, with no capture
errors. `RESULT.json` preserves the `evaluate`-phase failure; `query.json`
identifies its cause as `stopped: timeout`. Both upload steps succeeded.

The evaluator logs start at 04:47:01 for heap-1536 and 04:46:47 for heap-2048.
The common workflow step began at 04:46:22 and includes preparation, admission,
JVM probing, and reference-result decoding before evaluator supervision starts.

## Source, plan, and result verification

Both pre-execution and post-execution plan receipts match the pinned capsule
SHA-256 `ce21381b3bec721aab246b26b84c00834959871235e1e82354addca8a40dcef7`.
The capsule contains one full-summary QLX and its 15 stage files. The effective
QLX SHA-256 is `bb7a4ea7ec0910b62f34efc0e9e25a3e23e7f57d3dadde9799069ed1e824875f`.

The readback checked each complete command, accepted heap/native allocation,
and exact 39-query precompiled-load census. The database, CLI, query sources,
retained references, 1,437-file starting cache, and same-arm allocation settings
agree with the historical control. Only the full SummaryStats compiled plan
changed; the other 38 QLX identities remain unchanged. The analyzed database
remains bound to source commit `56f191f04a57806869b8a03078ee4d27ffe900ab`,
CLI 2.27.2, and query pack 0.1.44.

`SEMANTICS_RECHECK.json` records independent BQRS byte hashes, original decoder
output hashes, and recomputed semantic hashes for every available query. Tuple
normalization preserves columns, values, and multiplicity. All original
decoder receipts have exit status zero. The archived fresh BQRS census is
exactly the expected 38 queries. The full evaluator logs were also streamed
and rehashed against their original observation receipts:

| Arm | Log bytes | Log SHA-256 |
| --- | ---: | --- |
| heap-1536 | 507,592,233 | `7b18aba40cfea6d3aba23a646ee3a96dee4f0f2993cf1a121bc2bf637a5a1d40` |
| heap-2048 | 513,705,470 | `9d26441b1ed50a32b55576b78e7a1834834e486557ed2f27b088f40a4d3caea7` |

## Local comparison and hosted status

The exact experiment-source comparator was run locally against the original
two `RESULT.json` files. It returned exit status **1** and the recorded failure
`fresh 39-query result census differs`. `LOCAL_COMPARISON.json` and
`local-comparison.log` retain that complete-suite admission result. The
independent byte/semantic readback returned exit status **0**; its actual
output is `recheck_outcome.log`.

At **2026-11-11 10:03:28 UTC**, hosted comparison job `130447340947` was still
queued. `API_READBACK.json` preserves that observation. The local result is
identified separately from this pending hosted job.

## Packet and method identities

`MANIFEST.json` lists every included file's relative path, byte count and
SHA-256. It also inventories the eight exact source files inside
`source-snapshot.zip`, with their original repository paths, Git blob identities
and experiment commit. This archive freezes the analysis-method version; it
can be extracted into a separate reproduction directory to restore `source/`.
The historical method files are unchanged.

The 20 selected workflow receipts retain their original bytes. So do the
independent semantic results, command logs, resource summaries, phase records,
tail excerpts, and the two calculation scripts. Editorial changes are confined
to the Markdown narrative and two descriptive strings in `COMPARISON.json`;
the manifest records their original identity and the changed string fields.
Numerical observations and result data are unchanged.

`BASELINE_REFERENCES.json` gives immutable commit links, byte counts and hashes
for the historical evidence already retained in the repository. The larger
matched-delta lists can be regenerated from the original workflow archives.

## Reproduction

Obtain the two original artifact ZIPs using the public artifact IDs above and
store them as `13844887141.zip` and `13844956987.zip` in one directory. The
launcher verifies their complete byte identities before any calculation and
writes into a new output directory.

```sh
python reproduce_analysis.py semantics \
  --archives /path/to/original-archives \
  --output /path/to/new-semantic-readback \
  --repository /path/to/q-periapt

python reproduce_analysis.py resources \
  --archives /path/to/original-archives \
  --output /path/to/new-resource-readback
```

The semantic mode restores the eight frozen method files, runs the existing
byte/semantic readback, then invokes the original full-suite comparator. Its
comparator result is expected to report the missing 39th result. The resource
mode uses the original calculation script with only its two input/output path
assignments relocated in a temporary copy. It regenerates phase, resource,
tail, and matched-delta files. Neither mode starts a CodeQL query evaluation.

The launcher is a packaging aid added after the recorded readback; the actual
commands used for that readback remain in `LOCAL_EXECUTION.json`. The packet
includes their original outputs rather than attributing a new execution to
the portable launcher.

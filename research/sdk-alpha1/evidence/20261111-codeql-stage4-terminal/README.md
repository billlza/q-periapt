# Stage4-only retained-database terminal readback

The Stage4-only projection experiment reached its 18,000-second evaluation deadline in both allocation arms. Both completed the same 38 queries and preserved their retained-result semantics; `queries/summary/SummaryStats.ql` remained unfinished. This is an actual long-tail result for the Stage4-only experiment on the retained macOS-origin database.

## Terminal result

[Run 43009319450](https://github.com/billlza/q-periapt/actions/runs/43009319450) used source `4fb3b2db1d6647ec4fa85fb8bd744b1d97ef1215`, CodeQL 2.27.2, Rust queries 0.1.44, and the frozen 39-query suite. The patch enabled the recursive-read target projection in `Stage4Param`. The control mode was `projection`, with dynamic join order `all`.

| Recorded field | Heap 2048 MiB | Heap 1536 MiB |
| --- | ---: | ---: |
| Job | 130484629159 | 130484629706 |
| Observed JVM max heap, bytes | 2,147,483,648 | 1,610,612,736 |
| Observed off-heap allocation, MB | 10,643 | 11,155 |
| Evaluation seconds | 18,000.102768548 | 18,000.029451174 |
| Recorded stop reason | timeout | timeout |
| Query starts / precompiled loads / compilations | 39 / 39 / 0 | 39 / 39 / 0 |
| Distinct completed queries | 38 | 38 |
| Fresh results with retained semantics | 38 | 38 |
| Last completion in query stderr | 11m02s | 13m24s |
| Eviction pauses | 46,585 | 54,051 |
| Maximum sampled process-tree RSS, bytes | 14,545,317,888 | 14,939,774,976 |
| Resource samples | 8,975 | 8,954 |

Each arm had one evaluator invocation. The wrapper retained the deadline failure, captured and decoded all 38 available fresh results, and recorded an unambiguous process cleanup. Its partial-result capture stayed within its separate 120-second budget. The comparison job then failed the required 39-result census. These records distinguish the evaluation timeout from the downstream admission decision.

`heap-*/RESULT.json` and `PARTIAL_RESULTS.json` are original artifact members. `query.stderr` contains every completion line. `SUMMARY_CONTROL_COMPARISON.json` is the original comparison result. The three complete job logs and the API job/step snapshots retain the surrounding execution and terminal status.

## Independent result and resource verification

`READBACK_VERIFICATION.json` records an actual read of both original evidence ZIPs. Their bytes and SHA-256 digests match GitHub's artifact metadata in `ARTIFACTS.json`. Each ZIP has 334 members; complete member names, sizes and CRC values are retained in `heap-*/ZIP_MEMBERS.json`.

For each arm, the verification read the exact 38 fresh BQRS files and 38 retained BQRS files, checked their hashes against the original receipts, and checked the fresh BQRS sizes against the partial-result receipts. It also read the corresponding original decoded JSON and recomputed the existing semantic normalizer's canonical hash. All 38 fresh/retained semantic pairs matched, and the two arms' fresh semantic maps matched each other. None of the 38 fresh BQRS binaries equalled its retained binary; the established equality is the recorded decoded-result semantics. The report includes each query identity, BQRS and decoded-output hash, byte size, canonical semantic hash, and table row counts.

The verification reused the existing pure semantic normalizer after matching its relevant function ASTs, including the strict JSON parser, to the experiment's pinned Git source. It performed archive, hash and JSON reads. It did not execute CodeQL, a JVM, extraction, queries, or another BQRS decode.

The complete resource JSONL streams were read to verify their hashes, byte counts, sample counts, nonempty-process counts, and recorded RSS maxima against the original resource summaries. `RESOURCE_SELECTED_SAMPLES.jsonl` retains the original first, first maximum-tree-RSS, and last rows. The full streams remain in the original ZIPs. RSS values describe the maximum recorded process-tree sample; sampling can miss between-sample peaks and shared pages can be counted more than once. `PROCESS_RESOURCES.json` preserves the measurement interpretation and sampler overhead.

## Separate Stage3 and Stage4 experiment

[Run 43016694869](https://github.com/billlza/q-periapt/actions/runs/43016694869) uses source `128c8392690b59a98e35c17f67e704cc79cea18e`. Its patch enables the projection in both `Stage3Param` and `Stage4Param`, with a different frozen capsule and compiled inventory. The query source, 39-query manifest, CLI and query-pack versions remain the same. `SOURCE_MODES.json` and the exact source files under `source/` bind these modes and inputs.

At the separate **2026-11-11 16:37:06 UTC** readback, this successor was `in_progress`, its conclusion was null, and its artifact list was empty. The 2048 and 1536 MiB evaluation steps had started at 16:23:49 and 16:23:51 UTC respectively. This packet reports the terminal outcome only for the preceding Stage4-only source; the successor's snapshot remains a running observation.

## Artifact custody and replay

The two downloaded evidence ZIPs are 31,837,325 and 32,645,123 bytes. This compact packet retains selected original members, complete member censuses, independently computed verification, source-mode files, and the 352-byte comparison ZIP. The large evidence ZIPs and the underlying 288,417,501-byte database archive are excluded from this packet; the database archive was not downloaded for this readback. `ARTIFACTS.json` retains artifact IDs, repository API URLs, digests, sizes and expiry metadata. Original GitHub job logs preserve their BOM and terminal escape sequences.

To repeat the archive checks while the original artifacts are available, place them at `<artifacts>/heap-2048/evidence.zip` and `<artifacts>/heap-1536/evidence.zip`, and use a repository checkout containing the pinned experiment commit and matching semantic-normalizer functions:

```sh
python3 VERIFY_ARCHIVES.py \
  --artifact-root <artifacts> \
  --source-root <q-periapt-checkout> \
  --output <verification-output>
```

`VERIFICATION_EXECUTION.json` identifies the completed local readback and its scope. `MANIFEST.json` binds every other packet file by byte size, SHA-256 and Git blob identity. Evidence publication is separate from production source and does not start a workflow.

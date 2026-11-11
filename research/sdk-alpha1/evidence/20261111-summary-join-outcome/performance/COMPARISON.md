# Fixed full-summary plan: resource and stage readback

Both new arms timed out after approximately 18,001 seconds with 38 of 39 fresh queries; the full SummaryStats computation remains incomplete. The fixed `all` capsule ran with unchanged query sources. Matched predicate intervals changed, while the full computation remained active at the five-hour boundary.

## Comparable inputs and actual hosts

This independent readback confirms exact equality with the corresponding historical allocation for configuration, input identity, tool identity, all 39 query-source hashes and analyzed source. The evaluator command differs only in the intended `--dynamic-join-order-mode` value. Full capsule and output semantics are checked in the [independent result and plan readback](../SEMANTICS_RECHECK.json).

| Allocation | Run / plan | CPU model | Logical CPUs | MemTotal kB |
|---|---|---|---:|---:|
| heap-1536 | 42822797947 / none | AMD EPYC 9V74 80-Core Processor | 4 | 16367524 |
| heap-1536 | 42956070561 / all | AMD EPYC 7763 64-Core Processor | 4 | 16367520 |
| heap-2048 | 42822797947 / none | AMD EPYC 9V74 80-Core Processor | 4 | 16367524 |
| heap-2048 | 42956070561 / all | AMD EPYC 9V45 96-Core Processor | 4 | 16367524 |

The kernel is 7.0.0-1017-azure for all four observations. Each reports 2 cores / 4 siblings and 3,145,724 kB swap, initially free. The new heap-1536 host reports 512 kB CPU cache versus 1,024 kB for the other three. These are distinct hosted machines: milestone timings are observations, not an isolated plan-effect estimate.

## Resource observations

| Allocation / plan | Sampled tree peak GiB | Mean Java cores | Java read GiB | Java write GiB | ARRAY eviction pauses | Last Stage4 iteration |
|---|---:|---:|---:|---:|---:|---:|
| heap-1536 / none | 13.315 | 1.566 | 692.217 | 152.249 | 66,033 | 282 |
| heap-1536 / all | 13.754 | 2.289 | 689.983 | 173.468 | 66,582 | 281 |
| heap-2048 / none | 12.224 | 1.947 | 551.377 | 147.218 | 69,236 | 282 |
| heap-2048 / all | 14.102 | 2.001 | 1,119.889 | 224.958 | 92,464 | 288 |

RSS is a sampled non-atomic tree sum. CPU uses own-process ticks; I/O belongs to the single observed Java process. The new samplers stopped normally; each has one missing final I/O observation, which is excluded from I/O differences. Logical VITAL evictions remain separate from these physical-byte counters.

## Matched hot predicates

| Stage4 predicate | Old heap-1536 (s) | New heap-1536 (s) | Old heap-2048 (s) | New heap-2048 (s) |
|---|---:|---:|---:|---:|
| fwdFlowRead | 10292 | 8514 | 10160 | 8950 |
| fwdFlow0 | 4049 | 4194 | 3669 | 4364 |
| fwdFlowThrough | 1304 | 1029 | 1376 | 1008 |
| fwdFlow1 | 657 | 75 | 685 | 61 |

These sums match starts to delta completions at one-second resolution and are not exclusive CPU times. The first two predicates account for 12,708 s (new heap-1536) and 13,314 s (new heap-2048) of matched intervals; their largest new read deltas contain 143,463,320 and 181,684,098 rows. The local `fwdFlow1` interval reduction is visible in both arms, with the same predicate hash and near-equal maximum delta size; available baseline summaries do not retain its full per-iteration delta list.

The new heap-2048 arm reaches iteration 280 at 12,729 s, compared with 16,611 s historically. The new heap-1536 arm reaches it at 17,182 s, compared with 15,992 s historically. CPU models differ, and delta schedules may differ: these measurements support locating the cost, not a blanket speedup ratio.

Stage4 begins at 2,031 s versus 1,029 s in heap-1536, and 1,481 s versus 1,373 s in heap-2048. Measured from that stage start, iteration 280 takes 15,151 s versus 14,963 s in heap-1536, and 11,248 s versus 15,238 s in heap-2048. Most of the heap-1536 whole-run milestone delay is therefore already present before Stage4; its later matched milestone is 188 s behind. The exact 1,437-file initial cache inventory does not by itself establish equal runtime cache hits when compiled stage bytes change. This readback neither attributes that difference to cache misses nor assumes reuse was identical.

At the boundary, new heap-1536 has an unfinished `fwdFlowRead` iteration 281. The new heap-2048 arm has completed the last recorded iteration 288 helper deltas; the log does not identify an unfinished last helper. The full summary still has no output in either arm.

## Smallest targeted next candidate

The pinned upstream implementation constructs `fwdFlowRead` by joining `fwdFlowRead0` with `fwdFlowConsCand` on the access-path/content keys, applies the original type/stored constraints, and exposes the target-state projection to the read branch of `fwdFlow0`. Inspect this pair in the actual compiled IR first. A dedicated full-summary plan can push the key semijoin before wide expansion and materialize the target-state projection where only existential source/content witnesses are required; preserve the full relation for other consumers.

The algebraic basis is `A ⋈ B = A ⋈ (B ⋉ π_(ap1,c)(A))`, followed by the same complete constraints and target projection. This retains all original cases. It is a specific equivalence-preserving optimization candidate, not a measured implementation improvement. Its performance depends on whether the compiled full summary still demands the wide relation elsewhere. Use existing source/capsule/semantic admission for the next implementation; no new execution, source change, query reduction or deadline adjustment was performed here.

Primary source: [pinned generic DataFlow implementation](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/shared/dataflow/codeql/dataflow/internal/DataFlowImpl.qll), especially `fwdFlowRead0`, `fwdFlowRead`, and the read branch in `fwdFlow0`; [pinned taint reach](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/TaintReach.qll); [full SummaryStats](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/SummaryStats.ql).

## Reproduction and scope

`analyze_new.py` streams the two unmodified artifacts and checks the raw evaluator-log SHA-256 against their receipts. It writes resource windows, phase records, exact last excerpts and all matched deltas. `COMPARISON.json` retains host fields, exact matching milestones, selected delta rows, comparison limits and input hashes. The small new phase/resource/excerpt files suffice for the review; the larger matched-delta files are reproducible diagnostics. No tests, benchmarks, source edits, remote actions or CI reruns were executed.

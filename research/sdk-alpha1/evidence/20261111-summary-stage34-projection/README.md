# Stage3 and Stage4 read-target projection

The candidate extends the existing Stage4 target-projection mechanism to
Stage3. It compiled successfully with the fixed official CodeQL tool, produced
the intended recursive structure in both stages, and completed one new execution
of the existing nonempty Rust fixture. Its complete 29-row `SummaryStats` result
equals both retained results from the original `all` plan and Stage4 candidate.

The change addresses the measured Stage3 read-relation work in the retained
project probe. `STAGE3_FEASIBILITY_READBACK.json` preserves the prior source and
RA inspection: the forward recursive consumer uses only the six target columns,
while the complete read relation also serves a later nonrecursive consumer.
The new source enables the projection for Stage3 and keeps those later consumers
intact. The original Stage4 pack and existing workflow assets were not modified.

## Mechanism and identity

The candidate's only vendor-file change is the actually resolved embedded
`codeql/dataflow@2.1.15` `DataFlowImpl.qll`. Relative to the prior Stage4 candidate,
it adds the `Stage3Param` override and updates the helper's explanatory comment.
The generic default remains false. `SOURCE_EQUIVALENCE.json` records direct
equality of the original full read body, `readStepFwd` and PathGraph read
consumer. The helper retains the same join and guards and existentially
quantifies the five discarded source/content columns.

`EQUIVALENCE.md` gives the fixed-point projection argument for Stage3 and its
composition with Stage4. The new RA confirms the resulting placement:

| Stage | Recursive target relation | Complete read relation | Later consumer |
| --- | --- | --- | --- |
| 3 | Target6 in forward layer | Read11 in subsequent nonrecursive layer | `readStepFwd` still reads Read11 |
| 4 | Target6 in forward layer | Read11 in subsequent nonrecursive layer | `readStepFwd` still reads Read11 |

`IR_COMPARISON.json` enumerates every full-read reference and the exact layer
boundaries. The complete RA is retained losslessly in `logs/`.

| Identity | Value |
| --- | --- |
| Official CLI | Rust CodeQL 2.27.2 |
| Official bundle SHA-256 | `acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea` |
| Full query source SHA-256 | `7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67` |
| Effective vendor source SHA-256 | `6a444d1baf03a1db4cbf1f98e39320ba3a7d68d2b9b6db7feffb2bf9cd315bde` |
| Compiler input key | `6a7530eb694360655ab8331a895c9fcd` |
| Capsule bytes | 620,230 |
| Capsule SHA-256 | `5b17fb41cd3c59fea564ec4e9cb49ef586c0ad06ccc3f2445e46b7b5ca8430cb` |

The capsule contains the full QLX and all 15 referenced stages. The original
39 selected root query sources and other 38 QLX files are unchanged. Only the
declared vendor source changes among the 1,175 embedded dependencies. After
evaluation, the complete 1,357-file effective query pack matches the original
1,342 files plus the exact declared source and capsule changes, including local
query support sources.

## Completed nonempty fixture execution

The accepted original database from the
[environment-source fixture comparison](../20261111-summary-projection-fixture/README.md)
was copied into a new directory. All 6,651 initial files match that experiment's
initial input inventory. The new arm used a fresh common cache and result
directory, one thread, a 1,536 MiB heap, 512 MiB native evaluator memory and the
same 300-second supervisor bound. The original `all` and Stage4 baselines were
read back without rerunning them.

The new process returned zero in 100.001 seconds. It loaded one fixed QLX and
performed zero implicit compilations. All 29 decoded rows, column descriptors,
values, order and multiplicity match both baselines. The results contain 15
active sources, 106 tainted nodes, 3,153 non-summary dataflow nodes, 34,775
additional taint edges and seven query sinks. Extraction and consistency error
counts remain zero.

| Executed relation | Rows | Digest |
| --- | ---: | --- |
| Stage3 target projection | 78 | `7c5daf299264jo0bg9popg0dt4c` |
| Stage3 complete read | 78 | `4dc439jno1lnmi9nn2l8k47a1ff` |
| Stage4 target projection | 78 | `0aeedeu5rvfljmmn3d0m9vqg9m5` |
| Stage4 complete read | 78 | `b5dc56n02j0d4492ub25r54nfi6` |

Both changed target relations are nonempty. The complete read relations retain
the exact row counts and evaluator digests observed in both baselines. The
complete decoded JSON SHA-256 remains
`e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725`.
`FIXTURE_COMPARISON.json` includes every result value, original BQRS identities,
actual relation lines and the post-execution input checks.

## Compilation and shared-resource context

Exactly one new compile was invoked, under a 180-second supervisor bound. It
started with 3,035,640 KiB of available memory and requested a 1,536 MiB JVM heap,
`--ram=2048` and one thread. CodeQL raised its RAM option to its own 2,638 MiB
minimum and respawned with an effective 1,800 MiB JVM heap. The original request,
automatic adjustment and final successful 99.280-second outcome are all retained.

The compile overlapped a separate Stage4 retained-project probe. That probe
returned exit code 137, with `Killed` in its stderr, after 2,256.168 supervised
seconds. The original supervisor receipt and stderr are retained in
`resource-context/`; the termination cause remains undetermined. Its overall
record finished after partial-result capture, so that timestamp is distinct
from a kernel termination time. `RESOURCE_CONTEXT.json` records these observed
boundaries without inferring an exact kill timestamp.

The new fixture execution began after the probe had ended. Its 100.001 seconds
and the earlier fixture times therefore represent different host conditions.
They establish completed result equality. A separate exclusive retained-project
run is in progress; its completion and performance results are recorded independently.

## Packet contents and reproduction

`results/` includes the new original BQRS and both retained baseline BQRS files.
Their complete decodes and original execution receipts are preserved alongside
the new `steps/` records. `LOG_IDENTITIES.json` binds every compressed log and RA
to its original bytes.

`reproduction-inputs.zip` contains the exact candidate vendor source, its upstream
MIT license and the local method-source snapshot. `REPRODUCTION_INPUTS.json`
publishes the complete member list and hashes. Unpack these inputs into a private
reproduction workspace. Start with the authenticated official query pack, apply
the single-file patch to the embedded dependency, check the source inventory,
and load the complete fixed capsule. The recorded commands then run the same
full query against an independent copy of the accepted fixture database.

This packet records one new compile and one new query evaluation. Existing
baselines and production assets remain at their original identities.

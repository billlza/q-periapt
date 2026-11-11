# Same-runner B-A-A-B: complete 39-query fixture qualification

The controlled fixture completed successfully in [run 43087152738](https://github.com/billlza/q-periapt/actions/runs/43087152738), job 130754412834. All four analyses produced the complete 39-query result set. Independent readback of the downloaded original artifact confirmed equality of all 39 decoded results across all four analyses, including column metadata, types and duplicate-row multiplicity. All four also reproduced the complete frozen 29-row SummaryStats baseline.

On this runner and this fixture, A averaged **90.1571 s** and B averaged **92.5356 s** for the complete analysis command. B added **2.3785 s (2.6382%)**. This controlled comparison replaces the misleading use of separate-runner fixture durations as an estimate of candidate overhead.

## Experiment identity and controls

| Item | Fixed identity |
| --- | --- |
| A: Stage3+4 projection source | `b5185165283880527a54289b47397fde78ddf553` |
| B: five-column Unit source | `ed38e305552db2825d90622c130973df87e16d50` |
| Diagnostic workflow commit | `95ba31c114fd9b0c3bc014ed9e37d416a577715f` |
| Diagnostic tree | `b97bd462405228631f9d830dac290a8f87d4f0ef` |
| Branch | `diagnostic/codeql-fixture-baab` |
| Execution order | B1, A2, A3, B4 |
| Query suite | Complete frozen 39-query suite |
| Allocation | 4 threads; 14,000 MB requested; 3,484 MB resolved heap; 9,329 MB off-heap |
| Analysis deadline | 600 seconds per complete analysis |
| Join-order setting | `all` |

One extraction produced a 6,651-file database inventory with SHA256 `23362b3a54a7b0811f1df7f357e71fdc949759e7cb53f447b1613fac084ecbb1`. Each arm started from a separate copy of those same input bytes, without BQRS results, and used its own runtime and cache. Full source inventories were bound to immutable Git commits and independently matched the earlier verified public Git inventories: 597 files for A and 600 for B.

B1 sampling stopped before A2 started. All four timed analyses finished before any result decoding began. The timed boundary is each original `database analyze` command; extraction, snapshot preparation, runtime preparation and subsequent semantic decoding are outside that boundary. The workflow commit and each imported production source are recorded separately; the GitHub workflow identity was not rewritten.

The original method, diagnostic helper and workflow are retained under `source/`. The public source binding and immutable commit API response are alongside them. Source-preparation qualification, including the earlier failed run and the cold Git repair, is in [the preceding evidence packet](../20261111-codeql-baab-source-preparation/) at parent commit `3ecccfc3d4bca918ca54daadf1c24cf1c1ad077f`.

## Observed timing and resources

| Arm | Source | Analyze wall seconds | Observed process CPU seconds | Sampled tree RSS peak bytes | Sampled tree RSS peak GiB |
| --- | --- | ---: | ---: | ---: | ---: |
| B1 | ed38 | 93.834136005 | 312.17 | 10,861,559,808 | 10.115616 |
| A2 | b518 | 90.379728935 | 300.03 | 10,959,904,768 | 10.207207 |
| A3 | b518 | 89.934440762 | 299.35 | 10,893,246,464 | 10.145126 |
| B4 | ed38 | 91.237130649 | 303.99 | 10,861,412,352 | 10.115479 |

Mean observed CPU time was 299.69 s for A and 308.08 s for B (+2.7996%). Mean sampled process-tree RSS peak was 10.176167 GiB for A and 10.115547 GiB for B (65,089,536 bytes, or 0.5957%, lower for B). These are the existing sampler's observations: process-tree RSS can count shared pages more than once and can miss peaks between samples. The original JSONL samples were independently checked against the reported counters and maxima.

The CLI's SummaryStats evaluation durations were 79, 76, 76 and 77 seconds in execution order. Queries share the same four threads, so these printed per-query durations are concurrent-suite observations.

The measured mean difference describes one nonempty fixture with two observations per source on one runner. Large retained-database experiments have separate sources, identities and outcomes; their results are not inferred from this fixture.

## Completed independent readback

The downloaded original ZIP was read in full, including every member's CRC and bytes. Its size and SHA256 matched the artifact API. The readback checked:

- The run, job, workflow tree, source commits and all four private runtime/cache bindings.
- Thirty-nine canonical, distinct stderr completion identities per arm, 39 starts, 39 precompiled loads, zero compilations, one evaluator invocation and 39 fresh BQRS results per arm.
- Equal input inventories, original input and runtime guards, identical resolved memory allocation and complete SARIF admission.
- All 156 arm/query decoded results, with tuple order normalized while preserving types, columns and duplicate rows. All 39 query results matched across the four arms.
- The complete 29-row retained baseline, including 15 active sources and 106 tainted nodes.
- All 195 stored BQRS copies: the 156 arm results plus the original B1 database's duplicate 39 files.
- Original process-resource samples, reported CPU counters, sampled RSS maxima and nonoverlapping analyze boundaries; all decoding occurred after B4 completed.

Runtime identity was 2,282 files / 231,156,107 bytes, canonical SHA256 `1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90`. Both packs contained 1,357 files. A's pack SHA256 was `13705d5f8b164bd69a12219c41a7fe8ba7e304247a4b78d0150c4dd36882d441`; B's was `332897d1bbd8506384f3788f1e27635593b815e7a7e739154e6b340885e726be`.

## Original artifact and this publication

The original artifact is **13888275093**, named `codeql-fixture-baab-43087152738-1`:

- **13,255,489 bytes**
- **SHA256 `705f5687f29e74bca5bfb539e7c90291ac120f2087305368415f8478bf8daf96`**
- **1,148 members**, including the full detailed evaluator logs, raw resource JSONL, receipts, BQRS results and decoded JSON.
- [Artifact metadata](https://api.github.com/repos/billlza/q-periapt/actions/artifacts/13888275093)
- [Original ZIP download endpoint](https://api.github.com/repos/billlza/q-periapt/actions/artifacts/13888275093/zip), subject to GitHub Actions access.
- The recorded artifact expiration is **2026-11-25 19:35:44 UTC**.

The local execution environment disconnected after the full independent readback and before final Git publication. Consequently, **the original ZIP and the original local readback JSON files are not included in this Git tree**. This commit contains the original available run/job API text, serialized artifact API data, exact retrieved job log, immutable diagnostic source, and `QUALIFICATION_SUMMARY.json`, which is explicitly a newly serialized summary of the completed independent readback. It does not present that summary as the byte-for-byte original local reports.

For the original per-arm receipts and comparisons, inspect `qperiapt-codeql-wrapper-fixture/comparison/evidence/RESULT.json`, the B1 `evidence/` directory, and `comparison/runs/{A2,A3,B4}/evidence/` inside the original artifact. The original archive's digest identifies the full detailed evidence independently of this smaller publication.

`MANIFEST.sha256` covers every published file other than itself. No query, compiler, workflow rerun, production-source change or reference update was performed while publishing this index.

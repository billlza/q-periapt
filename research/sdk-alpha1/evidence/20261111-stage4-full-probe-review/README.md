# Original Stage4 projection: full-database probe review

The terminated local probe preserved **38 completed query results, all semantically equal to their retained counterparts**. A read-only postcheck also passed for the complete 1,175-file dependency inventory, the selected 39 query sources and compiled QLX files, the full SummaryStats plan's 15 referenced stages, and 9 root-pack support files. These checks establish the integrity of the executed candidate and its available results.

The full SummaryStats query remained incomplete. The evaluator returned `137`; stderr ends with `Killed`, while the supervisor's stop reason is `null`. The recorded process duration is 2,256.167902404 seconds, below the configured 3,600-second supervision deadline. A kernel or cgroup cause record is unavailable, so the termination cause is undetermined. A separate Stage3+Stage4 compilation overlapped the final portion of this probe; the incomplete wall time is therefore not used as a clean performance baseline.

## Execution and source identity

| Item | Recorded identity or result |
| --- | --- |
| Retained input source run | `42554273879` |
| Retained input source head | `3254c81066af26cd23a2881198010fb616ce6b7a` |
| Analyzed database commit | `56f191f04a57806869b8a03078ee4d27ffe900ab` |
| Input artifact | `13677417145`, 288,417,501 bytes; SHA-256 `cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d` |
| CodeQL / Rust query pack | `2.27.2` / `0.1.44` |
| Original controller source commit | `443f05fa4da60093f57b6f529fccf19c17373300` |
| Controller SHA-256 | `5fd41ef197189ff5a173fdbe1e39772899cc6f26ee0e4d1b0377973b2f69d409` |
| Local probe method SHA-256 | `7ca6051af6140ec1d5e9c8e5ef870104025b3bb7eb4d0f403a494d7b515e4502` |
| Stage4 capsule SHA-256 | `1fe6db109a540d6063fca24e25e9d6c56a88f972a5c248d74fd95f7248fb6132` |
| Compiler input key | `70fcc50b9809b694b26b77a11722cdbb` |
| Full SummaryStats QLX SHA-256 | `65e651eb4b56da599cca6538a9eaf55df2cc1dd8ce3943e91786c24daa1d97df` |
| Requested resources | 1,024 MiB JVM heap, 4,096 MiB native memory, 4 threads |
| Evaluator invocation | `2026-11-11T10:55:59.322658+00:00` |
| Final probe receipt | `2026-11-11T11:34:04.297685+00:00` |
| Evaluator observation | 39 precompiled query loads, 0 query compilations, 38 query completions |

The original method imported the controller before later edits to the integration worktree. Its recorded controller hash matches the archived source at commit `443f05fa`. That commit predates the later unified projection dispatch. `reproduction-sources.zip` preserves the original method and the six-module repository import closure from this commit; it also preserves the read-only review script. The entrypoint recorded its own and controller hashes. The import-closure hashes are reconstructed from the identified source commit rather than claimed as separately instrumented runtime measurements.

The archived original method and its source-binding receipt provide the replay entry point. Restoring the authenticated database, official Rust bundle, and original prototype pack is a separate input step. Paths in the method retain the actual workspace locations used by this run.

## Result and pack verification

| Check | Independently verified outcome |
| --- | --- |
| Available result census | Exactly 38 queries; only `queries/summary/SummaryStats.ql` is absent |
| Existing decoder receipts | All 76 retained/fresh decode commands returned 0 |
| Semantic comparison | 38 of 38 pairs equal after canonicalization of the full decoded tables |
| BQRS identity | Each captured BQRS matches its recorded digest; each fresh captured BQRS also matches the original fresh output |
| Dependency inventory | Exact 1,175-file path set and byte/hash records match the pre-evaluation inventory |
| Selected query sources / QLX | All 39 sources and all 39 compiled files match the pre-evaluation records |
| SummaryStats stage closure | All 15 referenced stage files and the compiler input key match the original capsule |
| Root-pack support | All 6 root QLL files and 3 package metadata files match the fixed support specification |

Canonicalization sorts each table's tuple array using compact, sorted-key JSON and then hashes the complete result object. It preserves table metadata, columns, duplicate tuples, and every row. The archive `decoded-results.zip` retains both sides' original decoder output and command receipts, allowing the comparison to be repeated without starting CodeQL. The postcheck covers the exact selected 39-query suite; the bundled pack also contains unselected queries.

The additional support-file specification comes from commit `11ba16eb257c4d68ed967fa554d9a36b362848b0`. Its capsule, compiled inventory, and dependency inventory identities match the original Stage4 probe. It supplies the later explicit support-file pins for the postcheck and is not substituted for the controller source actually executed.

## Stage3 diagnosis and resource overlap

The fixed log-prefix readback ended at `11:22:57 UTC`. At that point, evaluation remained in Stage3, and Stage4 evaluation had not started. The readback identified the Stage3 full-read relation as a concrete hotspot: 284 matched wall seconds and a maximum reported delta of 2,112,710 rows. The compiled relational-algebra readback locates its recursive consumer and the later nonrecursive full-relation consumer. These observations motivated the separately compiled Stage3+Stage4 candidate; that candidate has a distinct source and capsule identity.

The Stage3 snapshot uses a 486,699,920-byte prefix. Its SHA-256 was independently recomputed from the final original log and matches the snapshot receipt. Predicate durations use whole-second log timestamps, and reported delta volumes are not final relation cardinalities or a measured duplicate-witness factor.

The separate compilation ran from `2026-11-11T11:33:01.649495+00:00` to `2026-11-11T11:34:40.929829+00:00`, as recorded in the unchanged compilation receipts under `overlap/`. The probe's final evaluator-log timestamp is `11:33:29 UTC`. These records establish overlapping activity without assigning an exact kernel kill time or a termination cause.

## Packet contents

| File or directory | Purpose |
| --- | --- |
| `REVIEW.json` | Concise execution outcome, verification result, and scope |
| `QUERY_PACK_POSTCHECK.json` | Source-bound pack postcheck receipt |
| `QUERY_PACK_INVENTORY.json.gz` | Complete checked dependency, selected query, stage, and support inventories |
| `PARTIAL_SEMANTICS_REVIEW.json` | Per-query semantic and binary identities for all 38 pairs |
| `decoded-results.zip` | Original retained/fresh decoder outputs and command receipts |
| `REPRODUCTION_SOURCES.json`, `reproduction-sources.zip` | Original method, source binding, import closure, and review method |
| `raw/` | Unchanged original failure receipts and small stdout/stderr logs |
| `stage3/` | Unchanged fixed-prefix and relational-algebra diagnostic receipts |
| `overlap/` | Unchanged overlapping compilation and resource-context receipts |
| `EXTERNAL_ARTIFACTS.json` | Identities of larger original evidence retained separately |

The original evaluator log is **488,792,813 bytes**, SHA-256 `57c7f116f46b31e4648957f8a8be6b27fb5f70d1abf2596fbb4eaedf962733d7`. This packet records its independently verified identity; it does not duplicate or recompress that log. The original BQRS files, process-sampling stream, and full database-input inventory remain in the original results evidence. No CodeQL process, compilation, query, fixture, or remote mutation was started for this review.

# Forward-fusion complete-wrapper qualification

The production candidate `9c0d63d4d258f126af92a8bda64aec090019a1b3` completed the frozen nonempty fixture through the production CodeQL wrapper. All **39 admitted queries** produced fresh results, and the complete **29-row SummaryStats result is byte-for-byte equal to the retained baseline**.

## Source and execution

- Production source: `9c0d63d4d258f126af92a8bda64aec090019a1b3`; tree `85fcc41a318020290955f6862b65b99a96b79691`.
- Diagnostic workflow: `e28782427c519f46750445c906a56a77ceb9c1fe`; tree `daeddbfe94dfced00391b1b24648db6ce14232bc`.
- [Run 43069971846](https://github.com/billlza/q-periapt/actions/runs/43069971846), attempt 1; job `130694887360`, completed successfully.
- Artifact `13877746562`: **3,696,640 bytes**, SHA-256 `da02e25c836dcbef67a6d97d4d440ed051caf66ba4c0316cf6846f11801ccc13`.
- Retained fixture and baseline source: `99340939848d290191651ab306d1b5edc0f59df2`.

The diagnostic commit is a direct child of the production source and adds only the isolated fixture workflow and method. The method uses the production preparer, command assembler, environment, memory resolver, source admission and postchecks. Readback authenticates twelve production source files against their public Git blob identities, and reconstructs the complete production root and artifact trees from the saved GitHub responses.

## Complete result and admission checks

| Check | Result |
| --- | --- |
| Workflow contracts | 10 passed, 0.033 s |
| Query starts / precompiled loads | 39 / 39 |
| Implicit query compilations | 0 |
| Evaluator invocations | 1 |
| Complete original-stderr query-completion set | 39 distinct paths and counters 1–39 |
| Fresh BQRS results | 39 |
| Byte-identical result copies checked | 78 |
| SummaryStats | 29 rows, exactly equal to the frozen baseline |
| Nonempty fixture counts | 15 active taint sources; 106 reached nodes |
| SARIF | Valid CodeQL 2.27.2 run; successful invocation; no warning/error notifications |
| Newly extracted database inventory | 6,651 files; zero preexisting BQRS |
| Query pack inventory | 1,357 authenticated files |
| Runtime inventory | 2,282 files, 231,156,107 B |
| Original artifact | 257 members, 48,908,873 expanded B; all CRCs checked |

The decoded SummaryStats bytes have SHA-256 `f05f212ce3a9847d01191fb595c9a154aac94a83e33faf6fdc7f85dbb19b259e`; the semantic digest remains `e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725`.

The full plan matches its primary manifest before and after analysis. Its pins are:

- Manifest SHA-256: `2b961807f0147058e7c2012586a3f5c67d7b718b7ed86ea92bf6ec25087632c1`.
- Compiler-input key: `0ee092250be1b05f03b994a868d639cc`.
- Capsule: 621,407 B; SHA-256 `d90df7ba37cc05bfa7f603f74e9758b9dd0d791920b9e67b42d66414196dcbdf`.
- Pack inventory SHA-256: `85f18ab7b28a87c1e4cad75ebd0001591b172fa9c57e564bbfa249b3414739da`.

Readback checks the capsule's complete sixteen-member closure, the fifteen referenced stages and the binary plan's compiler-input key. It also checks all thirty-nine query source hashes and compiled-query identities, establishes that the other thirty-eight compiled queries retain the bundled inventory, authenticates all 1,175 dependency files, and matches the frozen fixture's thirteen archive members and eight source/support files.

## Internal progress-log observation

The original stderr contains all thirty-nine completion events. The internal evaluator log contains thirty-eight: its progress row for `BrokenCryptoAlgorithm.bqrs` is absent. The corresponding stderr event is `26/39`; the query's fresh BQRS and its retained copy have matching bytes and SHA-256.

The production validator already distinguishes internal progress-message counts from the independently authenticated complete stderr set. This packet retains the actual internal count of **38**, the exact missing path, both raw logs and all fresh-result identities. No source, raw record, completion count or result was rewritten to make the observations agree. `COMPLETION_EVENTS.json` records the two sets separately.

## Timing observations

| Raw measurement | Earlier successful wrapper | Forward-fusion wrapper |
| --- | ---: | ---: |
| Run | 43048934821 | 43069971846 |
| Extraction elapsed | 40.858475858 s | 44.924213953 s |
| Complete analyze command elapsed | 71.722686671 s | 86.180217655 s |
| SummaryStats evaluator-reported duration | 1m0s | 1m13s |
| Precompiled query loads | 39 | 39 |
| Implicit compilations | 0 | 0 |

The new workflow's combined setup/extraction/analysis step ran from 17:37:43 to 17:40:22 UTC. The analysis command itself ran from 17:38:52.481 to 17:40:18.661 UTC; its 86.180217655-second receipt is the reported analysis duration.

The earlier run's QLX load messages span 15:31:07–15:31:09 UTC; its SummaryStats evaluation starts at 15:31:12 and reports completion at 15:32:13. The new run's load messages span 17:38:56–17:38:58; SummaryStats starts at 17:39:02 and completes at 17:40:15. The CLI does not provide a separate summed setup/load duration, so the packet preserves these raw milestones without inventing one. `TIMING_COMPARISON.json` binds the extracted lines to both original artifact hashes.

The measured time increased on this small fixture. The demonstrated result here is preservation of complete production-wrapper behavior and the fixed nonempty result under the fused plan. The timing records are observations from these two hosted executions.

## Files and reproduction

`artifact.zip` preserves the original downloaded bytes and all 257 original members, including the complete internal evaluator log. `job.log` preserves the complete downloaded job log. `original/` contains selected original receipts copied without modification, and `ZIP_MEMBERS.json` records the SHA-256, byte length, CRC and compressed length of each archive member.

`readback.py` reuses the earlier successful wrapper's full verification checklist and adds the explicit primary-source, binary-closure and fixture bindings. Its internal-progress assertion records this execution's actual count and missing path under the existing production rule. The old packet is unchanged.

Run:

```sh
python3 readback.py
```

The readback uses retained bytes only; it does not extract a CodeQL database, compile a query, invoke a JVM or run a new benchmark. It reproduces `READBACK.json`, `COMPLETION_EVENTS.json`, `ZIP_MEMBERS.json` and `SOURCE_PIN_READBACK.json`. `MANIFEST.json` seals the packet's byte lengths, SHA-256 and Git blob identities, excluding itself.

This fixture qualification publishes no SARIF and creates no three-target production profile receipt. Native, WASM and macOS project-scale analyses retain their separate execution records.

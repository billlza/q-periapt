# Five-column Unit-state complete-wrapper qualification

The production candidate `ed38e305552db2825d90622c130973df87e16d50` completed the frozen nonempty fixture through the production CodeQL wrapper. All **39 admitted queries** produced fresh results, and the complete **29-row SummaryStats result is byte-for-byte equal to the retained baseline**.

## Source and execution

- Production source: `ed38e305552db2825d90622c130973df87e16d50`; tree `9daa64caa7814d759397fbde3218b6a2f6721348`; sole parent `9c0d63d4d258f126af92a8bda64aec090019a1b3`.
- Diagnostic workflow: `e9ecdb3c5f0cbb496a3be9a1b0bebd518b1fbebe`; tree `937e62defb074235d0e43074eee236c7b65522b0`.
- [Run 43076555996](https://github.com/billlza/q-periapt/actions/runs/43076555996), attempt 1; job `130717765889`, completed successfully.
- Artifact `13882738653`: **3,769,482 bytes**, SHA-256 `0ec4111efbc5109df1125033f830860673caee6915d866898b4cc2b628da1581`.
- Retained fixture and baseline source: `99340939848d290191651ab306d1b5edc0f59df2`.

The production commit changes the fixed nine-file plan, source, documentation and test set. The diagnostic commit is a direct child of that source and adds only the isolated fixture workflow and method. The method uses the production preparer, command assembler, environment, memory resolver, source admission and postchecks. Readback authenticates twelve production source files against public Git blob identities and reconstructs the complete production root and artifact trees from retained GitHub API responses. Local copies are admitted only when their complete bytes reproduce the public blob and size.

## Complete result and admission checks

| Check | Result |
| --- | --- |
| Workflow contracts | 10 passed, 0.028 s |
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
| Original artifact | 257 members, 49,834,725 expanded B; all CRCs checked |

The decoded SummaryStats bytes have SHA-256 `f05f212ce3a9847d01191fb595c9a154aac94a83e33faf6fdc7f85dbb19b259e`; the semantic digest remains `e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725`.

The full plan matches its primary manifest before and after analysis. Its pins are:

- Manifest SHA-256: `efd65ee72a4f966620a3d9bd6ac97b0a6d8ef5567017f3c342f654c4e1f55873`.
- Compiler-input key: `c327768d3f383933ff70cd941341916b`.
- Capsule: 621,211 B; SHA-256 `35ab9955321008fb55e436c78b38725370fd5930885635e43ed093ab672fc6d3`.
- Pack inventory SHA-256: `332897d1bbd8506384f3788f1e27635593b815e7a7e739154e6b340885e726be`.

Readback checks the capsule's complete sixteen-member closure, the fifteen referenced stages and the binary plan's compiler-input key. It also checks all thirty-nine query source hashes and compiled-query identities, establishes that the other thirty-eight compiled queries retain the bundled inventory, authenticates all 1,175 dependency files, and matches the frozen fixture's thirteen archive members and eight source/support files. The runtime inventory digest is `1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90`.

## Internal progress-log observation

The original stderr contains all thirty-nine completion events. The internal evaluator log contains thirty-eight: its progress row for `codeql/rust-queries/queries/security/CWE-319/UseOfHttp.bqrs` is absent. The corresponding stderr event is `28/39`, at original stderr line 111; the query's fresh BQRS and its retained copy have matching bytes and SHA-256.

The production validator already distinguishes internal progress-message counts from the independently authenticated complete stderr set. This packet retains the actual internal count of **38**, the exact missing path, both original logs and all fresh-result identities. `COMPLETION_EVENTS.json` records the two sets separately. The new readback derives the observed count from this execution rather than inheriting either previous run's count or missing path.

## Timing observations

| Raw measurement | Earlier successful wrapper | Forward-fusion wrapper | Five-column Unit-state wrapper |
| --- | ---: | ---: | ---: |
| Run | 43048934821 | 43069971846 | 43076555996 |
| Extraction elapsed | 40.858475858 s | 44.924213953 s | 50.998139436 s |
| Complete analyze command elapsed | 71.722686671 s | 86.180217655 s | 94.944334919 s |
| SummaryStats evaluator-reported duration | 1m0s | 1m13s | 1m21s |
| Precompiled query loads | 39 | 39 | 39 |
| Implicit compilations | 0 | 0 | 0 |

The workflow was created at 18:18:44 UTC; its setup step began at 18:24:27. The combined preparation/extraction/analysis step ran from 18:24:31 to 18:27:23. The analysis command itself ran from **18:25:45.435 to 18:27:20.380 UTC**; its **94.944334919-second** receipt is the analysis measurement.

The new QLX load messages span 18:25:49–18:25:51 UTC. SummaryStats evaluation starts at 18:25:55 and reports completion at 18:27:17. The CLI provides these milestone timestamps and the displayed query duration; a separate summed setup/load timer is not recorded. `TIMING_COMPARISON.json` binds the observations to each original artifact hash.

The measured time increased across these small-fixture executions. This qualification establishes preservation of complete production-wrapper behavior and the fixed nonempty result under the five-column plan. Project-scale analyses retain their own measurements; the fixture records do not attribute the observed time differences to a particular stage or platform factor.

## Files and reproduction

`artifact.zip` preserves the original downloaded bytes and all 257 original members, including the complete evaluator log. `job.log` preserves the complete downloaded job log. `original/` contains selected original receipts copied without modification, and `ZIP_MEMBERS.json` records each member's SHA-256, byte length, CRC and compressed length.

`readback.py` reuses the earlier successful wrapper's full verification checklist, including primary-source, binary-closure, fresh-result and frozen-fixture bindings. `EXPECTED.json` fixes this run's API identities and the authorized evidence parent. The earlier packets remain unchanged.

Run:

```sh
python3 readback.py
```

The readback uses retained bytes only; it reproduces `READBACK.json`, `COMPLETION_EVENTS.json`, `ZIP_MEMBERS.json` and `SOURCE_PIN_READBACK.json` without invoking CodeQL, a JVM, a compiler, database extraction, a test suite or a new runner. `MANIFEST.json` seals the packet's byte lengths, SHA-256 and Git blob identities, excluding itself.

This fixture workflow publishes no SARIF and creates no three-target production profile receipt. Native, WASM and macOS project analyses retain their separate execution records.

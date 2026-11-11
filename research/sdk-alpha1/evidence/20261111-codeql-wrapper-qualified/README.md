# Qualified nonempty production wrapper

[Run 43048934821](https://github.com/billlza/q-periapt/actions/runs/43048934821/job/130620449051)
completed successfully using workflow source
`74101a672c945d0e952e283a4750748a8da27065` and production source
`b5185165283880527a54289b47397fde78ddf553`. It performed a fresh extraction,
ran the complete **39-query suite**, generated valid native Rust SARIF and
decoded the full **29-row SummaryStats result**, which is byte-identical to the
retained original `all`-plan result. The hosted method completed all source,
pack and runtime postchecks.

| Actual command | Result | Elapsed time |
| --- | --- | --- |
| Frozen fixture extraction | Exit 0 | 40.858 s |
| Production `database analyze` | Exit 0; all 39 queries and SARIF | 71.723 s |
| SummaryStats BQRS decode | Exit 0; complete 29-row equality | 0.461 s |

These are command timings for this hosted execution. The fixture contains
5,252,379 extracted elements, 2,917 files including the standard library,
53 user-source lines, 15 active taint sources and 106 tainted nodes. Extraction
errors, warnings, unextracted elements and the recorded consistency counts are
zero; all six macro calls resolved.

## Independently verified result

The readback verifies the original ZIP digest and every one of its 257 members.
All 12 production source-contract files match their exact Git objects, and the
recorded wrapper method matches its workflow source. The initial extracted
database inventory has 6,651 files and no BQRS. The 39 fresh result identities
match both retained copies of every result: the evidence copy and the database
result copy. The ZIP therefore contains 78 BQRS members representing 39 results.

The complete decoded JSON has 1,185 bytes and SHA-256
`f05f212ce3a9847d01191fb595c9a154aac94a83e33faf6fdc7f85dbb19b259e`.
Its canonical semantic digest is
`e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725`.
The readback compares the complete object, columns, ordered rows, values and
multiplicities with the retained baseline input. No baseline was rerun.

The new completion receipt binds the retained `analyze.stderr` bytes and the
exact 39-query identity set. Independently parsing that stream finds each
admitted completion once. This execution also records 39 starts, 39 completions,
39 precompiled loads, zero compilations and one evaluator invocation in its
internal log; those internal counts remain separately recorded. The earlier
[37-message internal-log divergence](../20261111-codeql-wrapper-completion/README.md)
and its [receipt repair](../20261111-codeql-completion-receipt-fix/README.md) retain
their original source and outcomes.

Actual evaluator allocation is 3,484 MiB Java heap plus 9,329 MiB off heap within
the requested 14,000 MiB budget, with four query threads and a 600-second
supervisor. The 1,357-file pack inventory matches the accepted Stage3/Stage4
package. The 2,282-file, 231,156,107-byte private runtime inventory matches
canonical digest `1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90`.
The final plan identity equals the initial identity. Native SARIF 2.1.0 names
CodeQL 2.27.2, reports successful execution and contains no tool warning/error
notifications.

This completes qualification of the exact production analysis wrapper on the
frozen nonempty fixture. The current native, WASM and macOS workflows supply
project-source extraction, analysis and combined publication qualification.

## Preserved material

`artifact.zip` is the unchanged artifact `13867679562`: **3,741,772 bytes**, SHA-256
`8b98728022af8d3a51708e6ac497f1f6184c8a1bb1f33c6f3b80d1bebc1701c3`.
It retains the full raw logs, both copies of all results and all hosted receipts.
The 29,133,392-byte execution log remains in that ZIP. `original/` contains the
selected unchanged command, result, source, completion, plan, runtime, database
and SARIF records. `job.log` is the full decoded job log, and the API readbacks
bind the workflow, job and artifact identities.

`READBACK.json`, `COMPLETION_EVENTS.json` and `ZIP_MEMBERS.json` contain the
independent checks. `readback.py` is the exact local byte-reading method; it ran
no additional CodeQL commands, JVMs, compilation, extraction, queries or tests.
`MANIFEST.json` covers every packet file except itself.

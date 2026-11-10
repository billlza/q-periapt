# Retained SummaryStats allocation control: measured outcome

The two requested memory allocations have completed their controlled runs. Both
executed the pinned 39-query suite on the same retained macOS-origin database,
completed 38 queries, and reached the 18,000-second boundary while the full
`SummaryStats` query remained in `TaintReach` Stage 4. These two allocations are
therefore insufficient to complete this input within the existing evaluator
budget. Production query coverage, CLI version, and timeout were unchanged.

## Execution identity

- Workflow run: [42634713742](https://github.com/billlza/q-periapt/actions/runs/42634713742), attempt 1.
- Experiment commit: `747c45bab13320d1df2ebaaa0012f183fcf4a1a0`.
- Analyzed source: `56f191f04a57806869b8a03078ee4d27ffe900ab`.
- Source diagnostic artifact: `13677417145`, SHA-256
  `cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d`.
- Inner database ZIP: SHA-256
  `c8bdc47f5cbb0b6d83c0d60c63e8ff9f80ad63683c58cdf32311dd8bb6c9dbf1`.
- CodeQL 2.27.2 / Rust query pack 0.1.44; authenticated CLI bundle SHA-256
  `acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea`.

Both artifact ZIPs were downloaded and verified against the SHA-256 and byte
counts reported by GitHub's artifact API and the respective upload log. The
local audit recomputed the database and 1,437-file retained-cache inventory
digests from `DATABASE_INPUTS.json`, checked all 39 query-source and compiled-plan
hashes against independent controller pins, verified the exact execution
commands, and checked actual JVM heap limits from retained `PrintFlagsFinal`
output. The original controller source identities are in
`CONTROLLER_SOURCE.json`; `INPUT_IDENTITY.json` contains the common input pins.

## Results

| Measurement | heap-2048 | heap-1536 |
| --- | ---: | ---: |
| JVM heap limit, MiB | 2,048 | 1,536 |
| Accepted off-heap budget, MiB | 10,643 | 11,155 |
| Total budget, MiB | 14,000 | 14,000 |
| Threads | 4 | 4 |
| Supervised elapsed seconds | 18,001.00679493 | 18,001.006627495 |
| Query completions | 38 / 39 | 38 / 39 |
| Eviction pauses, independently recounted | 76,024 | 83,314 |
| Highest recorded Stage 4 iteration | 284 | 289 |
| Largest completed `fwdFlow0` delta, rows | 129,268,663 | 194,634,663 |
| Termination | timeout | timeout |
| Cleanup ambiguity | false | false |

The final newly started predicate in the 2,048 MiB arm was `fwdFlow0/7` at
22:42:12 UTC, iteration 284. In the 1,536 MiB arm it was `fwdFlowRead/11` at
22:39:48 UTC, iteration 289. Raw evaluator events continue through 22:43:50 and
22:43:12 UTC respectively. The full and reduced summary queries both remained
in the selected suite; the reduced query completed in both runs. All 19 security
queries have completion events in each arm.

Both hosts report four logical CPUs, AMD EPYC 9V74 processors, kernel
`7.0.0-1017-azure`, and `MemTotal` 16,367,524 KiB. The heap values above are JVM
limits observed from the launched JVM, and the off-heap values are accepted
command budgets. No independent RSS time series was collected. Fixed-point
iteration numbers and relation sizes describe the computation reached; they are
not percentages of completion or an elapsed-time speedup measurement.

## Result semantics and failure retention

All 38 retained input BQRS files were hashed, their successful decode receipts
checked, and their decoded JSON canonicalized again. Their binary and semantic
digests agree across the two arm artifacts. This validates the common retained
result baseline.

Each uploaded artifact contains zero fresh BQRS or decoded-result members. The
controller writes new query outputs under `root/results/codeql/rust-queries`,
whereas the workflow uploads `root/evidence/**`. Its fresh-result decoder and
copy run only after successful evaluator termination. Consequently the available
evidence establishes the 38 completion events but does not retain those newly
written results for a semantic comparison. This is a specific diagnostic
retention gap: the next narrow change should capture available fresh outputs on
failure and label them partial while preserving the existing 39-query admission.

The original strict comparator was rerun locally against the two original
`RESULT.json` receipts. It exited 1 and retained `completed: false` with
`fresh 39-query result census differs`. This is recorded in
`LOCAL_COMPARISON.json` and `comparison.log`. At the evidence snapshot the hosted
aggregate job `129492456066` was queued. Neither arm is represented as a
completed analysis or a production configuration selection.

## Retained evidence

Each arm directory retains its original result/command receipts, JVM stdout,
query stderr, complete GitHub job log, independent audit, full progress events,
last 80 non-eviction lines, and the actual final 40 evaluator lines. The full
evaluator logs, retained BQRS, decoded result files, and admission records remain
inside the two original verified ZIPs bundled in `SUMMARY-CONTROL-CAPTURE.zip`.
`RAW_CAPTURE.json` identifies that bundle and both original GitHub artifacts.
The local audit recomputes hashes and decode-output semantics; it does not claim
a separate local CodeQL decoding run.

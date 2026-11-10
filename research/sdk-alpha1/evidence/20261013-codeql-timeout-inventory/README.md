# Rust CodeQL timeout and current source inventory

The hosted Rust analysis of `9b90c76040a389235eb3064178832ab5ba479093`
timed out in Analyze after 300 minutes. The complete job log records 39 query
starts and 38 completions; `SummaryStats.ql` remained unfinished. The last other
query completed at 00:33:32 UTC, about four minutes after query evaluation began.
The evaluator continued the `TaintReach` fixed point with repeated native-cache
evictions until termination. This is an observed bottleneck, not a verified
resource fix or a finding about product execution performance.

`OBSERVATION.json` retains the job URL, complete raw-log size and SHA-256,
completion lines, and excerpts from the single evaluator-log section. The raw
600 MB log remains in the task's `target/continuity-codeql-timeout` directory.
No query, threat model, database-quality assertion, or workflow timeout changed.
The previous frozen-database memory allocation experiment completed neither
profile within its 900-second bound; it cannot justify calling the timeout fixed.

An independent local failure was reproduced in the current `bb82bd78` source:
the fixed tracked-source count still required 581 files, while Git contained
594. The 13 added browser sources are enumerated in `INVENTORY.json`.
The repaired count and artifact guide require 594, and the inventory test now
explicitly includes those browser paths. Exact path and extraction checks remain.

Validation used the task-owned real-Git gate clone at `bb82bd78`, first without
the repair, then with only the three changed files overlaid:

```sh
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh -m unittest -v \
  test_codeql_rust_quality.CodeQLRustQualityTests.test_tracked_inventory_is_nonempty_and_nul_terminated
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh -m unittest -v test_codeql_rust_quality
```

The original check failed with `tracked Rust source count must be 581, got 594`.
After repair all 44 quality-gate tests passed. These local tests do not execute
CodeQL or close the hosted-analysis requirement. No release claim is made.

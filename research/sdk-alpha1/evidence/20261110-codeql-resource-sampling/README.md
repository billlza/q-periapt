# Independent CodeQL process resource samples

The retained two-arm SummaryStats run records accepted JVM/off-heap allocations
and fixed-point progress. This change supplies independent process counters for
subsequent runs: approximate RSS for the query roots and their observed tree,
own-process CPU ticks, and available per-process storage I/O counters.

`artifact/codeql_process_resources.py` samples Linux procfs without changing the
query command, timeout, source/database/query-plan identities, or complete-suite
comparison. It excludes the controller and pre-existing child subtrees. Observed
PID/start-time identities remain associated after reparenting; reused PIDs and
older children in a non-atomic census cannot adopt a new parent's identity.

Default sampling is every two seconds, with explicit process-count, identity,
record-count, byte, scan-work and shutdown-wait bounds. Sampling errors retain
the evaluator's original result. The summary distinguishes unavailable,
unsupported, partial, stopped, and incomplete-shutdown outcomes. Shared pages
can occur in several RSS counters, so the recorded tree maximum is a sampled
RSS sum, not physical job peak memory or PSS. I/O counters are retained per
process because they can include waited-for children. Short processes and peaks
between samples may be missed; these interpretation fields accompany the data.

## Validation

- The unchanged baseline passes all 92 original control tests.
- The candidate passes 108 tests: the original 92 plus 16 resource controls.
- Real allocating parent/child processes are observed at a shortened 50 ms
  control interval. The success case records 28 samples, 27 with processes,
  one root and two identities. Its sampled tree RSS maximum is 74,055,680 bytes;
  the root maximum is 33,947,648 bytes.
- A separate real one-second supervised timeout records 20 samples, 19 with a
  process, and retains the typed timeout with unambiguous cleanup.
- PID reuse, a non-atomic older-child counterexample, reparenting, pre-existing
  background processes, malformed/redirected inputs, output/count limits,
  unsupported procfs, and secondary sampling failures are covered.
- AST comparison confirms that only the controller's `run_queries` function
  changes; constants, command construction, admissions and the strict 39-result
  comparator are identical. Both sparse workflow checkouts include the new
  module, and the existing preflight runs the resource tests.

The real-process controls allocate Python memory and sleep; their complete
commands, counters, source hashes, and supervision receipts are retained under
`live-controls/`. They validate sampling and cleanup, with no new CodeQL
performance measurement or hosted query execution claimed.

```sh
sh artifact/python-run.sh -m unittest -v test_codeql_summary_control test_codeql_process_resources
python3 -I research/sdk-alpha1/evidence/20261110-codeql-resource-sampling/run_resource_controls.py \
  --source-root . --output /absolute/fresh/resource-control-output
```

See [the control documentation](../../../../artifact/codeql-summary-control.md)
for counter definitions, bounds, and primary Linux procfs references. Merge the
workflow-input guard repair first so its literal sparse-checkout entries are
classified as file-selection data by the existing repository-wide CI guard.

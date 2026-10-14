# Rust analysis inventory and evaluator cache control

Run [38465320255](https://github.com/billlza/q-periapt/actions/runs/38465320255),
source `986ef66c13624e4b8203d1523ed4c350669ec6e2`, failed Rust Analyze at its
300-minute limit. The other five language jobs succeeded. The full compressed
workflow log was downloaded and hashed; `OBSERVATION.json` identifies that
archive and the two Rust log members used here. Two earlier direct job-log
downloads timed out without bytes; their failure receipts remain local.

The query evaluator reported 38 of 39 queries complete by 21:07:49 UTC,
about six minutes into evaluation. Full `SummaryStats` remained unfinished.
The retained evaluator section shows the selected `TaintReach` Stage4 predicate
entering iteration 453 and 167,585 native-cache eviction pauses. Iterations and
eviction counts are diagnostics, not a completion percentage, ETA or proof of a
single root cause. Resource settings were four threads, JVM heap 5788 MiB and
native memory 6898 MiB. The completed query progress does not establish a passed
database quality gate or uploaded Rust analysis.

Separately, the current `b53cb08d` inventory check failed because it still
required 630 Rust sources while Git tracked 644. `INVENTORY.json` lists all 14
additions since the prior inventory update. The repair updates the exact count,
the artifact guide and both the positive and missing-source regression lists.
No extraction-path equality check, quality assertion or query was weakened.
The two original inventory tests failed with the expected 630-versus-644 error;
the retained red log records that observation.

The existing diagnostic evaluator workflow now compares `baseline` against
`reusable-cache`. The latter changes only the cache expectation to
`--no-expect-discarded-cache`, keeping the same database/cache snapshot, all 39
query text and compiled-plan hashes, threat model, threads and memory allocation.
The hypothesis is that permitting reusable intermediate results can reduce
recomputation after eviction. The option changes evaluation planning, not the QL
query definition; its benefit is **not yet measured**. GitHub's
[CLI documentation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-run-queries)
describes this flag as controlling intermediate-result evaluation and caching
decisions. The earlier `more-native` diagnostic profile remains available.

Both arms retain the existing 900-second bound. Timeout and incomplete output
remain failures. Fresh output must contain all 39 results; old BQRS cannot satisfy
the check. This experiment neither uploads SARIF nor qualifies current-source CI.
The production CodeQL workflow, all its queries and its quality gate are unchanged
apart from the corrected source census. No timeout increase is proposed.

Local validation: 87 tests passed across `test_codeql_rust_quality`,
`test_codeql_memory_control` and `test_evidence_io`; the log is retained here.
The first combined invocation also named a nonexistent checkout test module and
exposed the guide's stale number. That failed invocation and a second guide-only
failure remain in the local stage; the final run uses the real test modules and
updated guide. `actionlint` and `git diff --check` passed. Hosted cache-control
execution, full current-source Rust analysis and release readiness remain open.

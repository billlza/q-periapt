# Frozen Rust query cache comparison

Run [38501404936](https://github.com/billlza/q-periapt/actions/runs/38501404936)
compared the baseline `--expect-discarded-cache` setting with
`--no-expect-discarded-cache`. The frozen database, all 39 original query and
compiled-plan hashes, four threads, 5788 MiB heap and 6898 MiB native allocation
matched. Both profiles timed out at 900 seconds; both recorded unambiguous child
cleanup. Each completed 38 queries and left full `SummaryStats` unfinished.

The baseline's last selected TaintReach read iteration was 289 with 3,913 native
cache eviction pauses. The reusable-cache arm reached iteration 282 with 2,991
pauses. These figures describe different amounts of unfinished work on separate
hosted runners. They are not an ETA, completion percentage or proof that one arm
is faster. No complete result set or full semantic comparison was obtained.

`CHECKS.json` identifies the two downloaded archives; their sizes and SHA-256
digests match the GitHub artifact API. `CAPTURE.zip` retains their command and
failure receipts, runtime resource observations, exact query hashes, run metadata
and log summaries. Full archives and evaluator logs remain in the task's
`target/continuity-codeql-20261014` directory. No security query, extraction check,
quality assertion or production analysis setting was changed. The observed
outcome does not justify adopting the cache setting as a fix.

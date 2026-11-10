# Retain original publication bytes in CI artifacts

The installed producers already export verified publication IDs, plans, exact
retry bytes and supporting public observations. Their C/Swift/Kotlin directory
names were absent from the CI upload selections, leaving summary JSON without
the raw bytes needed for independent readback. The focused Android workflow has
the same omission for its prerequisite C publication scenario.

The correction adds five explicit public-directory paths across two workflows
and three upload configurations. It changes no runtime, timeout, query, assertion,
artifact identity or private-state export rule. A new path-selection regression
constructs the actual public directory shapes for Debug/Release and both Kotlin
collectors, and includes private runtime/state sentinels that must remain excluded.

The original configurations fail all three upload subtests for omitted public
bytes. After the correction, the complete workflow regression module passes
**14 tests** in 3.446 seconds. On the
[completed real C output](../20261104-continuity-c-maintenance/README.md), the old
selection omits exactly **168** files, all in `c-publication-public`; the new
selection retains all **35,713** output files. The original publication reader
has already revalidated both 84-file profile exports. The new test does not claim
that the yet-running foreign consumers have completed.

The qualified C receipt remains pinned to `ff072bd6`. Comparing its captured
1,399-file input inventory with MAIN after the correction finds only
`.github/workflows/ci.yml` changed; all selected runtime inputs and the Rust
workspace digest are unchanged. The focused-workflow change and regression
source are recorded separately. No old receipt is rewritten as a new-source
hosted pass.

`CAPTURE.zip` retains original/repaired workflows, original failing outputs,
the complete passing output, regression source and real-output selection
readback. All 15 members were reread: 85,075 bytes, SHA-256
`047c94a71542f8b2cc875ffdec38663fbcd5fd7b42bc9416cc7e4e2201f47d15`.
The initial two-upload red test is preserved alongside the complete three-upload
red test; the final result uses the latter. No failed test or private fixture was
discarded to obtain the passing result.

`NEXT_WAVE.json` separately records an existing sequencing constraint. The focused
Android workflow still selects SDK run `39129232908`, which belongs to source
`23280124` from 2026-10-18. Its pin must be validated/refreshed from a matching
hosted producer before uploading the focused-workflow correction. The source/SDK
producer can be staged first by normal ancestry; the current open CI wave must
finish before either next wave. No pin, remote workflow or branch was changed,
and no automatic latest-artifact fallback was introduced.

The later [wave-readiness checkpoint](../20261105-ci-wave-readiness/README.md)
prepares the earlier clean qualification source `ff072bd6` as the first hosted
producer, together with its parent P0 correction `232ace17` in one normal atomic
update. Both targets pass a dry-run and preserve existing commit identities.
The current-head jobs are terminal, but older same-branch jobs remain running;
the source wave has not yet been uploaded. The explicit hosted-producer/report
validation and later focused-workflow pin update remain in the order above.

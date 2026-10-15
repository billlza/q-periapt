# Current-source Rust CodeQL terminal timeout

The [CodeQL run](https://github.com/billlza/q-periapt/actions/runs/38692152632)
for source `9d396755c3f872d3a59932c6fe106b2b5e1b2e59` is now a terminal
failure: five language jobs succeed; Rust fails. Rust Analyze runs from
06:33:48 to 11:33:48 UTC on 15 October 2026 and reaches its 300-minute limit.
The subsequent quality gate and Rust SARIF upload do not complete. This is not
accepted current-source Rust analysis.

The retained progress sequence contains all 39 query starts and exactly 38
completion markers. The last of those completes at 06:45:40, about 6 minutes
23 seconds into evaluation. The sole unfinished query is full `SummaryStats`;
`SummaryStatsReduced` completes. Progress markers are not a verified complete
BQRS result set. The action uses CLI 2.27.1, Rust queries 0.1.43, four threads,
`--ram=14575` and `--expect-discarded-cache`.

The pinned upstream [full summary query](https://github.com/github/codeql/blob/codeql-cli/v2.27.1/rust/ql/src/queries/summary/SummaryStats.ql)
includes taint statistics in addition to extraction/consistency metrics. Its
[TaintReach configuration](https://github.com/github/codeql/blob/codeql-cli/v2.27.1/rust/ql/src/queries/summary/TaintReach.qll)
computes reachability from active modeled sources to every dataflow node.
The fetched full/reduced query text hashes match the retained query manifest.
This explains a broader computation than the individual security queries; it
does not prove a specific setting will make it finish.

At 11:33:52, the post-action database bundle fails because the IMB cache is still
locked by another process. The debug dump contains evaluator cache-eviction
activity through 11:36:26, after Analyze has timed out. The action falls back to
a partial database ZIP, retained in artifact `11969826027` (749,225,094 bytes).
That artifact was not downloaded or its database metadata inspected in this
checkpoint. The generic partial-bundle message is not treated as evidence that
the underlying database was unfinalized. Child cleanup and query completion
are distinct problems; fixing cleanup alone would not pass analysis.

Earlier allocation, reusable-cache and single-thread controls did not complete
full `SummaryStats`. Their older frozen database remains a separate experiment,
not qualification for this source. No resource setting is adopted on the basis
of eviction counts, and no query, threat model, source census, quality assertion
or timeout is relaxed. No new workflow run is started here.

The contemporaneous [push CI](https://github.com/billlza/q-periapt/actions/runs/38692135318)
and [PR CI](https://github.com/billlza/q-periapt/actions/runs/38692152702)
each have 44 of 51 jobs successful, with the remaining seven macOS jobs queued.
Those runs are preserved. A documentation-only push would not address the
Rust query failure and could cancel these outstanding qualifications.

The full Rust job log is 609,823,885 bytes. Bounded explicit byte-range requests
retain the timeout window, tail and evaluator samples locally with ETag,
length and SHA-256 checks. The initial suffix-range request received HTTP 200
and stopped before reading its body; explicit start/end requests returned 206.
The [Azure range documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-the-range-header-for-blob-service-operations)
describes the supported forms. No full log or 749 MB artifact download was
needed. Tokens and signed URLs are kept only in memory; publication includes
selected diagnostic lines and range identities, not bulk raw logs.

`CAPTURE.zip` contains **31 members**, SHA-256
`c9aa78f7595bd58eaceb713f8b181c2e6c35648a486d7b42d39f47c2f2749504`.
`CAPTURE.json` and `READBACK.json` bind API snapshots, selected diagnostics,
retrieval recipes and unchanged workflow/quality sources. This supersedes
earlier observations that this CodeQL run was still active. It does not close
the Rust CI or release gate.

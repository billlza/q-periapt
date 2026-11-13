# Current PR and CI evidence

GitHub connector reads on 2026-11-04 confirmed PR #117 at `475cd239` and PR #118
at `6084f3bf`. No successor commit or run was found for either HEAD in the 09:02
UTC refresh. No workflow was started, rerun or cancelled, and no branch was
uploaded during this observation.

The original `INDEX.json` and job snapshots record the 08:31–08:35 observation.
`refresh-0842/INDEX.json` covers an intermediate subset. The latest complete
current-HEAD inventory is [`refresh-0902/INDEX.json`](refresh-0902/INDEX.json):
316 generated jobs across twelve runs, with 201 successful, 79 queued,
35 in progress and one failure. Every jobs response was requested with
`per_page=100` and checked against its `total_count`; pending dependency jobs
are not assumed to exist or to have passed.

`CAPTURE.zip` preserves all 53 original JSON/log members byte-for-byte, including
the per-job records referenced by the indexes. `ARCHIVE.json` records their
hashes and the archive identity. Compact indexes, the current failure log and
the original SDK ZIP remain directly accessible beside the archive; duplicate
expanded snapshots were removed only after full archive readback.

Three `continuity-installed-rust` jobs are running (#117 push/PR and #118 push).
The #118 PR counterpart has not yet been generated. Ubuntu reference account
validation is successful for the current #118 HEAD, including Debug, Release
and native signers; the remaining platform work is not inferred from it.
The latest independent workflow remains at `adaaeb49`: Ubuntu source and
installed-wheel jobs have passed, while both Apple Silicon jobs are queued.
Its Rust counterpart was source-built; it is not an installed-Rust result or
a `6084f3bf` run.

The one new failure is
[job 126463649767](https://github.com/billlza/q-periapt/actions/runs/41791854684/job/126463649767),
Linux policy-maintenance-package. Step 5 failed while listing/downloading
`rust-sdk-package` with `ECONNRESET`, before the product validation command.
Step 7 then failed because no package evidence existed to upload. The complete
log and step state are retained in `refresh-0902`. This establishes a transport
failure before execution; the endpoint-level cause of the reset is not known.
The SDK artifact exists and had already been downloaded successfully through
the connector. After the current wave is terminal, the bounded recovery is one
rerun of this specific job with the same inputs and original limits. A repeated
failure requires investigation, not an automatic retry loop.

Eight predecessor failure logs from `27463cdf` also remain retained: seven
formatting gates and one directory ledger fixture failure. The latter produced
eight `protected database inode changed` errors. The private canonical fixture
repair and current directory/Ubuntu reference passes are separate evidence;
remaining platform execution is still open.

`rust-sdk-package-6084f3bf.zip` is the original artifact `13304914186` from
run `41791854684`, successful producer job `126446831250`. Its SHA-256 is
`342d7db5d8d180eb395517a76576f3be4850193758186cd5866f5c0361a44e54`.
Its package report identifies the same clean source commit and workspace digest;
the selected installed C/OpenSSL regression verifies the exact consumed archives
against those sources. The initial and refreshed hash inventories retain the
observation boundaries rather than replacing an earlier result with a later one.

The next upload remains gated on the current wave ending and actual failures
being resolved. Local P0/P2 tests and symbolic replay do not turn pending or
failed hosted jobs into passes or qualify the overall release.

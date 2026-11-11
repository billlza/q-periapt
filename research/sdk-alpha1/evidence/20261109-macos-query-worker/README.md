# macOS extraction with a Linux full-query worker

This repair is based on PR124 commit
`a381f0803691238d90ad63f958a163bcbeaf7b54`. Its nine source files were
validated as code tree `d3a006ece048b8949329447cbec7cce6463518cb` before
the evidence files in this directory were added.

## Observed problem and change

The macOS job in run `42507570881`, job `128813668143`, extracted the native
`aarch64-apple-darwin` database and started all 39 pinned security queries.
Thirty-eight completed; `queries/summary/SummaryStats.ql` remained when the
18,000-second command budget expired. The timeout receipt records
18,001.218615 seconds and unambiguous cleanup. The origin workflow head is
`358b921ab3469ce49f166633fc9a762ff6ed7e3d`; the actual analyzed checkout is
`f99a1100a74a10cb649a6f2a5fc61430f1174436`. See
`MACOS_QUERY_EVIDENCE.json`, `COMPATIBILITY.json`, and `ORIGIN_JOB.json`.

The workflow now prepares and exports this database on macOS, then imports it
for the same full 39-query analysis on an ordinary Ubuntu worker. Native and
WASM worker behavior is retained. The macOS origin compiler, target, source
hashes and extraction quality remain recorded in immutable schema-1
`PROFILE.json`. Schema-2 `ANALYSIS.json` records the Linux analysis host,
resources, source, run and attempt separately.

The prepare job exports the transfer manifest digest and origin attempt as
job outputs. Import and publication both require these independent anchors;
the manifest binds the database archive, its inventory, and the origin
evidence files. Archive bounds, paths and file types are checked before the
CLI imports it. Fresh exports exclude results, logs, temporary files and
query caches. The attempt relation is
`origin_attempt <= analysis_attempt <= publication_attempt`, and the selected
profile artifact name must match the actual analysis attempt. Publication
selects the latest artifact before validation, so a newer failed result does
not fall back to an older success.

Only the publication job has `security-events: write`. It depends on native,
WASM, macOS preparation and macOS analysis. The existing full query inventory,
`SummaryStats`, result census, source/compiler identity, macro coverage and
target-specific SARIF categories remain required.

## Executed validation

`VALIDATION.json`, `combined.stdout`, and `combined.stderr` record **160 tests
passed, with zero failures, errors or skips**, using canonical CPython 3.12.3
through `artifact/python-run.sh`. The tests ran in an independent checkout
with a real `.git` directory, an index matching the code tree above, and no
unstaged changes. The receipt binds all nine source files and both raw logs.
The command covers quality, consumer context, target coverage, compiler
sources, Cargo metadata, profile, publication, transfer, workflow wiring,
documentation, and the repository's Python and strict-JSON policies.

`FINAL_CANDIDATE_REVIEW.json`, `PRODUCER_TRANSFER_INDEPENDENT_REVIEW.json`, and
`MACOS_PUBLICATION_INDEPENDENT_REVIEW.json` retain the separate implementation
and review observations. Their recorded executions and review ownership are
kept distinct from the combined 160-test run.

The retained historical macOS database was also exercised with the pinned
Linux CodeQL 2.27.2 CLI:

| Check | Observed result | Receipt |
|---|---|---|
| Source archive against the origin Git commit | All 1,173 Rust source paths matched | `SOURCE_ARCHIVE_CHECK.json` |
| Fresh origin-bound `ExtractedPaths` query | 1,173 rows, equal to the macOS-origin result | `FRESH_QUALITY_QUERY.json` |
| Fresh pinned diagnostic query and SARIF interpretation | Repository-relative source locations and the macOS target category | `SARIF_PORTABILITY.json` |
| Exact extraction-only bundle flags | Archive admitted by the transfer helper; excluded result/log/temp/cache entries absent | `RETAINED_EXTRACTION_ONLY_BUNDLE-20261109T0110Z.json` |

These executions establish compatibility for importing the real macOS-origin
database, querying it on Linux, and associating its emitted source locations.
The new hosted full 39-query run is recorded separately when it executes.

## Retained checkpoint and integrity

The current clean checkpoint is **191,772,849 bytes**, with SHA-256
`d358085631eff6a2e072e59a448a3b9ce9f9e8760523bd7cbec37be1b0a73362`.
Its 997 members were produced by a fresh unbundle of the retained original
database followed by the exact export flags. The source archive, database
metadata and Rust schema have the same hashes as the original. The new bundle
receipt, complete member manifest and `RETAINED_BUNDLE_POSTPROCESS_VALIDATION.json`
retain that identity and the subsequent independent CRC/hash check. The large
ZIP is retained in the research delivery, outside Git.

The initial compatibility probe also created an earlier 175 MB checkpoint.
Its initial receipt is preserved in `EXTRACTION_ONLY_BUNDLE.json`; a later
local read found that file truncated. `BUNDLE_RETRY_INPUT_FAILURE.json` and the
new retained-bundle receipt record that observation and the replacement. The
current checkpoint above comes from the original verified database. This
distinction preserves the scope of the earlier review without reassigning its
old hash to the replacement.

`SHA256SUMS.json` covers every file in this evidence directory except itself.

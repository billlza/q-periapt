# Recovery of the retained WASM query logs

The recovery workflow selects only artifact `13609897355` from CodeQL run
`42439010975`, with its exact 600,073,757-byte length and SHA-256
`68fc0a7e8f3fc02d9f072acc7eaa457d8e9174ab597d888ca632330ea6ba86c9`.
That archive belongs to analyzed merge
`cf5bf0195936c2f38197aa571c452a216c757abe` for integration head
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9`. The connector's 536,870,912-byte
download limit prevented direct access to this archive's individual query logs.

`codeql-log-recovery.yml` performs a recovery-only job on changes to its three
files in `integration/sdk-020`. Its token has read access to source and Actions
artifacts. The script sends the bearer token only to the fixed GitHub API
endpoint; a new unauthenticated request retrieves the signed HTTPS URL. Neither
credentials nor signed URLs are retained in receipts.

The script validates the complete archive identity and member inventory, then
streams only `qperiapt-codeql-database/rust/log/` members into deterministic gzip
files. The database archive is neither extracted nor opened. File paths,
regular-file types, encoding, duplicate names, declared lengths, CRCs, line
length, elapsed time and output sizes have explicit bounds. Complete raw-log
SHA-256 values accompany query-progress, TaintReach-iteration and cache-eviction
summaries. Summaries label omitted/clipped notes; the gzip files retain the
complete admitted log bytes. The maximum compressed raw-log output is 400 MiB,
with separately bounded summaries, allowing the result to fit the download
interface. A failed bound remains a failed recovery and produces no partial
gzip presented as a complete log.

This workflow performs no CodeQL evaluation and publishes no SARIF. The frozen
older evaluator-control experiment is unchanged. Its receipt distinguishes
diagnostic recovery from analysis completion.

## Local validation and source-matched prior evidence

All 15 recovery tests pass. They exercise archive identity, traversal/link and
duplicate rejection, CRC corruption, memory/time/output bounds, exact gzip
round trips, exclusion of the database member, token isolation and failure
receipt redaction.

A control replay used the separately downloaded prior artifact `13600568708`
from run `42436153297`, whose exact 17,818,662-byte ZIP SHA-256 is
`5c0208e7dacedf018a98a650e79b0b9d7ce9aec832ac2d1a40ed13bbb482e93e`.
Only the in-process artifact identity constants were substituted for this
control; the committed recovery script remains pinned to the current artifact.
The control recovered all 12 logs, totaling 334,072,945 raw bytes, into
17,696,116 gzip bytes. Every recovered gzip was independently decompressed and
its SHA-256 compared with the raw-log digest. The measured process peak RSS was
21,392 KiB, and recovery plus round-trip verification took 8.49 seconds.
`LOG_RECOVERY_CONTROL.json` binds these observations to the script hash.

The prior final evaluator log records 39 query starts and 38 completions, with
SummaryStats still evaluating at TaintReach Stage 3, iteration 444, when the log
ends at 02:33:16 UTC. It records 513 cache-eviction pauses. Prior profile artifact
`13601090631` and current profile artifact `13610185661` contain identical
inventories for all 1,173 tracked Rust source hashes, 328 compiled-source
hashes and all 39 query hashes. Both use CLI 2.27.2, Rust 1.98.1, four evaluator
threads and 14,000 MiB RAM. Their extracted database outputs differ. These are
source-matched prior observations; the current five-hour timeout's exact query
state will come from the recovery workflow, not from substituting this control.

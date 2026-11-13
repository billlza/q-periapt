# Fresh-result retention after interrupted CodeQL evaluation

The diagnostic controller now retains available fresh BQRS after evaluator
failure, before attempting bounded partial decoding. The original timeout or
nonzero exit remains the primary failure. These partial results stay separate
from the successful 39-query result map.

## Observed defect and scope

The two allocation arms in [run 42634713742](https://github.com/billlza/q-periapt/actions/runs/42634713742)
each reached the 18,000-second evaluator limit with 38 query-completion events.
Their authenticated artifacts retained 38 original reference BQRS and zero fresh
BQRS. The [read-only outcome record](../20261109-codeql-summary-control-outcome/README.md)
contains the artifact digests, original receipts, same-input checks, full query
inventory, and independent failed comparison.

The controller's evaluator wrote fresh output to `results/codeql/rust-queries/`.
The workflow uploaded `evidence/`. Previously, copying fresh BQRS into the upload
directory occurred only after successful evaluation. A timeout skipped that
path. The repaired failure path adds retention for subsequent runs; the previous
artifacts' missing fresh bytes are not reconstructed by this change.

## Behavior and bounds

The failure path visits only the 39 authenticated query-output paths and copies
all available stable regular-file snapshots before decoding any of them. It
records the SHA-256 and byte count of those same private copies. Symlinks,
changing files, and files over 64 MiB fail snapshot admission. Aggregate copy
data is limited to 512 MiB. Failed incomplete copies are removed, while admitted
copies remain available for upload.

Copying and decoding share a 120-second work budget. Each decoder gets the
remaining whole seconds and the existing supervisor's bounded shutdown.
Unattempted decodes remain labeled `not_attempted`; attempted failures retain
their raw BQRS, bounded output streams, and typed failure. Successful decoding
uses the existing semantic normalization and records agreement or mismatch with
the corresponding retained reference. Ambiguous evaluator cleanup skips
capture; ambiguous decoder cleanup stops additional decoders.

`PARTIAL_RESULTS.json` and `RESULT.json.partial_results` distinguish captured,
missing, rejected, decoded, and unattempted queries. Even a full set of captured
BQRS has `analysis_completed: false` in this failure-only record. The original
failure survives a secondary retention error. The full comparison still
requires successful evaluation and all 39 fresh results, with semantic equality
across arms and against the original 38 references.

## Verification

The original suite passed 80/80; the revised suite passed 92/92. The 12 added
regressions cover real child timeout and nonzero exit, real decoder timeout,
copy-before-decode ordering, source replacement after snapshotting, partial
semantic mismatch, malformed decoding, symlink/size/aggregate-byte rejection,
old-result exclusion, ambiguous cleanup, secondary-error preservation, and
complete-comparator rejection. An independent review reran five critical
regressions successfully. Exact counts, durations, and logs are in
`REGRESSION.json`.

The local BQRS and successful decoder outputs are explicitly synthetic fixtures.
The process supervisor, file snapshots, hashes, receipts, and timeout stream
retention are exercised directly. Hosted Rust query evaluation remains the
source of the separate historical outcome evidence.

`SOURCE_BINDING.json` verifies every restored baseline runtime file against tree
`05c75d9d5848814a8b6b988df5e0c1240bec081a`. It also checks identical ASTs for the
full comparator, retained-result validator, query admission, evaluator command,
configuration, tool admission, and query supervisor. Every pre-existing top-level
constant is unchanged, including CLI 2.27.2, the 39-query inventory pins, memory
profiles, and the 18,000-second evaluator limit. The workflow and query manifest
are byte-identical. This change adds no RSS measurement or allocation experiment.

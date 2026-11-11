# SDK integration and independent Linux job queues

This packet records one metadata readback at **2026-11-11 15:41:43–15:41:44 UTC**. The selected fields, exact API resources and observation window are retained in four JSON files.

SDK integration ref `integration/sdk-020` points to [`75eda8f5`](https://github.com/billlza/q-periapt/commit/75eda8f54a721dbed16a0bed43cdc493c9071485). The complete comparison with qualified production source `b5185165283880527a54289b47397fde78ddf553` contains one descendant commit and exactly three modified Markdown files: `artifact/codeql_summary_projection.md`, `docs/SDK_0_2_RELEASE_READINESS.md`, and `docs/SDK_INTERNAL_REVIEW.md`. Code and workflow files are unchanged. `SOURCE_EQUIVALENCE.json` binds both trees and the exact changed-file census.

GitHub records [PR #169](https://github.com/billlza/q-periapt/pull/169) as merged at **15:38:00 UTC**. [PR #121](https://github.com/billlza/q-periapt/pull/121) remains open, with the new SDK head and a blocked merge state. The main ref remains `48d0fb9a5651b50494ec33d025dda52bd2ff5eae`. `REFERENCES.json` preserves the individual PR head/base and merge fields; the closed PR's saved base is kept separate from the current SDK branch ref.

## Observed scheduling

In [CodeQL run 43050342732](https://github.com/billlza/q-periapt/actions/runs/43050342732), both Linux Rust jobs had assigned runners and executed steps while the macOS jobs were still queued:

| Job | Job ID | Observed state |
| --- | --- | --- |
| Analyze Rust (native) | 130625390075 | In progress; runner assigned and steps executing |
| Analyze Rust (wasm) | 130625389933 | In progress; runner assigned and steps executing |
| Prepare Rust (macos) | 130625389506 | Queued; no runner assigned |
| Analyze (swift) | 130625389939 | Queued; no runner assigned |

This snapshot establishes that the Linux workers began without waiting for the queued macOS jobs. `CODEQL_JOBS.json` retains the relevant job and step states. GitHub supplies a `started_at` value even for queued placeholders, so execution is established from runner, status and step evidence together. The workflow-list aggregate still reported CodeQL as queued; that original value is preserved separately.

The exact-head run census contains nine workflows, including **one ordinary `ci.yml` run**, [43050342715](https://github.com/billlza/q-periapt/actions/runs/43050342715), triggered by PR #121, and zero ordinary push runs. JoC run [43050342735](https://github.com/billlza/q-periapt/actions/runs/43050342735) belongs to the same head. The returned total count fits the single 100-entry page; `WORKFLOW_RUNS.json` records the complete census.

This readback captures integration and queue independence. Complete current-target analysis and its elapsed time are determined by the subsequent execution receipts. The packet performs no tests, extraction, query execution, reruns or alert changes.

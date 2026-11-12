# CodeQL scheduling and evidence flow

## Automatic checks and explicit experiments

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `ci.yml` | All pull requests; pushes to `main`; tags; manual dispatch | Complete candidate and release checks. An integration branch with an open PR gets one automatic matrix for that revision. |
| `codeql.yml` | Pull requests into `main`; pushes to `main`; weekly schedule; manual dispatch | Current-source security analysis and Rust target coverage. |
| `codeql-summary-control.yml` | Manual dispatch with `none`, `all`, or `projection`; push to `diagnostic/codeql-summary-projection` selects `projection` | Two allocation arms over one fixed retained database, followed by complete-result comparison. |
| `codeql-memory-control.yml` | Manual dispatch | Retained-database evaluator allocation controls. |
| `codeql-log-recovery.yml` | Manual dispatch | Recover logs from the fixed historical artifact. |

The previous SDK head `4870db5eff0a611973a302f29e94c0992df66cfe`
started both [CI run 42996581287](https://github.com/billlza/q-periapt/actions/runs/42996581287)
and [CI run 42996553264](https://github.com/billlza/q-periapt/actions/runs/42996553264).
The `integration/sdk-020` push and PR events selected the same full CI jobs;
their event-specific concurrency groups allowed both matrices to run.
Removing that push subscription preserves every job and required context,
the PR merge checkout, and independent checks of the eventual `main` commit.
Production CodeQL already used the separate PR/main trigger policy.

Production jobs now queue independently by language or Rust target. The key
contains the workflow and PR/main ref, plus the job and its matrix dimension.
Each group retains its running analysis and the newest pending revision with
`cancel-in-progress: false`. An old Swift or macOS wait therefore does not hold
the Linux language and target queues. The publication dependency still joins
only the three target results from its own workflow and source revision. See
[job concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

Updating `diagnostic/codeql-summary-projection` is an explicit request to run
the retained projection experiment. It is a launch ref, not a development or
candidate branch. The older cache/joins diagnostic refs no longer start
experiments on push. This dedicated entry point also supports publishing
clients without a dispatch capability. Once dispatch is available, an
authenticated operator can select the exact experiment revision and mode:

```sh
gh workflow run codeql-summary-control.yml \
  --ref <experiment-ref> -f summary_plan_mode=projection
```

GitHub documents the default-branch requirement for the web dispatch button
and API/CLI dispatch against a selected ref after a workflow has run. See
[workflow dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).
The push entry point is fixed to one ref and one mode; a mode is never inferred
from an ordinary SDK or PR branch name.

## Responsibilities and completion

| Component | Responsibility |
| --- | --- |
| `codeql_rust_profile.py` | Compile and extract each current Rust target, validate active source and macro coverage, resolve the pinned suite, execute all 39 queries, and bind the complete results to source, target, tool, memory policy, and workflow identity. |
| `codeql_rust_plan.py` | Restore the authenticated private runtime, install the fixed projection, assemble the full analysis command and bind before/after plan, runtime, database and evaluator identities into production receipts. |
| `codeql_evaluator_logs.py` | Read bounded evaluator logs for production and diagnostic callers, and display distinct admitted query completions while preserving the original stderr bytes. |
| `codeql_rust_transfer.py` | Seal the pending native macOS extraction for its Linux query worker, verify the archive and source identities, and exclude previous query results and quality receipts from that transfer. |

| `codeql_rust_publication.py` | Validate all three profile receipts, paired target coverage, complete query inventories, and SARIF identities before publishing the established Rust categories. |
| `codeql_summary_control.py` | Restore the exact retained database and verified cache, run fresh results in both allocation arms, and compare complete semantic results under an explicitly selected plan mode. |
| `codeql_summary_plan.py` / `codeql_summary_projection.py` | Admit the fixed capsules and verify the effective plan and source/dependency identities. Production and diagnostic callers retain their own execution and result contracts. |

The macOS origin compiles and extracts with its native toolchain, then seals
`EXTRACTION_INPUTS.json` with quality still pending. Transfer schema 2 binds that
record and the database to the origin job output. After import, Linux runs the
unchanged `ExtractedPaths`, `Metrics`, and `MacroCalls` queries with 4 threads and
14,000 MB. Only successful extraction and active macro coverage checks create
`PROFILE.json`; it retains the native compiler identity and separately records
the Linux quality host, budget, attempt, and exact extraction-input digest.
Security analysis and publication both require that binding. A failed quality
query leaves the extraction pending and cannot produce an admitted profile.

Production publication depends on successful native, WASM, macOS extraction,
and macOS analysis jobs. GitHub's [`needs` semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idneeds)
prevent it from running after a failed producer. Publication then validates
the artifacts before any SARIF upload. A full SummaryStats result is part of
the 39-query completion requirement; 38 completed queries leave the analysis
incomplete. Diagnostic uploads run on failure so that query progress remains
available without changing that outcome.

The retained experiment uses the fixed `56f191f04a57806869b8a03078ee4d27ffe900ab`
database. Its cache is admitted by the existing exact inventory and hashes;
fresh BQRS outputs and semantic results are checked separately. Both arms
receive the same selected capsule, and the comparison uses the same explicit
mode. `projection` names a source transformation; the evaluator's dynamic join
setting remains `all`, so those two names must not be treated as interchangeable
experiment identities.

For a retained artifact already available locally, `run --retained-archive
/absolute/path/diagnostics.zip` selects that transport explicitly. The controller
authenticates the same outer and inner archive bytes and complete database,
cache, and retained-result inventory before use. A missing or altered local
archive ends the run without a network fallback. `SOURCE_TRANSPORT.json`
records the chosen transport and admitted input identity; it does not change
the allocation budget or qualify an analysis as complete.

A successful allocation comparison certifies complete equivalent results for
that fixed database and selected plan. Production selects the fixed Stage3 and
Stage4 projection on the current target extractions, using the same 39 root
queries and explicit plan mode at analysis and publication. The effective
source, complete runtime, actual evaluator command and memory allocation are
bound to the current profile and publication receipts. Details of the
transformation and production admission are in
[the projection record](codeql_summary_projection.md).

The normal extractor also loads the 68 authenticated partial Rust snapshots
into its file view while retaining their non-module status. This repairs the
recorded manifest-loading warnings without changing the complete source or
diagnostic checks; [the archive record](CODEQL_RUST_ARCHIVES.md) explains the
input identity and fixed-version extractor behavior.

## Reading long-running command evidence

Each profile command writes `<label>.started.json` immediately before invoking
the bounded subprocess supervisor. It records the UTC invocation time, selected
argv and directory, time bound, source commit, run ID, and attempt. The same
timestamp is included in `<label>.json` when the supervisor returns or reports
a bounded failure, together with the finish time and measured elapsed time.
Raw stdout and stderr continue to stream into their existing files.

An invocation receipt identifies an entered command, not a completed query.
Its timestamp precedes supervisor setup and is not the subprocess's exact
deadline; an Actions step timestamp may precede it by substantially more.
Completion is established by the existing analysis and publication receipts.
If a worker is killed before it writes a final receipt, the start record and
streamed logs preserve the last observed state.

The focused scheduling contracts are in `test_codeql_workflow_contract.py`
and are discovered by the ordinary CI artifact test step. Existing profile,
publication, transfer, and summary-controller tests exercise incomplete
results, source binding, target identity, and failure propagation.

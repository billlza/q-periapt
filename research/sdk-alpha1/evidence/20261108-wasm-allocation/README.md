# Linux query allocation and Rust analysis category continuity

Recorded on 2026-11-08. The current candidate builds on integration head
`358b921ab3469ce49f166633fc9a762ff6ed7e3d`; each experiment below identifies
its exact checked-out source or retained database separately.

## Completed retained-database evaluation

The `native-heavy` arm of [run 42511575195](https://github.com/billlza/q-periapt/actions/runs/42511575195)
completed every one of the 39 pinned queries, including `SummaryStats.ql`.
Its evaluator returned zero after **11,138.785639223 seconds**. The query log
records `SummaryStats.ql` completing in **183m50s** and the result census reaching
39/39. All 39 BQRS digests and decoded semantic digests are in
`NATIVE_HEAVY_RESULT.json`.

The input is the retained WASM database from head
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9`, analyzed commit
`cf5bf0195936c2f38197aa571c452a216c757abe`. The diagnostic code is
`6ec4d7824cada30bdc4bdb6867fd00a0e34d9731`. Its allocation was a 3,072-MB
Java heap and 9,329-MB native budget, with four threads and an 18,000-second
outer evaluator deadline. The database, bundled cache, 39 query sources,
compiled query plans, tool bundle and fresh result inventory have explicit
identities in the retained result.

The completed job is `128825576664`, and its evidence artifact is
`13635504402`: 14,211,267 bytes, SHA-256
`f15e8c933c67430e4f9bb05db6d5dc5f3ae948d9bb3926a781f8e4b7c2405089`.
The downloaded archive matched both this digest and the service metadata.
`HOSTED_OBSERVATION.json` records the baseline job still evaluating at this
observation. The paired comparison will be reported from both final receipts;
this observation supplies the candidate's complete evaluation result.

## Production candidate

The native Linux and WASM calls keep `codeql database analyze`, the pinned
security-extended suite, `--ram=14000`, four threads, `--threat-model=local`,
and the five-hour deadline. Both Linux profiles add
**`--off-heap-ram=9329`**. Apple Silicon retains its existing 5,500-MB
automatic allocation. The native Linux extension follows the two complete
hosted timeout receipts described below.

Before evaluation, the same pinned CLI runs `resolve ram` against the current
`db-rust` dataset with these exact high-level memory options.
`QUERY_MEMORY.json` records the resulting heap, native allocation, and their
arithmetic difference from the requested total. These fields describe
configuration; resident memory and operating-system headroom are separate
measurements. CodeQL's dataset-aware overhead calculation can produce a heap
different from the diagnostic's explicit 3,072-MB heap. The adapter records
that result directly.

The completion record binds the memory receipt's SHA-256. The publication
validator checks that binding, the fixed Linux native allocation, the typed
receipt fields, the expected profile, and the total budget. Every previous full-query, extraction,
macro-coverage, source-identity and SARIF qualification check remains active.
An invalid resolver result, missing full-summary BQRS, or changed memory
receipt rejects completion/publication. Production acceptance follows the
complete hosted run on the updated source and its existing three-profile
publication gate.

## Actual CLI propagation check

The exact official Rust bundle used by the diagnostic was downloaded and
verified: 98,247,028 bytes, SHA-256
`acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea`.
The executable is CodeQL 2.27.2 and the query pack is `rust-queries` 0.1.44.

A synthetic one-file Rust TRAP fixture was created through `database init`,
populated with one `files()` tuple and a source archive, and completed through
`database finalize --no-pre-finalize`. Two independent copies were evaluated
through the unchanged high-level `database analyze` command. Both ran the
complete 39-query suite, produced SARIF under `/language:rust/target:wasm/`,
and decoded all 39 results to equal canonical semantics.

| Fixture case | `resolve ram` | Actual child evaluator |
| --- | --- | --- |
| Existing 14,000-MB request | heap 5,768 / native 6,870 MB | identical |
| 14,000-MB request plus native 9,329 MB | heap 3,584 / native 9,329 MB | identical |

`CLI_HIGH_LEVEL_CONTROL.json` retains the exact high-level options, observed
child commands, all result digests and tool identities. This fixture exercises
parameter propagation and result interpretation. The full retained WASM
evaluation above supplies the repository-scale completion observation.

`executed_cli_probe.py` is the exact script retained from that local control.
It expects the recorded scratch layout: a verified bundle at
`tool/codeql`, the finalized fixture at `cli-propagation/minimal-database`,
and the query manifest in the sibling `qperiapt-ci-memory/artifact`
directory. Its output is a fresh `high-level-control` directory. The fixture
contains the source text `pub fn allocation_probe() -> u32 { 1 }` and one
`files()` TRAP tuple for that file. The fixture's metadata digest is bound in
the receipt; its absolute source prefix and creation time belong to this run.

## Why the full summary dominates

The pinned [SummaryStats.ql](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/SummaryStats.ql)
includes `taintStats`. Its [TaintReach configuration](https://github.com/github/codeql/blob/codeql-cli/v2.27.2/rust/ql/src/queries/summary/TaintReach.qll)
starts from every active threat-model source and treats every node as a sink.
It therefore evaluates broad global taint reach and counts reached nodes.
The reduced summary selects extraction and inconsistency statistics.
`UPSTREAM_QUERY_SOURCES.json` binds this explanation to the actual bundle's
four relevant source files. Both summary queries remain in the pinned suite;
the allocation change preserves their original contents and the full result
census. The project-specific `codeql-rust-quality/Metrics.ql` performs its
existing extraction, macro and consistency checks before the security suite.

The official [RAM resolver documentation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/resolve-ram)
describes dataset-aware heap/native options. The exact 2.27.2 `database analyze
--help -vv` also exposes `--off-heap-ram`; the actual-child check above confirms
its propagation in this bundle.

## Initial allocation validation

The initial allocation change, published in
`d42e7f64d5e5556e90bafc5236243cbd29bc4564`, completed **98 tests with
zero failures, errors or skips**. `LOCAL_VALIDATION.json` binds that command,
code-file hashes and raw output. Cases include native/macOS policy preservation,
invalid and default allocations, resolver failure, altered typed receipts,
WASM full-suite completion, omission of `SummaryStats.ql`, and memory-receipt
binding at publication. The first linked-worktree attempt preserved the
existing `.git`-directory policy; the full successful run used an independent
copy of the original directory-based Git checkout.

## Rust analysis category continuity

PR #121's [CodeQL check 128817368077](https://github.com/billlza/q-periapt/runs/128817368077)
reported `1 configuration not found` for main's `/language:rust` analysis.
The old workflow used that category for its Ubuntu Rust analysis. The new
three-profile workflow had named every result `/language:rust/target:<profile>`;
finishing those jobs would not itself publish the old category.

The native Linux profile now continues **`/language:rust`**. WASM and macOS keep
**`/language:rust/target:wasm`** and **`/language:rust/target:macos`**. The analyzer
and strict SARIF validator use one profile-to-category function, and the
workflow uploads each corresponding SARIF once. Explicit `profile`, `target`,
compiler host, source and compiled-source digests remain bound in the existing
profile evidence. At the category-continuity revision, the publication
validator was byte-for-byte unchanged from the initial allocation patch. Full query, extraction and paired macro-coverage gates
continue to apply to all three profiles.

GitHub's [analysis-category documentation](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options#analysis-category)
ties an explicit category to SARIF `automationDetails.id` and preserves an
identity already present in the file. The repair therefore changes native
generation, validation and upload together. The original failed check remains
recorded in `CATEGORY_MIGRATION.json`; this change supplies the compatible
identity for subsequent completed publication.

The category-continuity source passed **101 tests with zero failures, errors or skips** in
the same four regression modules. `CATEGORY_VALIDATION.json` binds all five
relevant code/workflow files and the test output. The new controls verify
category selection for every profile, reject other targets even after a
changed SARIF digest is rebound, and require exactly one corresponding upload
per profile. The full-suite analysis controls retain rejection of missing
`SummaryStats.ql` results for native, WASM and macOS. The unchanged WASM memory
receipt checks remain covered. `CATEGORY_REVIEW.json` records the independent
source review of these same bytes.

The production patch and these receipts remain a candidate until the updated
hosted workflow completes. The diagnostic branch and its running baseline
keep their original immutable inputs.

## Complete-workflow category regression

The two full CI jobs on `4854acd800f51955de4a4b9a6dbb12ff1acf6247`
each ran 3,494 tests and reported one failure: the repository-wide workflow
wiring test still expected the superseded `/language:rust/target:native`
upload category. `GLOBAL_CATEGORY_FAILURES.json` binds the exact jobs and
their complete log digests.

That test now uses an explicit category for each of the three profiles and
matches the entire category line. In particular, accepting `/language:rust`
cannot accidentally accept an added `/target:native` suffix. Three mutation
controls exercise the full wiring gate with the native suffix restored,
WASM aliased to native, and macOS aliased to WASM; each is rejected.
`GLOBAL_CATEGORY_VALIDATION.json` records both passing tests and the three
negative mutations. The production workflow and analysis/publication code
are unchanged by this correction, and their previously recorded 101-test
validation retains its original source identity.


## Linux allocation extension after full hosted evaluation

The original three-profile run
[42507570881](https://github.com/billlza/q-periapt/actions/runs/42507570881)
checked out PR merge commit `f99a1100a74a10cb649a6f2a5fc61430f1174436`
from integration head `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. Native
Linux job `128813667918` and WASM job `128813667753` each completed 38 of
39 queries and reached the 18,000-second boundary in the full
`SummaryStats.ql` query. Both passed the active-target extraction quality
gate, with zero extraction errors and warnings. Both used an observed
5,668-MB Java heap and 6,733-MB off-heap allocation. Their final logs record
repeated eviction of approximately 207–210 MiB cache arrays.

`LINUX_HOSTED_TIMEOUTS.json` binds the final job observations, artifact
digests, result census, memory arguments and log excerpts. Each of the 1,173
source entries was compared against the actual merge commit, and all 39
query identities matched the pinned manifest. This establishes the same
full-summary timeout condition for both Linux profiles. The retained WASM
database experiment above supplies the completed candidate observation on
its separately identified input.

The extension uses the same dataset-aware resolver and 9,329-MB off-heap
policy for native Linux and WASM. Receipts carry their actual profile;
publication rejects a native receipt substituted for WASM or the reverse.
`LINUX_ALLOCATION_VALIDATION.json` records **104 passing tests**, zero
failures, errors or skips, including the global category regression and
three category mutation controls. `VALIDATION_SOURCES.json` binds all
513 source/configuration files used by this validation, unchanged between
the beginning and end of execution. The earlier 98-test, 101-test and
two-test receipts remain records of their respective earlier revisions.

`NATIVE_CLI_PROPAGATION.json` records an additional execution through the
actual CodeQL 2.27.2 native high-level command on the one-file TRAP fixture.
All 39 queries completed in 9.198 seconds; the observed child evaluator
used heap 3,584 MB and off-heap 9,329 MB, matching `resolve ram`, and the
SARIF automation id was `/language:rust/`. `executed_native_probe.py`
retains the executed script. This is a parameter propagation check; the
updated repository-scale runs provide the full-source completion result.
The verbatim CLI child log uses the execution host's offset clock; the
validation receipt records the actual UTC observation.

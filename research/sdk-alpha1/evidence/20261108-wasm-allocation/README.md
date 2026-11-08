# WASM query allocation: completed diagnostic and production candidate

Recorded on 2026-11-08 against integration source
`358b921ab3469ce49f166633fc9a762ff6ed7e3d`.

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

The WASM call keeps `codeql database analyze`, the pinned security-extended
suite, `--ram=14000`, four threads, `--threat-model=local`, and the five-hour
deadline. It adds **`--off-heap-ram=9329`** only for the WASM profile. Native
Linux and Apple Silicon retain their existing arguments.

Before evaluation, the same pinned CLI runs `resolve ram` against the current
`db-rust` dataset with these exact high-level memory options.
`QUERY_MEMORY.json` records the resulting heap, native allocation, and their
arithmetic difference from the requested total. These fields describe
configuration; resident memory and operating-system headroom are separate
measurements. CodeQL's dataset-aware overhead calculation can produce a heap
different from the diagnostic's explicit 3,072-MB heap. The adapter records
that result directly.

The completion record binds the memory receipt's SHA-256. The publication
validator checks that binding, the fixed WASM native allocation, the typed
receipt fields, and the total budget. Every previous full-query, extraction,
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

## Local validation

The four affected CodeQL modules' regression suites complete **98 tests with
zero failures, errors or skips**. `LOCAL_VALIDATION.json` binds the command,
code-file hashes and raw output. Cases include native/macOS policy preservation,
invalid and default allocations, resolver failure, altered typed receipts,
WASM full-suite completion, omission of `SummaryStats.ql`, and memory-receipt
binding at publication. The first linked-worktree attempt preserved the
existing `.git`-directory policy; the full successful run used an independent
copy of the original directory-based Git checkout.

The production patch and these receipts remain a candidate until the updated
hosted workflow completes. The diagnostic branch and its running baseline
keep their original immutable inputs.

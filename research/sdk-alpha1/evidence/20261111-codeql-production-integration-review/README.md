# Production integration design for the admitted SummaryStats projection

## Decision and inspected boundary

The projection can enter the existing production `database analyze` path. Keep the current extraction, target-quality, transfer and publication ownership boundaries; introduce a private authenticated analysis runtime and query pack immediately before the existing analysis command. Retain the full 39-query suite, its SARIF interpretation, the three target categories and the single 18,000-second analysis supervisor.

This is a read-only implementation design for SDK commit `faabcff16fc49e1a99388c68f0991a2bfd64d509`, tree `b5c6e256b9abb95a8163efae052c34ae6bd0f035`. `READBACK.json` binds the inspected repository files, exact tool inputs and this review's scope. No production source was changed and no CodeQL, JVM, test, query or large download was started for this review. The Stage3+4 asset revision is being prepared independently; deployment must select its final repository manifest and capsule, rather than infer identity from the word `projection`.

## Current identities and the actual attachment point

| Component | Current production | Integration consequence |
| --- | --- | --- |
| Rust CLI and query pack | CodeQL 2.27.2 and `codeql/rust-queries` 0.1.44 | The version family matches the projection. |
| Production tool archives | Combined `codeql-bundle-linux64.tar.gz`; combined `codeql-bundle-osx64.tar.gz` for macOS extraction | These are not the authenticated Rust-only archive used to build and admit the projection. A same-version check does not establish identical archive bytes. |
| Projection tool archive | `codeql-bundle-rust-linux64.tar.zst`, 98,247,028 bytes, SHA-256 `acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea` | Use these exact bytes to create the private analysis runtime. |
| Analysis location | Linux for native, WASM and the transferred macOS database | One Linux private-runtime implementation covers all three analyzers. |
| Existing analysis budget | 4 threads, 14,000 MB requested total, 9,329 MB off-heap, one 18,000-second supervisor | Reuse `analysis_memory_arguments` and `QUERY_MEMORY.json`. Diagnostic arm allocations and the local probe budget are separate experiments. |
| Extraction tools | Fixed CodeQL paths in `codeql_rust_quality.py` | Leave their setup and strict path contracts intact. |
| Other language jobs | Separate CodeQL 2.27.1 path | Outside this Rust integration. |

The exact producer attachment is `codeql_rust_profile.py:analyze`, after `PROFILE.json`, expected commit/run/attempt, active-target quality and any macOS transfer anchor have passed. Extraction and `collect_quality` remain on the existing tool installation. Projection installation occurs on Linux after successful macOS import, so the exported extraction receipt continues to describe what actually happened on macOS.

There are two concrete reasons to use a private analysis runtime instead of merely changing the current setup URL or executable argument:

1. The pinned setup-codeql action accepts `.tar.zst`, but deliberately does not cache a single-language bundle in the normal toolcache. It extracts such a bundle into a UUID-named temporary directory. A local tarball also takes a temporary extraction path. Changing the setup URL to the Rust-only archive would therefore violate the current fixed CodeQL paths. `OFFICIAL_ACTION_READBACK.json` retains the relevant lines and whole-source hashes from action commit `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2`.
2. The exact official launcher accepts an inherited valid `CODEQL_DIST` and uses its `tools/codeql.jar`; `CODEQL_JAVA_HOME` can also select another JVM. Merely changing `argv[0]` while copying the full process environment can execute a different same-version distribution. The analysis child needs an environment allowlist, not the existing complete `dict(os.environ)` used for compiler preparation. Use task-specific `TMPDIR` and explicit `--common-caches`; do not assign or reset `HOME`. Clear inherited distribution/JVM option overrides and retain the validated runner identity fields needed by receipts and process cleanup.

## Keep database analyze and its interpretation semantics

Static inspection of the locally retained exact 2.27.2 `codeql.jar` establishes the wrapper route. In `AnalyzeCommand.executeSubcommand`, bytecode references at offsets 84 and 237 carry `CompilationOptions`; offsets 319–330 dispatch `RunQueriesCommand`. Its `executeSubcommand` passes compilation, evaluator, threat-model and rerun options to `ExecuteQueriesCommand` at offsets 179–285. `CompilationOptions` inherits `CoreCompilationOptions.dynamicJoinOptions`. `AnalyzeCommand.continueAfterRunningQueries` dispatches `InterpretResultsCommand` after query evaluation. `CLI_ROUTING.json` retains these references; the compressed full readback retains the surrounding static evidence and class hashes.

Consequently, the smallest production change keeps `database analyze`, adds the manifest's fixed dynamic-join option, and points the suite and runtime at the private admitted installation. It also records evaluator progress and applies the precompiled-load check to the actual execution. This static route inspection is not an end-to-end candidate analyze run; the remaining wrapper check is identified below.

Keeping this wrapper also preserves database-specific behavior that a direct plumbing replacement would need to reproduce. `RunQueriesCommand` consults database analysis configuration, extension packs, threat models and overlay state. The existing producer calls `database create` without an external analysis config, and the transfer seals the database archive. During integration, bind any effective database analysis/model-pack configuration and reject an unadmitted addition; do not silently bypass it by replacing the wrapper with direct `execute queries`. Retain `--threat-model=local`, `--no-download`, the current result layout and the existing SARIF interpretation options.

## Minimal implementation sequence

1. **Admit the existing extraction.** Reuse the current profile and transfer checks unchanged. Derive all new paths below the existing per-profile output directory; do not accept a caller-provided executable or pack search path.
2. **Create the private runtime from authenticated bytes.** Download or receive the exact Rust archive, take a descriptor-backed private snapshot using the existing evidence I/O primitives, verify size and SHA-256, and extract into an exclusively created owned directory. Do not hash one pathname and then extract a newly reopened pathname. Preserve legitimate official archive structure while preventing extraction outside the new directory. Retain the archive identity and actual launcher/runtime inventory in `ANALYSIS_TOOL.json`.
3. **Use the private runtime's own pack.** Its fixed internal path `qlpacks/codeql/rust-queries/0.1.44` already matches the installer and load-check conventions. It is a private copy of the official query pack, so a second mutable copy or a global toolcache mutation is unnecessary.
4. **Admit and install one explicit plan.** Reuse `codeql_summary_projection.install`, `validate`, `manifest` and `expected_identity`, including the original and effective 1,175-file dependency inventories, the one exact vendor patch, nine local support files, 39 root query sources, 38 unchanged upstream QLX files, the full SummaryStats compiler key and the closed capsule. Cross-bind tool archive/version/pack and the repository query-manifest hash before installation. Stage4 and Stage3+4 have distinct source/key/capsule identities even if the public selector remains `projection`.
5. **Freeze the 39-query selection.** Resolve and validate the existing security-extended suite against `codeql_rust_queries.json`, then generate a private suite of those exact absolute query paths. Record its digest and require the expected Rust result locations to be fresh. Do not remove or reuse a stale result tree as an implicit recovery. Existing custom quality-query results are a separate pack and remain available.
6. **Run the current analyzer under the current budget.** A resumed `ProfileRun` can use the private launcher and controlled analysis environment while retaining the fixed database/resources configuration, evidence directory and bounded command supervision. Keep the existing SARIF format, category, threat model, no-download setting and memory-resolution receipt. The plan supplies its exact dynamic-join mode. Record evaluator logs; require exactly the 39 admitted QLX paths and zero query-plan compilations, then the complete 39-query BQRS census. No success receipt is produced for a partial result set.
7. **Recheck before admitting publication.** After the supervised process has exited, rehash root sources and all effective QLX files, call the same plan `validate` on the private pack and verify the runtime binding. Perform this check in failure cleanup too, preserving the original evaluator failure alongside a secondary identity failure. Check the current SARIF and clean expected checkout as today.
8. **Bind small receipts into the existing publication chain.** A versioned analysis receipt binds tool identity, exact plan identity, before/after checks, query-load observation, command/configuration, profile, query inventory, memory, 39 BQRS digests and SARIF. The publisher independently checks the admitted constants, exact receipt digests, load/result census and target/run identities. Retain the full evaluator logs in the existing log artifact; include their byte counts and hashes in the small observation receipt. There is no requirement for native, WASM and macOS results to equal each other: their target databases intentionally differ.

## File ownership and existing functions to reuse

| File | Smallest responsibility |
| --- | --- |
| New `artifact/codeql_rust_plan.py` | Private analysis context, environment, authenticated runtime/pack admission, fixed plan selection and pre/post receipt validation. Keep these concerns outside the large experimental controller. |
| `artifact/codeql_rust_profile.py` | Select the private analysis context inside `analyze`, retain `ProfileRun.command`, `analysis_memory_arguments`, `validate_query_inventory` and `validate_sarif`, then bind new receipts into the analysis record. Keep prepare/export/import behavior. |
| `artifact/codeql_rust_publication.py` | Require the selected exact plan/tool and successful postcheck/load census before producing `PAIRED_QUALITY.json`; retain all current quality, source and SARIF gates. |
| `artifact/codeql_rust_transfer.py` | Reserve the new analysis-only receipt and command prefixes in `FORBIDDEN_EVIDENCE` / `_evidence_name`. The extraction transfer schema, archive and job-output anchor stay as they are. |
| `.github/workflows/codeql.yml` | Provide the exact analysis archive and explicit production plan selection, include the small new receipts and required module/tests in retention/checkouts, and preserve publication permissions and all three upload categories. |

The installer and capsule implementation already exist. `evidence_io.consume_regular_snapshot`, `read_regular_snapshot`, `parse_strict_json_bytes` and `fresh_output_directory` provide reusable file admission. The controller's `validate_plan_tool`, frozen-suite construction and bounded `evaluator_observations` logic provide the relevant generic patterns. If sharing requires extracting those few generic helpers, do it once into a small common module while leaving diagnostic `none`/`all` identities and comparison rules unchanged; do not copy the retained-database restoration, two-arm comparison or historical allocation logic into production.

`codeql_rust_quality.py`, `codeql_target_coverage.py` and the 39-query source manifest need no functional change for this attachment. Focused tests belong with the private context, profile/publication receipt cross-binding and the reserved transfer namespace. Existing installer controls already cover malformed capsules, wrong dependency/source identities and partial installation.

## Gates that remain in force

The three target profiles retain current source and compiled-source hashes, locked Cargo inputs, compiler identity, extraction census and macro quality, active-target validation, macOS transfer source/run/attempt anchoring, and the three-profile coverage check. Publication still selects the latest attempt for each profile and cannot substitute an older successful artifact for a newer failed attempt. All 39 pinned query roots, including full SummaryStats, remain required. The analyzer must complete successfully, produce all 39 current BQRS outputs and valid successful SARIF, and keep the three established categories. Only the paired publication job receives SARIF write permission.

The new receipt version should explicitly select either the old production identity or one admitted projection identity. It must not treat missing plan fields as projection success, accept a Stage4 receipt against a Stage3+4 manifest, or combine profiles from incompatible plan revisions. The rollout can update producer and publisher together in one commit; the existing source-commit requirement already prevents cross-commit artifact substitution.

## Remaining deployment inputs

The source projection proof, compiled plan structure, existing nonempty fixture results and explicit installer are already available. The immediate work depends on three concrete items: the independently prepared final Stage3+4 asset revision; the currently isolated large-database candidate run and its actual full-result/identity receipts; and one bounded end-to-end check of the existing `database analyze` wrapper on the already available small database, through SARIF and the updated publication contract. That last check resolves wrapper option propagation, QLX use and interpretation together; it does not require a new five-hour baseline.

The prior local Stage4 exit 137 occurred with overlapping compilation and has no observed kernel/cgroup cause. It provides resource-termination evidence, not a clean speed baseline. This design neither assigns that cause nor changes the production time/memory budget. Further evaluation is coordinated separately; this review ends with source and static routing evidence only.

## Primary source references

- Inspected repository revision: `billlza/q-periapt@faabcff16fc49e1a99388c68f0991a2bfd64d509`; per-file hashes and top-level definitions are in `READBACK.json`.
- [Pinned setup-codeql action metadata](https://github.com/github/codeql-action/blob/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2/setup-codeql/action.yml).
- [Pinned setup-codeql implementation](https://github.com/github/codeql-action/blob/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2/src/setup-codeql.ts), especially lines 922–930, 1,071–1,080 and 1,195–1,196.
- The exact locally retained official 2.27.2 launcher, jar and existing execute-help identities are bound in the readback records; no CLI invocation was needed to inspect them.

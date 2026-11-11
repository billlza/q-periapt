# Local database analyze fixture method

This directory prepares one end-to-end execution of the existing, nonempty
official Rust `dataflow/sources/env` fixture through CodeQL 2.27.2
`database analyze`. The method has not executed CodeQL. It is ready for the
exclusive large-database run to finish before the local execution is started.

The existing all, Stage4, and Stage3+Stage4 SummaryStats executions remain the
comparison inputs. Their complete decoded results contain 29 rows, including
15 active taint sources and 106 tainted nodes. This method reuses their saved
bytes and the original extracted database; it does not repeat extraction or
any baseline execution.

## Execution

The production integration checkout must be committed and clean, with the
Stage3+Stage4 admission assets and `codeql_rust_plan.py` present. Substitute its
complete commit identity below. The output directory must not already exist.

```sh
python /workspace/scratch/4b61438fb07b/summary-analyze-fixture-method/run_fixture.py \
  --execute \
  --repository /workspace/scratch/4b61438fb07b/summary-production-implementation \
  --source-commit <complete-final-commit> \
  --output /workspace/scratch/4b61438fb07b/summary-stage34-analyze-fixture
```

Without `--execute`, the script prints the declared method and starts no
external process. The execution path first rejects an active CodeQL JVM and
requires at least 7 GiB of available memory. It checks the retained archive and
initial database inventory, restores a private runtime through production's
`extract_runtime` helper from the exact official Rust archive, copies the
original database, and installs the fixed projection
into the runtime's actual embedded query pack. It writes a suite containing the
39 admitted root query paths. The resulting 1,357 query-pack files must exactly
match the already executed Stage3+Stage4 candidate.

`ProfileRun.command` supplies the existing bounded production command wrapper.
The fixture calls the real `database analyze` command and existing
`validate_sarif(..., "native")` contract, using its native category only to
exercise that validator. All receipts identify this as a local fixture. It
does not create a hosted `PROFILE.json` or `ANALYSIS.json`, upload SARIF, or
change a workflow or production default.

## Fixed local allocation

The analysis has one 600-second supervisor, one thread, 1,024 MiB of JVM heap,
and 4,096 MiB of native evaluator allocation. This is a local allocation,
separate from production's 14,000 MB total request and 9,329 MB off-heap setting.

`database analyze` normally resolves memory before starting its evaluator.
Static inspection of this exact official `ResolveRamCommand` shows that its
ordinary sizing path can revise both heap and off-heap requests. This local
method uses the existing explicit-Xmx measurement path:

```text
--ram=1024 --off-heap-ram=4096 --measure-ram=xmx
```

Before analysis, an actual `resolve ram` invocation must return exactly
`-J-Xmx1024M`, `--off-heap-ram=4096`, and `--measure-ram=xmx`. The analysis itself
also prints JVM flags. Its evaluator log must report the declared off-heap
allocation, and every observed JVM `MaxHeapSize` must be 1,073,741,824 bytes.
All flag lines remain in the original stdout; the observation receipt retains
each occurrence. The existing process-tree sampler additionally records actual
CodeQL JVM arguments with PID and process start identity, so wrapper, evaluator,
and interpretation processes can be distinguished in a pure readback. If the
wrapper exposes differing heap values, the first execution and all raw evidence
remain intact for a documented method correction.
The method stops on a resolution, parsing, or allocation mismatch and preserves
the raw diagnostics. It does not silently change options or retry with another
budget. A subsequent method revision would explicitly declare any changed
budget before execution.

`MEMORY_ROUTING_READBACK.json` retains the class hash, method bytecode, constants
and calls supporting this choice. The inspection reads the official JAR with
Python; it does not start a JVM.

## Database inputs

The private copy must match all 6,651 original extracted files. The shared
accepted database is checked again after execution. The production
`admit_database` helper checks both metadata and additional analysis inputs.

Exact-version class inspection identifies the configuration locations that the
wrapper reads:

| Input | Location relative to the database |
| --- | --- |
| Analysis configuration | `temp/analysisConfig.json` |
| Legacy extension-pack configuration | `temp/extensionPacks.json` |
| Generated query suite | `temp/config-queries.qls` |
| Overlay metadata | `overlay-base-metadata` |
| Overlay path mapping | `overlay-path-transformer` |
| Overlay scratch | `working/overlay` |

The accepted fixture has no such inputs and has both overlay flags set to
false. The method rejects an unadmitted addition instead of overriding it with
a CLI option. `DATABASE_CONFIG_READBACK.json` preserves the direct calls:
`getTemporaryFolder()` returns `dbRoot/temp`, while `getScratchFolder()` returns
`dbRoot/working`. `RunQueriesCommand` passes the temporary folder to the
analysis-configuration reader.

The wrapper also receives an explicit private `qlconfig.yml` containing the
three bytes `{}\n`. This prevents upward configuration discovery from selecting
the workspace's separate QL configuration. Its exact bytes are recorded and
checked after analysis and decoding. The method reuses production's controlled
environment, authenticated runtime restoration, full runtime inventory, and
database admission helpers.

The analysis may derive `baselineLinesOfCode`. Both metadata versions are saved;
structural fields and the source root must remain equal. The initial extracted
data, source, and TRAP files are checked after execution, excluding evaluator
cache and working/log files that are expected to change.

## Completion evidence

The method requires the following concrete outputs:

- Exactly 39 admitted QLX loads and zero query-plan compilations, counted only
  in `execute-queries-*.log` to avoid counting wrapper logs again. The same logs
  must contain 39 starts and 39 completions. This run uses only ordinary
  `--verbosity=progress` and `--logdir`; it does not request predicate-level
  evaluator tracing. Its exact evaluator invocation must carry the admitted
  heap and off-heap arguments, and all observed arguments remain in the receipt.
- Exactly 39 fresh BQRS files, starting from a database with no results. Their
  bytes and hashes are retained.
- A parseable SARIF result accepted by the existing production validator,
  including the CodeQL version, category, successful invocation, and tool
  diagnostic checks.
- Complete decoded SummaryStats JSON equality against all three saved
  baselines, including result-set names, column descriptions, all 29 tuples,
  their order and multiplicity. The retained semantic SHA-256 is
  `e2582f4726e1866ef348bf49f05d8c70c62afc6ce8a913eb883bf88684101725`.
- The same projection identity, whole query-pack bytes, and runtime inventory
  before and after analysis and decoding.

Original exit codes and bounded-process failures remain in their command
receipts. Post-check failures are recorded alongside an original analysis
failure, rather than replacing it. Process-resource samples are diagnostic
evidence; unavailable sampling is recorded without changing the query's exit
status. The saved local result therefore closes the wrapper and SARIF path for
this fixture, while the separately running large database supplies its own
completion and resource result.

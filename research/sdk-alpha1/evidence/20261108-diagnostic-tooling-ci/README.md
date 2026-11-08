# Diagnostic tooling CI repair

## Scope and observed failures

The baseline is `6ec4d7824cada30bdc4bdb6867fd00a0e34d9731` on
`diagnostic/wasm-summary-memory`. This change is prepared as a separate
`fix/diagnostic-tooling-ci` branch with that exact parent, and a draft PR targeting
the diagnostic branch. It does not update or cancel paired evaluator run
**42511575195**. No workflow trigger, evaluator allocation, query or deadline is
changed.

Ordinary CI [run 42511575194](https://github.com/billlza/q-periapt/actions/runs/42511575194)
reported these failures:

| Job | Test result | Concrete cause |
|---|---|---|
| check, 128825647892 | 3547 tests; 2 failures; 3 existing skips | Direct `json.loads` architecture violation; sparse-checkout data mistaken for a Python invocation |
| windows, 128825648074 | 175 tests; 1 failure; 6 existing skips | The same direct `json.loads` architecture violation |
| abi2-windows-package-2022, 128825648083 | 175 tests; 1 failure; 6 existing skips | The same direct `json.loads` architecture violation |

Complete hosted logs and the original source snapshots are retained in the
research handoff outside git. `HOSTED_FAILURES.json` identifies their hashes.
The two failures also reproduce locally on the exact baseline; `LOCAL_BEFORE.json`
records that run. The Windows failures occur in the same repository-wide AST
policy check, rather than in Windows-specific runtime behavior.

## Changes

`codeql_current_memory.py` now decodes a quoted metadata key through the existing
`parse_strict_json_bytes` entry point. Its `EvidenceIOError` inherits `ValueError`,
so the existing wrapper still raises `ControlError` with the safe message
`unsupported quoted database metadata key`, preserving the original exception
as its cause. A direct probe confirms escaped keys retain their meaning and an
invalid escape follows that error contract. The production change is exactly
one parser-call replacement; all evaluator and archive behavior is retained.

The workflow guard retains its original whole-file checks, including conservative
checks of environment literals and arbitrary action inputs. Its existing trigger
path and archive-argument exceptions are unchanged. A new indentation/context
selector recognizes only a single, literal, full-SHA `actions/checkout` step's
`with.sparse-checkout` scalar as checkout data. Unrecognized contexts receive no
new exception. The same path in an actual run command, an executable-bearing env
literal or another action input is still rejected.

An earlier run-only draft was withdrawn before publication: a real harmless
Python fixture demonstrated that an env-bound `"$SCRIPT"` command could bypass
that broader draft. The final change preserves the original env rejection. Its
regression executes that harmless fixture, then verifies rejection of the
corresponding workflow, including Bash, chained-alias, PowerShell and GitHub
expression spellings. No shell or environment interpreter was added to the guard.

## Validation

`LOCAL_AFTER.json` records **70 passing tests, zero skips**: the unchanged 63
paired-control tests, the strict-JSON architecture gate and six workflow guard
checks, including three new regression methods. The original env and archive
negative tests are unchanged. Full before/after logs are retained with the
research handoff; the receipts contain their hashes and exact replay commands.

`RUN_CONTEXT_AUDIT.json` independently parses all **19 workflows** with PyYAML
and checks the selector against actual YAML nodes. The only new exceptions are
**52 source lines in five checkout sparse-path scalars**. None of the **319 run
steps** has an executable source line excluded by this new rule.
`STRICT_KEY_PARSER.json` records the parser error-contract probe.

The local controls establish the two fixes and retain the prior bypass rejection.
The separate branch's hosted CI supplies the final platform validation. This
repair has not executed a CodeQL query locally and does not claim a performance
result for the ongoing paired evaluator.

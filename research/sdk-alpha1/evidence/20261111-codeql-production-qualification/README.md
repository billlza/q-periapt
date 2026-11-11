# CodeQL production integration: Python qualification

The recovered opt-in production integration passed **282 tests in 12.183 seconds** on GitHub Actions. The tested source is `af49f2302ef789cbb670bc26f952d0fcd5986dd2`, tree `cb04bf4c6af404ba855fb21fd06c43dfdfcfd94b`. Production projection remains disabled: the existing workflow still selects the default `none` mode.

## Observed runs

| Run | Source | Tests | Result |
| --- | --- | --- | --- |
| [43023229902](https://github.com/billlza/q-periapt/actions/runs/43023229902) | `a6bf9d80f795373e8f119e63f2b55a8596f6e2d2` | 282 in 11.100 s | 277 passed; 2 failures and 3 errors |
| [43025252530](https://github.com/billlza/q-periapt/actions/runs/43025252530) | `af49f2302ef789cbb670bc26f952d0fcd5986dd2` | 282 in 12.183 s | 282 passed; no failures, errors or skips |

These are two separate pushes of the same focused workflow, each at attempt 1. The second commit changes only three test files.

## What the first run resolved

Three new fault-injection tests attempted to overwrite receipts or configuration files that the producer had deliberately made read-only. The hosted unprivileged runner rejected those writes before the tests reached their intended content-validation checks. The corrected fixtures first assert the read-only mode, then replace their own fixture inodes and exercise the original validation assertions. Production file protections remain intact.

Two preexisting evaluator-failure mocks accepted the old three-argument callback signature. The new progress keyword raised `TypeError` before their intended timeout or injected error. The corrected mocks accept that keyword, verify the complete admitted query set, and retain their original failure behavior. All five cases passed in the second run.

## Established integration behavior

The suite covers the mocked complete production analysis and publication route, fixed runtime and plan admission, command and actual-allocation receipts, all 39 query result slots, transfer boundaries, and the existing diagnostic modes. Negative controls reject changed or rebound plan/runtime identities, implicit compilation, extra precompiled loads, an incorrect evaluator heap, a missing full SummaryStats result, and mutations detected by the postcheck.

The pinned-stdin regression uses a real bounded Python child. The eight progress controls also include a real child that observes both its retained stderr and the fixed progress line before it exits. Progress retains every original stderr byte, counts distinct admitted query completions, and emits at most 39 fixed-template lines. It does not replace result, SARIF or publication checks.

This packet qualifies the Python integration and process-I/O boundaries. The separate nonempty CodeQL `database analyze` fixture validates the actual analyze-to-SARIF route with the admitted Stage3/Stage4 plan.

## Retained evidence

`QUALIFICATION.json` records both run/job identities, exact source commits and trees, test counts and durations, step conclusions, and uploaded artifact metadata. `SOURCE_BINDINGS.json` binds the recovery and qualification commits to their file blobs and independently checked trees.

Both `JOB_LOG.txt` files are complete decoded GitHub job-log responses saved unchanged, including setup, test output, failures where present, artifact upload and cleanup. The first run's original structured review is also preserved unchanged; its corrected-source status describes the time before the second run.

The uploaded artifacts contain the source identity and original test output. Their API digests and sizes agree with the upload messages in the retained logs:

- First artifact: `13856631897`, 9,545 bytes, SHA-256 `8b59df2afee8ee46388c3a7d6efe66f398d7df33d4d03da2b8035fc51d70bfbb`.
- Second artifact: `13856768587`, 8,360 bytes, SHA-256 `522878964a72f964b3ac8ad8acaccdb281c2b14361b86f843139d7d6bbddc6b7`.

The exact-source assertion succeeded in both jobs, and the commit/tree bindings were independently read back from the GitHub Git API. The uploaded ZIP members were not separately decoded while the local executor was unavailable; the packet records that distinction explicitly. The full decoded job logs are retained here independently of GitHub artifact expiry.

# Complete installed C owner ABI checks

Source commit `43c60a808e53419c0c827d9dd973a2d2a9b614b5` adds a complete
declaration, type and layout gate for the unpublished `qpc-owner/1` facade.
Its existing symbol-only census already enforced all 158 exports. This change
adds the missing whole-header contract and compiler-to-compiler comparison;
it does not repair an observed mismatch in the existing production ABI.

The reviewed snapshot covers 158 function declarations, 70 C record names with
341 fields, one callback and 112 constants. Account and session cleanup status
share one Rust type, so there are 69 native record types. The constant values are
locked C declarations; this is not an independent proof of every runtime error's
meaning. Product ABI 2, `qpc-owner/1`, protocol bytes and storage formats are
unchanged. The snapshot explicitly remains an unfrozen candidate contract.

## Executed installation boundary

Both Debug and Release were built outside the checkout from nine admitted SDK
crate archives, the installed Continuity candidate archive and the exact C facade
sources. The SDK producer remains `6084f3bf`; its report SHA-256 is
`d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885`.
The candidate archive was produced at `21e00e9c`; its SHA-256 is
`1326dbd2ba1c93f950a5f582e11af1514a017f0275d643812b7072da90ba54a9`.
Every candidate archive member still matches current candidate source, and the
SDK workspace identity matches the original report. Resolution retains the
original locked external dependency set, with 171 external packages in this
facade's graph. This is an installed archive graph, not checkout dependencies.

The C shared library is copied into an installation directory. A separate C11
program retains all 158 symbol relocations, links that installed sibling library,
and emits the actual target layouts. The Rust facade's compiled unit-test binary
checks complete function-pointer types, field types and exhaustive record patterns,
then emits native layouts and type identities. The reader compares exact record,
field, function and callback inventories, types, sizes, alignments and offsets.
C parameter-array decay is permitted; two declared pointer-to-array extents must
still match. No lifecycle function is called by this metadata probe.

Both profiles pass the complete comparison and strict Clippy. A separate run of
the exact same native test executables passes **59 tests per profile**, zero
failed, ignored or filtered tests, including the existing lifecycle/admission
regressions. The new ABI test also executes there. The full C/OpenSSL/Swift/Kotlin
installed lifecycle suite was not rerun in this increment.

The 111 related Python regressions and 15 Windows packaging/workflow checks pass.
Formatting passes for all 24 changed Rust files. The exact tracked Rust inventory
is 1,165; this is source-gate validation, not a new CodeQL database scan. Windows
packaging now retains the exact snapshot before its consumer attempts admission;
native Windows, Linux and device execution of this new gate remain pending.

`SOURCE_JOIN.json` verifies every captured C facade and reader hash against the
committed tree. Removing only the test-only additions restores all 23 existing
Rust files to the parent bytes, modulo terminal whitespace. The actual Debug and
Release shared-library bytes are also identical between the pre-review and final
type-check iterations at the same installed paths. Existing runtime behavior was
not relaxed to satisfy these checks.

## Reproduced review counterexamples and retained failures

A narrow internal read-only review identified three gaps in the initial gate.
The primary execution reproduced them and retained the refusal controls:

1. Updating both C header and snapshot could change a function parameter to
   `double` or change an `i32` field to `u32` without changing the old layout-only
   output. The mutated C probe really compiled, linked the installed Release
   library and passed the old comparison without invoking lifecycle functions.
   The corrected grammar rejects unsupported parameter types. A second real C
   probe using permitted `int64_t` and `uint32_t` types is rejected by the new
   cross-side function and field type comparisons.
2. A new `u32` field fitted the four padding bytes of the actual witness Options
   record. The old macro still compiled with size 24, alignment 8 and unchanged
   original field offsets. The new exhaustive pattern rejects it; the original
   record remains a successful strict compiler control. This compiler reports
   “pattern requires `..` due to inaccessible fields”, not the diagnostic code
   initially expected by the isolated counterexample driver.
3. The original reader accepted missing test identity, duplicate success summaries
   or a contradictory trailing failure summary. The strict line-sequence reader
   rejects all three. This was a parser gap; the enclosing process runner already
   refused nonzero exit status.

The original three aggregate attempts remain failed or incomplete:

- `run-01`: Debug ABI comparison passed; strict Clippy refused seven test helpers
  placed after inline test modules. The helpers were moved, without lint suppression.
- `run-02`: both profiles' ABI and Clippy commands passed, but the diagnostic driver
  attempted a second exclusive write of its result file. Its initial partial report
  and failed finalization are retained; this is not an aggregate success.
- `run-03`: the new type reader failed to translate record names immediately after
  `*const`. The actual C and Rust records agreed. The token translation and a
  const-record-pointer regression were corrected; no ABI type was changed.

`run-04` completes both requested profiles, retains separate profile reports and
one final report, and verifies source hashes unchanged. The 59-test runs have
their own completed receipt. These separate successes do not rewrite any failed
attempt. Internal review is not external security review.

## CI observation and remaining scope

At 12:21:39 UTC, the twelve current-head runs contain **262 successful, 61 queued,
seven failed and two skipped jobs**, with none running in that twelve-run set.
Both PR heads remain `475cd239` (#117) and `6084f3bf` (#118). The two newly successful
Apple Silicon jobs are reference account job `126445762701` and root-winner job
`126445737013`; the #117 push reference-account workflow is now 10/10 successful.
The root job's complete log is retained. The account log request timed out in the
connector; its complete successful job/step inventory is retained, but no unseen
log-derived test count is claimed.

The separate older independent run `41791763191` at `adaaeb49` has two successful,
one running and one queued job. It is not a current-head or installed-Rust result.
The existing seven failures retain their prior
[classifications and original evidence](../20261104-ci-runtime-failures/README.md).
No remote push, rerun, cancellation or new CI wave was requested.

`CAPTURE.zip` retains 326 public files, 10,103,912 uncompressed bytes, including
command receipts/streams, the failed attempts, typed outputs, counterexample
sources, source join, exact diff and CI observations. Every member was independently
reread against `SHA256.json`. Private keys, stores and application fixtures are not
included. This closes the local C declaration/type/layout acceptance increment;
product ABI 2 admission, protocol/storage/maintenance freeze, final-source platform
qualification, resource budgets, external review and authorized release remain open.

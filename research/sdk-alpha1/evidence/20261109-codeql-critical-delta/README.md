# Python critical-result delta review

The newer Python SARIF contains one additional critical result. The prior 52
results comprised 51 `py/command-line-injection` results and one
`py/code-injection` result; the newer scan contains 52 and one respectively.
All prior 52 match exactly by rule, sink path/region and the complete set of
ordered source-flow coordinates. No prior result or flow was removed or changed.
All 70 Python source blobs used by the original review are also unchanged at
integration commit `db2ff7918e74d336e6c9fd12639eab70065158b6`.

## Added result and execution boundary

The added result is SARIF index 1253, `py/command-line-injection`, at
`research/continuity-matched-comparison/run.py:48`. Its four complete flows start
at `env = dict(os.environ)` on line 195. They propagate the environment dictionary
through the three reference variants and the construction of the executable path.
`new-flow.json` retains every ordered region and its original canonical flow hash.

The source overwrites `CARGO_TARGET_DIR` with the new invocation output's `build`
directory before constructing the variant list. The chunk64 variant overwrites
the same key again with `build-chunk64`. The executable basename is selected from
two fixed literals, and the corresponding locked Cargo build must succeed first.
`command` passes an argument list to `subprocess.run` with no shell enabled.

A finite probe executed the actual runner control flow with source preparation
and builds stubbed. An inherited adversarial `CARGO_TARGET_DIR` was not selected
for any of the three executable paths. Output paths containing spaces and shell
metacharacters remained individual arguments. A second probe of the actual
`command` function confirmed that its argument vector is preserved and no shell
is enabled. These are focused boundary probes, not another native experiment.

This result is classified as a reviewed derived execution target whose environment
key is overwritten. The reported input path does not grant unexpected control of
the reference executable. The research operator and dedicated workflow explicitly
authorize building and running the pinned source; normal toolchain/PATH authority
stays with that invoker. This conclusion comes from the actual source and probes,
not from the file's research or test label.

## Separate confirmed cleanup defect

Reading the complete driver exposed a different failure-path defect. The old
`main` always cleaned `.private-*.keys` under the requested output, even when the
initial source check failed before this invocation created that directory. A
temporary preexisting directory lost its private-pattern marker under both CLI
modes. An independent reviewer reproduced this with real git rejecting a temporary
non-repository; the ordinary file remained and no source directory was created.

The isolated fix moves cleanup into `run` after successful `prepare`. Preparation
exports source and injects observer code; the private observer feeds are produced
only by later execution. Both successful and exceptional owned execution still
clean those feeds, preserve public/outside files, and reject a symlink feed.
The retry-age runner has no corresponding cleanup path. Its sole runtime change
is the exact pin for the repaired matched runner. Its numerical and policy code,
and the matched execution body, remain unchanged.

The frozen four-file candidate passed 44 local tests and a separate independent
review with 44 tests plus real-git before/after controls. The repaired matched
runner SHA-256 is
`0d089a5913adfa47e14a2ac85eb74771e505cde67ff18385a163bc533624547e`.

## Source and scan identity

The new scan is run `42554273879`, Python job `128956398108`, artifact
`13654276807`. The ZIP digest and local SARIF member were both checked. The artifact
records checkout `56f191f04a57806869b8a03078ee4d27ffe900ab` and tree
`2acf7f26bfb2e332361f618cc019ed33b6cb2cfe`. Its SARIF SHA-256 is
`cd5d6bf8a4f0b5a75e85b6ce99355c71117cd6f188d8a2e36d35dac39aae6abb`.

The scanned driver and the pre-fix integration driver are byte-identical:
SHA-256 `0af65ca924d53514fd30a979e406adb1a8930c33aad87fa4e239f787a9eb4baf`,
Git blob `62fb9a6735cb045ded966ca36b6579db3eb5fc7b`.
`review.json` binds the comparison, source identities, finite probes and separate
cleanup counterexample. No alert dismissal, query change or threshold change was
performed. Other high results receive no new blanket classification from this
finite review.

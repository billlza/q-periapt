# SDK dependency aliases and packaged maintenance consumption

Qualified implementation: `de2c49e9e572972165a05411d2a11777f06e31b2`.
All local source-bound qualifiers are terminal. The implementation was clean and
unchanged through both the complete artifact suite and canonical Rust package
contract. This record is local package and Linux CI evidence, not release approval.

## Cause and repair

At `9d110e6e38e1aa7952dc20cb7cdcab05d96f288a`, the
[Rust package job](https://github.com/billlza/q-periapt/actions/runs/37765763452/job/113272919180)
correctly refused the newly introduced `redb-legacy` dependency because the
registry metadata serializer did not model aliases. The repair uses the original
package name for `name`, the local dependency name for `explicit_name_in_toml`,
and the local name when validating optional `dep:` features. Explicit equal names
retain the alias field; an absent `package` omits it. Alternate registries,
git/path sources and unmodeled implicit features remain refused.

The committed [Cargo fixture](../../../../artifact/testdata/crates_io_uploader/registry-alias-fixture.md)
was captured from Cargo 1.98.1 against a local rejecting receiver. Its documented
destination projection accounts for an alternate-registry field; no public
registry upload or acceptance is claimed. The added cases failed on the old
implementation. The focused four-module suite passed 76 tests after the fix.

The [Linux check job](https://github.com/billlza/q-periapt/actions/runs/37765763452/job/113272918726)
then exposed three separate contract mismatches: the added CLI install omitted
the explicit compiler selector, the deliberate dependency-count tripwire still
expected 240 rather than 242, and the closed publication topology omitted the
CLI's optional SDK/host-store edges. The repair pins `cargo +1.98.1 install`,
acknowledges exactly redb 2.6.4 and twox-hash 2.1.4, and updates the dependency
graph. No assertion or refusal was disabled.

## Observed qualification

| Boundary | Actual result |
| --- | --- |
| Complete `artifact/test_*.py` discovery | 2,653 tests passed, no skips; 612.689 seconds |
| Canonical `rust-publish-contract.sh --profile sdk-020` | All 12 archives built and verified; 4 external Rust consumer tests and Clippy passed |
| Dependency audits | Workspace, fuzz and consumer audits passed with one advisory database identity |
| Archive-built maintenance command | Release binary built offline from exact recorded archives outside the checkout; 7 installed-command cases passed |
| Linux Rust 1.98.1 and 1.90.0 migration tests at prior CI commit | 29 tests each; each exercised 232 typed I/O faults, 126 process cuts, 37 partial writes and 48 peer lock refusals |
| Linux source-installed maintenance command at prior CI commit | All 7 cases passed before the later artifact-test failures |

The maintenance consumer needs ten archive-derived package patches for Cargo
resolution, including optional rustls. Its selected dependency graph contains
nine local packages: the maintenance feature does not activate rustls. All
resolved external lock identities are a subset of the qualified workspace lock.
No workspace path dependency supplied its product code, and extracted source
bytes remained unchanged after building and consuming the installed binary.

Maintenance binary SHA-256:
`cd9b17a84635ffa06d9144d35a870f547ec0e0db6fe9a0cf6e8d363dc2327f6f`.
Its seven cases are successful original-format upgrade, current-format retry,
wrong trusted state, wrong independent root, corruption of either transaction
slot, and missing-store refusal. Partial writes and process cuts remain the
separate feature-test evidence; these seven cases do not imply power-loss safety.

A preliminary expanded regression invocation ran in a Git worktree and was
rejected by the existing standalone `.git` provenance requirement. Its failure
log is retained. Qualification uses the clean standalone clone instead. Two
isolated archive-consumer setup attempts also remain in the local capture tree:
one incorrectly expected optional rustls in the activated graph, and one removed
the optional archive needed for offline resolution. The final consumer models
both sets explicitly; those preliminary attempts are not counted as passes.

`CAPTURES.zip` contains the package report, terminal run records, raw test logs,
Cargo request capture, exact local runners and Linux job evidence, with an
internal `MEMBERS.json` digest inventory. Exact product `.crate` files and the
built binary remain in the recorded local output paths; the capture bundle is
not a redistributable SDK package. Hashes and result boundaries are in
`QUALIFICATION.json`.

## Remaining gates

The new implementation commit has not been pushed at recording time. The prior
[Rust CodeQL job](https://github.com/billlza/q-periapt/actions/runs/37765763456/job/113272915154)
is still analyzing and must retain its analysis, quality check, upload and
diagnostics before another CI push. The old failed jobs are not described as green.

Prebuilt maintenance-tool distribution is still open. No public registry install,
release, merge, Intel Mac support, power-loss qualification, physical-device gate,
or composed persistent-PQ-recovery security claim is established here.

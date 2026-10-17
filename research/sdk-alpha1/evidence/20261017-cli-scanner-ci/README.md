# Scanner CI corrections — 2026-10-17

The first hosted execution of `3df45b84` exposed two incomplete validation
contracts. Both failures are retained; neither is classified as an environment
fluke or retried unchanged.

[Windows job 117397671523](https://github.com/billlza/q-periapt/actions/runs/39033181044/job/117397671523)
passes both file/directory symlink-substitution controls, but the open-directory
test fails when rename returns Windows error 32 (`ERROR_SHARING_VIOLATION`).
Rust reports it as `Uncategorized`, outside the fixture's previous
`PermissionDenied` match. The [Win32 error definition](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
identifies that exact sharing refusal. The corrected fixture accepts this
specific Windows outcome, still scans only the original ECDSA input, and then
requires the same rename to succeed after the retained directory handle closes.
An arbitrary error or a permanently unrenameable fixture cannot pass.

[Audit job 117397671609](https://github.com/billlza/q-periapt/actions/runs/39033181044/job/117397671609)
stops before vulnerability evaluation because its workspace resource limit still
allows 259 registry packages. The reviewed scanner dependencies add twelve, for
271 total, without changing existing registry versions. The artifact job's sole
error among 2984 tests (three platform skips) is the same live inventory check.
Only the workspace count becomes 271; normalized/fuzz limits remain 256, the
fuzz lock still has 46 packages, and all byte/time bounds remain. Existing
boundary tests require acceptance at 271 and refusal at 272, including the
sparse helper receipt check. No package, checksum, yanked or advisory check is
omitted.

The correction passes all 23 native CLI tests, strict all-feature Clippy,
formatting and all 80 dependency-contract tests. An actual isolated audit then
checks the complete workspace and fuzz locks against crates.io and RustSec
commit `64f92cdc64401fab47baa10e2e11fe382aa57155`, with exact checksums, zero yanked
packages and warnings denied. [observations.json](observations.json) records
the changed-source hashes and bounded scope; adjacent logs retain terminal
results. Hosted execution of the corrected Windows assertion remains required.

The product scanner implementation, lockfile, SDK runtime and public ABI are
unchanged by these corrections. Full CI and 0.2.0 release qualification remain
separate from these focused results.

# Enrollment CI follow-up

Seven qualified commits were pushed from `b626bf92` through `2b596975` only
after the earlier Rust CodeQL analysis, quality checks, upload and retention
were all terminal. This record separates analysis success, findings review,
local regression and native package qualification.

## Windows import-library gate

Both [Windows](https://github.com/billlza/q-periapt/actions/runs/37726769361/job/113146609516)
and [Windows 2022](https://github.com/billlza/q-periapt/actions/runs/37726769361/job/113146609718)
failed on `SDK import-library contract export inventory differs`. The SDK
contract correctly lists 51 entries after existing-store enrollment, but
`Assert-ImportLibrarySymbols` still required 50. The Windows 2022 Python tests
and command-boundary checks had passed before the exact inventory guard failed;
the package build was skipped, so this was not an observed MSVC link failure.

Commit `294fb053` corrects that guard, its diagnostic and package prose to 51.
It retains exact sorted comparisons for both callable and `__imp_` symbols,
duplicate rejection, DLL identity and the separate historical nine-symbol
profile. Current introductory documentation now also says 51; dated historical
evidence keeps its original counts.

The actual PowerShell profile test reproduced the same failure locally before
the change, then passed on PowerShell 7.6.4 after it. Its symbol fixtures retain
missing-thunk, missing-import, extra, alias and duplicate negative cases. All
15 relevant Python SDK ABI/profile tests also passed. These local checks do
not execute dumpbin, MSVC or a Windows binary. The corrected commit still
requires its own hosted package producer and installed-consumer result.

## CodeQL checkpoints

The [b626 Rust job](https://github.com/billlza/q-periapt/actions/runs/37715391730/job/113110568834)
completed successfully, including its quality and diagnostic retention steps.
Artifact 11527966593 was downloaded and its 471,691,356 bytes matched the
GitHub-reported SHA-256. Its SARIF contains 781 results, 423 successfully
extracted files and zero files extracted with errors. These are analysis
coverage observations, not 781 resolved findings.

A multiset comparison by rule, primary source URI and exact message finds one
additional result and no removed results relative to the retained 780-result
snapshot. This comparison ignores line movement and does not establish
equivalence of all data-flow graphs. The added result is zero-based index 578,
`rust/command-line-injection`, at the bounded-stack recovery test's
`Command::new(current_exe())`.

The exact b626 source confirms that this module is compiled only under
`cfg(test)`. This call starts the running test executable with a literal exact
test name and literal flags, sets the child marker itself, and does not invoke
a shell or use a policy/network value as the executable or argument. It
isolates an aborting stack-overflow regression. Under the developer/test-host
trust boundary, the reported path does not demonstrate production command
injection. This does not make `current_exe` an authentication primitive or
protect a test host whose executable can be replaced. No query was disabled
and no remote alert was dismissed. The other 780 results were not reviewed
anew in this checkpoint; the earlier scoped review remains separately bounded.

The subsequent [2b596975 Rust job](https://github.com/billlza/q-periapt/actions/runs/37726769343/job/113146609549)
also finished its analysis, quality checks, upload and retention successfully
at 06:35:21 UTC. Its artifact 11532169915 identity is retained from the API;
its SARIF was not downloaded or reviewed in this checkpoint. Neither successful
job substitutes for the remaining findings review or the full 0.2.0 release
requirements. PR 111 remains draft and open; no merge or publication occurred.

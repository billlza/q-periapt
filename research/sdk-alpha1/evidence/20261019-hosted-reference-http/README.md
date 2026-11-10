# Hosted enrollment HTTP checks

[Run 39203490343](https://github.com/billlza/q-periapt/actions/runs/39203490343)
completed successfully at `1dc0f16fef08de67a2607dafa43afbb8876ab77d` on
Linux x86_64 and Apple Silicon. Both profiles ran all 26 source-derived test
entries (25 behavioral tests and one child dispatcher), with 20 library and 6
binary results. Formatting, strict all-target Clippy and release builds passed.

Three enrollment scenarios use actual loopback TCP, software WebAuthn signatures
and native SDK requests. They cover account/Origin/input isolation, exact result
recovery after disconnect before consuming the issuance body, original-database
restart and fresh login, explicit roster-conflict reapproval, cancellation and
root suspension. The frozen library suite retains 14 distinct SIGKILL boundaries;
these are not new HTTP cuts. Software user verification and policy family remain
fixtures; no physical or live signed-policy admission is claimed.

Readback checked exact head/lock/compiler/architecture, all debug and release test
names and summaries, and both 16-member archives against their GitHub digests.
The capture contains those archives, terminal metadata, reader and 30 exact
app/workflow source files. SDK dependencies are identified by the pinned Git head.
Executables and private/child-marker state were not exported or replayed. No live
job logs were read.

Browser enrollment controls and installed independent-client acceptance were not
implemented at this pinned head. Newer browser edits in the current worktree are
not covered by this receipt. Deployed HTTPS, full lifecycle and release admission
remain separate gates. This optional host does not make signup an SDK requirement.

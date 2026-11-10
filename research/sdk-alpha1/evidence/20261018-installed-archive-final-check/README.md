# Installed archive final-check repair

Linux job [117653451578](https://github.com/billlza/q-periapt/actions/runs/39119367383/job/117653451578)
at `fd42b370` completed with failure. After its runtime work, `qualify()` tried to
read `filename` and `archive`, locals that had moved into `package_candidate()`.
The first access raised `NameError`. The saved package report correctly retained
`completed=false` and `partition_completed=false`; it has not been rewritten.

The final guard now uses the original archive record returned by packaging. It
checks the expected filename, SHA-256 and byte length after all installed
consumers. Thirty package/profile tests pass, including changed filename, changed
size, same-length content substitution and missing-file refusal. A readback
executes the old actual guard against the downloaded archive and reproduces the
NameError, then executes the corrected actual call site on those same bytes.
This is a targeted guard regression, not a replacement end-to-end runtime.

The complete original 92,246,926-byte artifact has SHA-256
`7cd6e5e2696cad397d67c5b9bc262eda16154f4dc8d74572d5e817b780ba6c7f`
and remains locally and in GitHub artifact `12136726947`. The compact capture
retains its original report, candidate archive, strict C11 compile and execution
receipts, Rust stdout, terminal job log, guard reproducer and test outputs. Both
C11 input probes compiled with `-std=c11 -Werror -Wpedantic` and returned the exact
success marker in Debug and Release. This establishes the earlier shared-header
fix's Linux input runtime coverage. It does not independently requalify every
larger lifecycle subtree in the failed package report.

Superseded full runs `39119367383` and `39123933824` were cancelled after their
states were saved; the latter had the identical obsolete final guard. The original
failed job and all existing artifacts remain. A new full installed run is required
before the repaired overall qualification can pass. No SDK, crate, binding or
cryptographic implementation changes are part of this repair.

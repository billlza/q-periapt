# Pending-offer recovery: working checkpoint

This is a handoff of incomplete work, not release qualification or an external
security review. The source-native tests extend pending-write recovery to an
original committed rekey offer while preserving the previous no-offer cases.
The two Witness application outcomes are exercised in both variants; the test
checks retained epoch progress, the original closure report, joint authorization,
exact recovery and acknowledgement.

## Observed validation

The final run, `validation-02` inside `VALIDATION.zip`, completed on 2026-11-06 at 08:27 UTC using
Rust 1.98.1 on Apple Silicon macOS. Three selected tests ran once each under
Debug and Release (six executions); all passed. Format checking and all-target
Clippy with `-D warnings` passed. Each selected test run filtered out 1,460
other tests; this is not a full native test-suite run. The runner recorded its
12 commands, source-input hashes and outputs in `validation-02/` inside `VALIDATION.zip`.

The first run, `validation-01` inside `VALIDATION.zip`, tested an intermediate version containing only
the pending-offer cases in the staged test. The final version restores both
no-offer cases. Its intermediate source is retained alongside the run as
[archived text](intermediate-witness_pending_write_recovery_tests.rs.txt). The original
`intermediate-witness_pending_write_recovery_tests.rs` filename is now
`intermediate-witness_pending_write_recovery_tests.rs.txt`; the Git blob
`0cd83563828fce7f363ab894b02644e5688fbde3` is unchanged. This suffix marks a
historical test snapshot rather than an active Rust source. Original paths and
hashes inside `VALIDATION.zip` and the validation receipts are preserved; the
archive is not relabelled as an execution of the current source. The two runs
are not 12 distinct tests and should not be conflated. Test binaries are
not included in this checkpoint: `BINARY_PRESERVATION.json` records the local
copies of the first-run binaries; `validation-02/RESULT.json` inside `VALIDATION.zip` records the
final binary hashes. Paths in the raw receipts refer to the original machine.
The build cache and original binary files remain on that machine.

The tested parent was `9b370749f53b3145544b1b6892cd765dde71bc42` with the
subsequently committed test-file changes. `validation-02/INPUTS.json` inside `VALIDATION.zip` records
the actual 1,155 selected input hashes. These source tests do not qualify an
installed package, a physical device, physical power loss, or every recovery
history.

## Security analysis status

The [zero-tag prefix argument](../../../../docs/continuity/CLEANUP_REPORT_MAC_V1.md)
is a conditional manual working argument, not an independently reviewed proof.
The tests do not validate its probability bound. The complete shared-root,
private-state and multi-epoch computational argument remains open. The related
[cleanup/rekey note](../../../../docs/continuity/CLEANUP_REKEY_CAUSALITY_V1.md)
sets out the narrower observed behavior and remaining obligations.

## Other work in progress

The three `foreign-process-receipts/` files report exit status zero for Swift
Debug, Swift Release and Kotlin Release processes run against the separate source
checkout `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. They are process receipts,
not independent artifact readbacks or qualification of this later commit. Kotlin
Debug had not been started at this checkpoint. The previous hosted CI run for
PR #118, [42009001947](https://github.com/billlza/q-periapt/actions/runs/42009001947),
completed with failures. Review its failures and the new head's CI before making
any release decision. The product contract, full proof, remaining platform
qualification and independent external security review remain unfinished.

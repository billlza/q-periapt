# Swift restricted enrolled-device retirement

The new `ContinuityRetiredEnrollment` owns the existing native lifetime wrapper;
it cannot expose an operational owner, signer or raw handle. It copies bounded
independent authority inputs and delegates original inventory/report, host ACK and
logical journal/signer erasure to the same C/native engine. Immutable report bytes,
the original proposal and keyed report ID remain distinct. Report loading does not
perform host accounting or grant erasure permission.

On macOS arm64, both Debug and Release pass all 56 named Swift tests with warnings
as errors and complete concurrency checking. Both run eight actual Swift cleanup
processes, preserving the original report across three exits without completion.
A valid report-retention receipt fails as an erasure ACK, consumes the admitted
owner and leaves the journal Retained after exact reopen. Preparation cancellation,
short/malformed receipts and closed owners are exercised. Native Rust independently
reconstructs and compares every canonical report byte and checks session/message
accounting. The original Swift registration workload also passes its unchanged
one executed/27 filtered gate. Twelve affected artifact tests pass.

The package producer now requires this foreign retirement trace, binds its native
harness to the completed C qualification and retains public outputs in CI. The
four added Swift tests are mandatory in the strict 56-test collector. Test-host
report storage accepts the bounded 8 MiB canonical report while retaining the
existing 1 MiB default for other records.

`QUALIFICATION.json` and `CAPTURES.zip` bind source-copy identities, actual commands,
binary hashes, explicit public readbacks and the observed Swift 6.4 tool identity.
Private databases, signer/wrapping keys and TLS private keys are excluded. This is
source-based development consumption, not qualification of a new Swift archive.
The separately running `ce70bf83` Rust/C installed producer retains its own source.
Replacement authorization and fresh-generation TLS here remain Rust; no independent
implementation, complete foreign replacement, physical erasure/power-loss or broader
device/platform qualification is claimed. Kotlin retirement remains open.

The prior `737ca3ec` Rust CodeQL job completed analysis, source checks, database
quality and upload successfully on 2026-10-08. Its 471,554,161-byte diagnostics
artifact remains remotely retained, with the API digest and expiry captured.
It was not downloaded or newly dispositioned and does not analyze this new source.

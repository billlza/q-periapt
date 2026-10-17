# Installed browser permanent device retirement

This checkpoint qualifies the installed browser package's permanent old-device
exit path. Seven fresh cohorts perform 282 actual Worker calls: five complete
logical journal and original signer retirement; two deliberately missing or
replaced signer records are refused and do **not** count as complete cleanup.
The two native recipient processes, approval controller and browser use the same
engine on one host with loopback transport. This is not independent-implementation,
deployed HTTPS, platform-matrix or full 0.2.0 release qualification.

| Case | Worker calls | Result |
| --- | ---: | --- |
| Signer transaction committed, Worker terminated before SDK return | 40 | Original record recovered as erased; exact retry closes normally |
| Original signer record missing | 39 | `Absent`; no fabricated erasure success |
| Same signer bytes in a different valid catalogue object | 39 | `Conflict`; replacement object unchanged |
| Unapplied ordinary intent, then real credential and policy expiry | 41 | Independently authorized retirement; authoritative and uncommitted views retained |
| Applied ordinary intent with lost reply, then real expiry | 41 | Independently authorized retirement; superseded and authoritative views retained |
| Worker terminated after journal bytes flushed | 42 | Original journal retained on reopen; exact acknowledged erasure completes |
| Close during withheld signer commit receipt | 40 | `CommitUnknown`, closed owner, original lock held until receipt; reopen observes erased signer |

Each cohort first creates and enrolls a browser device, opens two original sessions
and commits one complete-account operation. The first peer records its application
effect once, then its acknowledgement is lost. Retirement retains both original
message identities, ciphertext hashes and unknown delivery outcomes. It sends no
new application traffic and does not reinterpret unknown delivery as consumption.
The full canonical report and proposal are written, file and parent synchronized,
and read back before requesting the independent purpose-21 host acknowledgement.
Reporting alone does not erase anything. Journal erasure and separate signer
erasure require explicit calls with the original authenticated scope.

The browser retired owner opens original storage without a current Runtime.
Historical credential/policy expiry does not authorize new ordinary witness
Advance/Fence writes. The controller independently approves device generation
replacement and permanently retires the old subject. Both expiry cohorts wait
past the actual signed credential and policy end times before replacement; no
backdating, extended old credentials or discarded pending intents are used. This
provides a permanent exit, not in-place renewal of the old device. The earlier
[renewal-ordering counterexample](../20261014-recovery-renewal-boundary/README.md)
remains applicable.

Native inode-bound signer plans remain `QPSRPL01`. Browser plans use `QPSRPL02`,
binding the original authenticated catalogue record ID, signing identity, encrypted
file digest and complete report proposal. Retirement atomically replaces that same
record with a fixed revision-2 `QPSRET01` terminal marker and its sealed catalogue
entry in the existing strict IndexedDB transaction. This is a dedicated terminal
transition, not a general secret replacement API. Missing records and different
record IDs are refused even when the original encrypted signer bytes are reused.
Logical retirement does not prove physical deletion of retained pages or backups.

Cancellation testing holds the real transaction's completion callback after the
commit. Concurrent original opening returns `Busy`; `close()` marks the owner
closed but does not settle or release its root before the native receipt. Releasing
that receipt produces `CommitUnknown`, completes close, and permits an exact reopen
that observes the original record as erased. A separate journal cut observed the
root lock still held after `Worker.terminate()`; browser release took about two
seconds. The controller's bounded 30-second lock-release observation is recorded
before reopening. No SDK retry or lock rule was weakened.

The implementation shares native report, journal and authorization logic through
the existing storage abstraction. Browser owner methods, signer persistence and
WASM report projections are separate modules; bootstrap and session projections
are further split by responsibility. No performance improvement is inferred from
file size. Managed account-root cutover, witness-key handoff, richer nonempty
inbox/prekey/terminal report states and broader lifecycle qualification remain open.

Validation passed: 36 native retired-device tests, two native expiry-boundary tests
(six cohorts), 60 artifact/package controls, native and WASM Clippy with all targets
and features and warnings denied, Rust 1.90 WASM checking, installed Node consumer
tests and strict TypeScript checking. The exact Rust inventory is 666 files, with
positive and missing-file controls for all seven new Rust modules. Package archive
SHA-256 is `569510a0c601270bfa75b5ea10fb20a1b7abed8519727994d2c6c35761b922a3`;
its manifest is `acf0cdd33ebdf5fb1591c719da13c8ecd78e4825325ca745bc4037267b6e5cee`.
The package producer's `browser_runtime: not-run` is preserved; the separate real
browser records provide the runtime evidence.

All unsuccessful attempts remain in the capture. The first replacement fixture
omitted the other two account members and was correctly rejected. Later collectors
misclassified a report request as enrollment capture and shadowed their result
variable. Run 04 completed its first three cases but its expiry case checked a
fractional wall clock against the native integer-second clock too early; its
aggregate remains failed. Those three cases were separately accepted only after
verifying all producer and installed-web hashes. Fresh run 06 used integer-second
expiry waiting. Run 05's immediate reopen returned `Busy` after termination; fresh
run 07 records actual lock release before attempting recovery. Failed cohorts are
never resumed or relabeled successful.

`CAPTURE.zip` contains source overlays, drivers, public inputs, complete reports,
command receipts and failed attempts. Private databases, keys and browser profiles
are excluded. `CHECKS.json` binds the archive and bounded acceptance scope. Exact
commit provenance is checked separately after committing this checkpoint. Rust
CodeQL and overall release readiness are separate gates.

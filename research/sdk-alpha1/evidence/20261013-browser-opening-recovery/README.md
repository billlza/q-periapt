# Browser opening ownership and recovery observations

The original opening bridge could orphan a live browser storage root when a
polled Rust opening future was dropped before the host promise returned it.
`BrowserDevice` installed its cleanup guard only after that return. The baseline
control held the real completed return for create, open and resume, then dropped
the Rust future while keeping the Worker alive. All three left the real Web Lock
occupied. Explicitly closing the late root released it; the original encrypted
wrapping record and recovered request were preserved. This is an internal Rust
future-drop control, not a claim that merely ignoring a JavaScript Promise
cancels its Rust computation.

`StorageOpening` now owns acquisition before the first Rust suspension. The
host captures the root as soon as its lease exists. A synchronous `take()`
transfers it only after successful completion; abandoning the opening closes
any current or late root. The existing storage owner still retains native I/O
receipts until actual settlement. Completed results are never silently adopted
after abandonment, and no cancellation is treated as proof of non-commit.

The same three return cuts now release their locks automatically. Three further
controls withhold real IndexedDB success delivery: dropping the Rust future keeps
the lock until that receipt is released, then closes and permits original reopen.
Another three cancel before the browser admits the lease. They return a closed
opening; the creation case publishes no database or directory, and existing
open/resume cases preserve their wrapping record and original request. These
controls use the actual host storage and shared Rust owner through an isolated
test export, without changing the underlying engine or fabricating I/O results.

The installed public web entry now offers `status()` and `is_closed()`.
Snapshots expose the exact authenticated enrollment phase and original journal,
including distinct Activating, Refreshing and RosterResolved states. Roster
observations retain their predecessor/target and any observed head, time and
outcome; SupersededUnknown is not translated to an uncommitted result. A snapshot
grants no authority and does not renew policy or credentials. Live browser roster
control workflows were not exercised in this checkpoint.

Shared-engine errors now carry `code`, the original `cause`, and `ownerClosed`
for device-operation failures. Busy leaves the current owner open; admitted
operation failures close it. Input failures before dispatch have no owner result.
Original storage codes and primary/cleanup chains are retained. Diagnostic text
remains available, but callers need not parse it to select a recovery path.
Neither the code nor a closed handle proves that a mutation did not commit or
that native cleanup has finished.

Validation used an actual installed npm package through its public web entry:

- Nine lifecycle/failure scenarios passed, with 357 real signed witness requests.
  Structured codes, owner-closed state, preserved causes, concurrent Busy behavior,
  original journal/prekey recovery and immutable status snapshots were checked.
- All five currently reachable basic phases were observed: Preparing, Requested,
  Accepted, Activating and Active. Corrupt/oversized first replies left Activating;
  reopening selected activation instead of recreating children. Closing the SDK
  runtime left an observable Active history but still denied key operations.
- Ten installed browser window/Worker scenarios, installed Node CommonJS/ESM,
  TypeScript 7.0.2 strict NodeNext, the canonical creation suite with 19 natively
  verified requests, 22 artifact tests, and the native original-enrollment/prekey
  regression passed. Strict engine/product WASM Clippy, Rust formatting and host
  JavaScript syntax also passed.

The installed archive has SHA-256
`863d254f950696c5f73020356177ca38ef66f4f27ad5e78c09b92997a02e2e30`;
its manifest has SHA-256
`be55875dbf422dab6f883c150fa5d2c52715d6c15cfc8c486a628f2c0a7b6864`.
`CAPTURE.zip` contains 2,606 members, including that archive, commands, public
inputs/requests/replies, status observations, exact source overlays, and isolated
opening controls. Its SHA-256 is
`57d55f6fc6dfb7e31c2ca2799fcf2c15f730460d16b3f62c720245ce465d16b2`.
Private keys, private witness databases and browser secret state are excluded.
Initial test-adapter compilation and relative-path fixture errors are retained
as harness failures, separate from the reproduced ownership defect.

The old standalone `19108614` Rust/C/Swift producer reached its outer 10,800-second
deadline and was terminated. Its C report completed; its aggregate and Swift
reports did not. The related processes were verified absent. The preserved
termination summary and receipt hashes do not convert that partial cohort into
a pass and do not qualify this source revision.

Full browser publication/session/root/roster/migration integration, deployed
HTTPS, minimum-compiler/browser qualification, full native packaging, independent
implementation work and the remaining 0.2.0 release/research scope stay open.
This checkpoint does not establish whole-profile rollback resistance, secure
erasure, power-loss equivalence or every possible asynchronous cancellation cut.

# Owned browser installation activation

Enrollment now carries its existing platform storage owner into installation,
journal and archive-index construction and initial activation. Native callers
retain synchronous signatures through `must_be_sync`; browser operations await
the actual owned storage. The installation constructors are grouped in
`src/installation/opening.rs`. Named retirement-report attempts preserve the
original close-on-error boundary when native async markers are removed.

The retained Chromium experiment generates each device signer in the browser,
submits its actual request to a fresh native issuer, and checks the returned
credential, independently supplied roster/policy pins and real signed SDK
policy. No private fixture key or unverified SDK binding is imported. The
isolated adapter is retained under `adapter/` in the capture; it is a regression
asset, not the final product browser API or an independent protocol implementation.

The final run passed nine lifecycle scenarios: original local-policy activation
and SDK prekey recovery, six real Worker terminations before/after installation,
journal and archive publication, published journal-index loss, and required-witness
preparation with explicit refusal of activation without a witness. Reopening
returned the original journal and prekey. Corrupted SDK signatures and changed
independent roster checkpoints were refused without replacing original state.

Three further cases withheld the real IndexedDB publication-completion callback
for each child database. Each returned `CommitUnknown` plus `ClosePending`, kept
a competing owner at `Busy`, and released its lease only after the actual
receipt. The same original journal subsequently prepared and activated.

Counterexamples and repairs are retained:

- The parent engine at `19108614`, with the same isolated adapter, accepted a
  real signed grant but failed preparation with native-filesystem `Unsupported`.
- A Worker terminated before publication left an extra OPFS file after retry.
  Authenticated original resume and staging now reclaim unpublished files while
  retaining every published file and active staging handle. Directory validation
  completes before deletion; an unexpected entry preserves both its own bytes
  and otherwise reclaimable staging bytes.
- Consecutive awaited staging calls encountered a spurious `Busy` because the
  previous operation delivered its result before clearing its execution state.
  That state is now cleared before delivery. Actual I/O receipts remain separate;
  the delayed-publication cases above passed after this ordering change.

`PHYSICAL.zip` adds three actual OPFS-file deletions after activation, one each
for installation, journal and archives. Each exact reopen returned `Absent`
without recreating the file or changing the remaining catalogue/files. The
earlier index-loss case separately returned `Corrupt` without repair.

Validation completed: 81 relevant native tests (70 installation, one original
enrollment, seven journal-provisioning and three archive tests), strict native
and WASM Clippy, Rust formatting, JavaScript syntax, 21 artifact tests, and a
fresh canonical browser-creation run (12 creation scenarios, four delayed-open
cases and 19 natively verified requests). The capture also retains the separate
959-test full native result at `67a19783`; that is the prior source, not a claim
that this change received another full-suite run.

`CAPTURE.zip` contains 1,207 members and has SHA-256
`4d185386ceb3dafa4d2f80f7538c0f539f81c36e6bcb8c574d716eb8444c2576`.
`CHECKS.json` records the supplementary physical-file capture hash. Public trust
inputs, requests, grants, exact adapter/source inputs and commands are retained;
private issuers, private stores and browser profiles are excluded. Two early
harness attempts used incorrect error-enum expectations, and a native test file
needed an explicit filesystem-test import after the module change; those
failures are retained rather than counted as product regressions or successes.

Positive required-witness browser activation, transport, complete lifecycle,
final unified product bindings, installed browser packaging and migration remain
open. Same-origin isolation, whole-profile rollback and cryptographic erasure
are not established by these tests. Logical staging cleanup is not secure erasure;
browser strict transactions/flushes are not native power-loss evidence. The
separate installed Rust/C/Swift qualification and hosted CI have their own source
identities and results.

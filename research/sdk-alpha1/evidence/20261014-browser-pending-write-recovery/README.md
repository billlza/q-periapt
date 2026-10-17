# Installed browser recovery of an expired ordinary write

Source commit: `0ec04f370b8c9edfb883183d8b213744f5bf5897`.
This is an unpublished candidate checkpoint, not release or protocol admission.

The installed browser owner now prepares complete metadata for the original
ordinary pending write and confirms an independently approved exact witness
target. It reuses the existing operation, cancellation and storage ownership
mechanisms. Confirmation sends a fresh signed Query, applies the original sealed
target, and creates no runtime or new traffic permission. The immutable request
exposes canonical approval inputs and complete JSON source/target inspection.

Eight fresh cohorts completed with 263 Worker calls, actual IndexedDB/OPFS and
separate native witness/controller processes on the same host:

| Scenario | Worker calls | Result |
| --- | ---: | --- |
| Original Advance not dispatched | 31 | Exact recovery, renewal and cleanup |
| Advance applied, G/T already staged | 30 | Original approval preserved |
| Advance applied, reply lost | 30 | Read-only exact confirmation |
| Advance not dispatched, G/T already staged | 31 | Original approval preserved |
| Close while signed Query reply is held | 33 | `Cancelled`, closed owner, exact recovery |
| Worker terminated before local confirmation | 33 | Original pending write retained |
| Worker terminated after local confirmation, before host result | 33 | Durable target, exact retry |
| Existing retirement journal interruption | 42 | Complete report and erasure recovery |

Each recovery cohort begins with a two-recipient account operation, one actual
business effect and a lost acknowledgement. Credential and policy expiry use the
actual wall clock. The controller independently retains the exact approval and
complete original metadata before privileged completion. The original session,
operation, message and closure identities survive recovery and G/T renewal.
Complete loss reports are durably retained before host acknowledgement. Unknown
delivery outcomes remain unknown, and recovery does not replay business traffic.
Malformed metadata is rejected without contacting the witness; an unapproved
target and a later head are refused. Exact confirmation retries use Query only.

Both Worker termination cases observed the original root lease before termination
and its actual release before reopening. Termination alone is not treated as a
release receipt. The retirement regression checks the shared metadata projector's
existing authoritative role and complete original unknown-message accounting.

The browser runs used archive
`07e9511b818324b00c3d66d1117653ab5d2e58272bc3edcabfb551437824ae86`.
After documentation and commit identity were finalized, a clean-source rebuild
produced archive
`a1d84a7922bc29a2787d284e32d8d1e500bc26d9fd3d890827088626ccecd896`.
Both were actually installed outside the checkout. Their entire installed file
sets match; only `README.md` and `PACKAGE_CONTENTS.json` differ in content.
All WASM, JavaScript, types and dependency files are byte-identical. Both installed
Node consumer tests and TypeScript 7.0.2 strict NodeNext checks passed. The package
builder's `browser_runtime: not-run` field is retained unchanged; the separate
Worker receipts provide the browser results.

Strict product WASM Clippy, Rust 1.90 WASM compilation, workspace formatting,
53 package/inventory unit controls and the exact clean-source gate passed. The
tracked Rust inventory is 676 and checks both presence and removal of the new
modules. The final source changes after the initial package are documentation
only. Raw commands, tool identities, source hashes and terminal results are in
`CAPTURE.zip`; `CAPTURE.json` lists every member and its digest.

The failed cancellation harness is retained: it expected `WitnessTransport`,
although the existing explicit-cancellation mapping correctly returned
`Cancelled` with a completed close and no cleanup error. Only that exact test
expectation changed, followed by fresh cohorts. A fixture lock update attempt
also failed because the non-TLS fixture has no rustls dependency; its original
lock remained unchanged. Neither failed attempt is counted as a pass.

This checkpoint uses one shared protocol engine and loopback transport. It does
not establish independent-implementation interoperability, mobile-browser or
power-loss equivalence, attacker eviction, physical erasure or PCS. New-entry
storage-failure coverage and C/Swift/Kotlin exposure remain separate work. Prior
CI receipts for `8358ef7` are retained as prior-source results, not CI results for
this browser increment. No package or release was published.

Private owners, signing keys, databases, browser profiles and generated caches
are excluded. All completed and failed cohorts are sealed; subsequent execution
must use fresh identities, storage and output directories.

# Installed product browser lifecycle

The npm web entry now exposes typed enrollment, account/roster trust, protocol
policy and witness configuration alongside `QPeriaptContinuityDevice`. Policy
verification uses the existing real `QPeriaptRuntime`. Device creation generates
its identity in the browser; no private fixture material or digest-only runtime
is imported. The same device owner accepts enrollment, prepares original child
stores, activates with a required witness, and generates/recovers public prekeys.
Secrets, raw signing owners and database handles are not exposed.

The shared `BrowserDevice` carries ownership across those stages. The retained
`BrowserEnrollmentProbe` delegates to it instead of keeping a parallel creation
path. Pending operations own their state outside the public handle, reject
concurrent calls, and close on failure or drop. Explicit close cancels transport
and awaits actual storage release. The large enrollment state is boxed instead
of enlarging every operational-state move; this is not a measured speed claim.

The browser-only build feature follows the dependency direction from the private
WASM facade to the shared engine. Node retains its prior exports and does not
load IndexedDB/OPFS host modules. The package producer captures candidate source
inputs, enables the browser feature only for the web build, and includes all
required host modules and the resolved 103-package third-party license closure.
Rehashed missing/altered host modules are rejected by package verification.

The actual archive was installed outside the checkout and tested through its
public `web/index.js`, without an experimental WASM activation adapter. Eight
scenarios passed with 308 real witness requests: normal activation, pre-dispatch
close, wrong witness pin, dropped reply/timeout/close after a native witness
revision commit, corrupted signature and oversized reply. Each recovered the
original journal and 1,184-byte prekey. Each witness advanced only from revision
1 to 2 to 3, with a continuous authenticated head chain and unchanged fence.
Re-enrolling the original genesis did not reset that state. Native witness
processes use the same protocol implementation, not an independent implementation.

All eight scenarios also issued concurrent enrollment requests. The competing
request returned `WouldBlock`; the first operation completed and the same owner
returned its unchanged original request. The healthy case additionally rejected
an altered SDK signature and roster checkpoint, then reopened the original
operational state. Browser cancellation in this run used the public owner's
`close()` while an actual witness request was pending.

The current package also passed 10 installed browser window/Worker scenarios,
installed Node CommonJS/ESM tests, TypeScript 7.0.2 strict NodeNext checking,
strict engine/product WASM and product native Clippy, formatting, and 22 artifact
tests. The canonical shared-creation suite passed again, including its interrupted
creation and delayed-completion controls and 19 natively verified requests.

Package identities remain explicit:

- Lifecycle fault tests used archive SHA-256
  `71c5b9d54e659195e9b82a5eb288e0afea569c21898fb03680b3199412c5c26e`.
- The strengthened producer/current fixture produced archive SHA-256
  `0f4c55ee53087056e59e13ec5a41c45353528cdcaa6d2fa65178bca32dae0a02`.
  Its manifest SHA-256 is
  `cfc71ba6a8869febfb17c519ff1c48eae4e56969859124726350034d4a3a6d71`.
- All 19 files in the complete web/ and node/ runtime payloads are byte-identical
  across those packages. `RUNTIME_EQUIVALENCE.json` retains each file hash.
  Their manifests, source/producer records and consumer-fixture identities are
  kept separate. The 10-scenario browser run used the current installed package.

The captured failures include an initial wasm-pack argument-order error, the
large-enum Clippy diagnostic, and a real browser failure when the fixture server
did not serve the new host modules. Cargo flags were moved after the separator,
ownership uses a boxed enrollment, and the exact module whitelist was extended.
No test assertions were weakened or cryptographic checks bypassed.

`CAPTURE.zip` contains 2,623 members and has SHA-256
`ca6b7a3d46ec18b831a712a197d2fcd592cf66edbfbcd0627522ddb656c2217b`.
It retains both npm archives, source overlays against `d2b05748`, commands,
public requests/replies and trust inputs, witness readbacks and test results.
Private authority/wrapping keys, witness databases and browser secret state are
excluded. The original standalone Rust/C/Swift producer at `19108614` remains a
separate qualification; it was still live when this checkpoint was assembled.

This is a prerelease lifecycle integration, not complete 0.2.0 qualification.
Explicit recovery-status and structured-error surfaces, signed prekey publication,
session/root/roster/migration APIs, real HTTPS deployment, minimum-compiler browser
qualification and the broader release/research requirements remain open. Tests
of explicit close do not establish every possible internal future-drop cut.
Whole-profile rollback, malicious same-origin code, secure erasure and native
power-loss equivalence are not established here.

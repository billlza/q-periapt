# Shared Continuity engine: browser portability checkpoint

The existing Continuity library now compiles for `wasm32-unknown-unknown` and
executes its real dual-signature identity code in a browser window and dedicated
Worker. Native TCP I/O is a separate target-specific module. Signed witness
request/response validation stays in the shared client; native method bodies and
all three moved TCP tests were compared with the predecessor, allowing only the
required helper visibility and rustfmt changes.

The previous library failed before reaching its own code because unconditional
`mio` imports reject this target. `baseline.stderr` preserves that failure.
Removing the socket dependency alone would leave public witness/publication
paths calling unsupported `std::time::Instant::now()`. The new
`MonotonicInstant` reexports that exact native type on native targets and uses
pinned `web-time` 1.1.0 on the browser target. Credential validity still uses its
separate explicitly supplied time; attempt budgets, original deadlines and
cancellation behavior were not weakened. The lockfile adds the clock and its
five `js-sys` support dependencies without updating existing versions.

`web-time` uses the browser performance clock, as described in its
[upstream implementation](https://github.com/daxpedda/web-time/blob/v1.1.0/src/lib.rs).
This checkpoint covers windows and dedicated Workers with that capability.
It does not establish clock behavior during OS sleep or promise support for
worklets without a performance clock. Deadline objects remain within their realm.

The actual Rust 1.98.1 library check and both native/all-feature and browser Clippy
checks pass with `-D warnings`. Twenty-five native tests cover TCP framing,
partial-response cancellation, pending-connect deadlines, exact publication
recovery and publication expiry/commit failures. No test was removed or weakened.
The `bindings-wasm` CI job now also checks this isolated shared engine.

[RESULT.json](RESULT.json) records Chrome 154.0.8037.99 on macOS arm64:

- Each realm generates fresh root/device owners using actual platform entropy,
  issues a 5,474-byte credential and 3,499-byte roster, and verifies their exact
  account/roster binding with both ML-DSA-65 and ECDSA P-256.
- Separate mutations of the two signature components are refused. Closed root
  and device signing owners are unusable. A native private-key file open is
  refused; no volatile replacement file is supplied.
- A fresh 200 ms deadline begins unexpired and expires after the asynchronous
  delay: observed elapsed times were 252.4 ms and 260.4 ms.
- The native build independently consumes each realm's public fixture and
  verifies the same authority binding and both signature refusals. This is
  cross-target execution of the shared engine, not an independent protocol
  implementation or external enrollment authorization.

[CHECKS.json](CHECKS.json) pins the 65-member [CAPTURE.zip](CAPTURE.zip), SHA-256
`d9f9e08aaf7878b3472e894b007f42d0fd0af8597a76d160087a7ae310b09743`.
It contains exact WASM/glue, probe source and lockfile, public fixtures, raw
compiler/test/browser outputs, original transport source and current source
patch/snapshots. Earlier probe dependency and Rust source errors are retained.
Every archive member was reread; the native verifier binary hash is recorded.
The owned browser was closed and the owned server terminated with status 143.
Actionlint still reports the same two pre-existing `ubuntu-26.04` runner-label
diagnostics as the predecessor; this is not an actionlint pass.

The probe remains isolated from package exports. Browser Continuity installation,
authenticated journal recovery, account/root transitions and live witness/peer
transport are **not admitted** by these results. The previous
[OPFS transaction experiment](../20261012-browser-redb-opfs/README.md) is a
separate storage boundary. Joining that backend to the original journal and
witness operations is the next integration step; neither checkpoint replaces
that work or the full 0.2.0 release requirements.

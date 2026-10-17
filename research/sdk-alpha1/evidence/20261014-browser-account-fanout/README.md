# Browser complete-account delivery

The installed WASM package exposes complete-account submission over the shared
portable session owner. A caller retains one original aggregate ID, shared input
and the complete set of existing recipient sessions. The journal authenticates
the signed roster, reserves and commits all required local messages together,
then permits one selected member exchange. It does not loop over individual
send operations or promise atomic remote business effects.

Four fresh Chrome scenarios exercise two native receivers under one independently
issued three-device roster: local protection, required witness with lost ACK,
receiver business effect followed by application failure, and actual Worker
termination after the native receiver result but before delivery of its reply.
Each scenario retains the original aggregate, per-session message identities and
ciphertext on retry. The business-effect file's device, inode, size and timestamp
remain unchanged. A previously confirmed member returns with zero exchanges;
the second member completes independently. Whole-aggregate retirement is refused
until every member has an authenticated or explicitly accounted disposition.

The same runs reject omitted, duplicate and empty recipient sets, an unavailable
selected member, closed input and closed policy. Ten invalid JavaScript index
values include negative/fractional numbers, NaN, infinity, non-number types,
wrapped-u32 and unsafe integers. No rejected pre-submission input reserves the
aggregate, advances member positions or dispatches peer traffic. Both selected
member and metadata index zero are exercised by the successful flow. Retrying
an aggregate with altered plaintext fails; unary delivery cannot bypass its
aggregate release checks. Metadata reconciliation returns the complete original
set without sending or completing a reservation.

Two defects in the new, uncommitted implementation were reproduced and corrected:

- On native targets, the async-to-sync transform removed an async block's scope.
  An early successful retained-ACK return bypassed operation finalization and
  closed the owner. A direct assertion reproduced this; a separate attempt method
  now funnels every successful return through the guard's finalization.
- The initial WASM binding reused a positive-only capacity validator for
  zero-based indices. The actual installed browser package refused position zero
  in run02. An account-specific bounded integer validator fixes selected delivery
  and member queries while preserving positive-only timeout/capacity contracts.

The initial browser driver also shadowed its CLI session name, and an initial
native TLS filter selected zero tests. Failed receipts remain archived. The
browser driver's owned session was explicitly closed, and the zero-test attempt
is excluded from validation. The explicit owned_connection integration target
passed three tests; portable session tests passed 13 and fanout tests passed 61,
including eight native TLS fanout tests. Native and WASM strict Clippy, Rust 1.90
WASM compilation, installed Node tests and TypeScript 7.0.2 strict NodeNext passed.
The package producer's browser_runtime: not-run receipt is retained unchanged;
the actual Chrome executions have separate terminal receipts.

run04 completed the after-effect scenario, then failed during the next scenario's
bootstrap before its planned Worker cut. The native receiver completed both
bootstrap replies, but the browser's 10-second invocation deadline expired and
closed the owner. That failed run remains in the capture. A fresh run05 records
browser and native monotonic timings while retaining the same 10-second bound and
all assertions. The older trace cannot distinguish browser scheduling from
cryptographic/storage tail latency; these finite passes establish no latency SLO.

The new carrier, browser owner, WASM API and value types live in dedicated modules
of 259, 64, 206 and 146 lines. Native TLS and portable carriers share the retained
outcome mapping, and both active and historical reconciliation use the same
metadata helper. This reduces duplicate state interpretation. No runtime
performance improvement is claimed, and source length is not a performance
measurement. The exact Rust source inventory increases from 648 to 653 files.

CHECKS.json binds the source overlay, installed archive, manifest and execution
counts. CAPTURE.zip contains public traces, producer inputs, command receipts,
counterexamples and source snapshots. Signing/wrapping keys, storage databases
and browser profiles are excluded. All scenarios use the same protocol engine on
one macOS arm64 host; this is not independent-implementation interoperability.

These APIs require an activated original device. Browser access to restricted
aggregate recovery/abandonment after expiry or retirement remains open, as do
additional authority races, reservation/commit interruption and cancellation
boundaries. Broader platform lifecycle, independent hosts/implementations, PCS,
performance, current CI and final release admission remain separate. Previously
accepted physical-device and protected historical cohorts were not reopened.

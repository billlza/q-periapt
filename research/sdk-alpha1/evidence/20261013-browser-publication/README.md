# Browser-owned prekey publication

The product web entry now exposes a bounded publication plan, original operation
ID, preparation/recovery, immutable status, abandonment and local artifact
retirement. These methods delegate to the existing registered native owner and
publication state machine. They do not export a signer or private key, replace
an interrupted operation, or turn local preparation into remote publication.
The host supplies current trusted time through a synchronous BigInt callback;
the shared engine resamples it across durable work and before public release.

This checkpoint is based on `238dd253` plus the exact 20-file overlay recorded in
`CHECKS.json`. Its final installed npm archive is SHA-256
`8a6457993e8e681cf8ebc81ea7e0fbf6c98bc4de59755f3f3fba7e142a38b526`;
the manifest is
`6038788cb425c9d48f3dc0070736fc6ed1dd8e5aa387684c31d8d8a31dad240a`.
The capture retains public protocol records, source overlays, exact package
reports/archives, test helpers and terminal failures. All authority private-key
and wrapping-key directories are excluded.

## Reproduced input-boundary failures

The intermediate generated JS/WASM interface silently converted fractional,
string, boolean, overflowing, negative-wrapping and coercible-object key roles
into valid enum values. The final interface checks the original JS values before
conversion, including the existing `generate_prekey` method. Publication and
prekey timestamps also use checked unsigned 64-bit BigInt conversion.

A second intermediate control exposed an error-reporting defect: converting an
invalid timestamp object to an error message invoked its throwing `toString()`
while Rust held a mutable borrow. Subsequent operations and `free()` were refused
by the Rust borrow guard. The repaired input/clock error wrapper retains the
original cause without reading its getters or invoking coercion hooks. The same
control now returns `InvalidInput`, then successfully uses and frees the plan.
Clock errors retain `InvalidClock` even if the original exception carries a
misleading `Busy` code. Actual Proxy exceptions retain cause identity and close
the device before recovery.

## Actual validation

- Final package: ten publication cases and **1,445** real signed witness requests.
  These cover byte-identical signed-artifact retry across Workers/reopens,
  conflicting intents, wrong retirement digests, expiry after reservation,
  invalid/throwing/hostile/coded clocks, cancellation, deadlines, abandonment,
  retirement and refusal of concurrent operations without closing the active owner.
- A native process verifies the account/roster, signed policies, independently
  expected manifest context and every public membership proof. Signature and
  proof bit flips both fail specifically with `Authentication`. This verifier
  uses the same Rust engine; it is not an independent protocol implementation.
- Nine pre-existing lifecycle/fault cases and **357** witness requests pass on
  the final package, preserving original journal/prekey identity after recovery.
- Ten installed browser cases pass in windows and dedicated Workers. Each
  roundtrip has exactly 178 assertions, including 96 publication input checks.
  Installed Node checks and strict TypeScript 7.0.2 checks pass.
- Product and engine WASM Clippy pass with `-D warnings`; formatting passes.
  The 41 relevant packaging tests and 44 Rust inventory tests pass. The tracked
  Rust inventory remains exact and now includes the two new modules (596 files).

Earlier failures are retained: the diagnostic verifier initially bounded the
pretty-printed public JSON too tightly, then compared the manifest's SDK policy
digest with the protocol policy digest. Both mistakes were corrected against
actual input sizes and the existing publication/bootstrap contract. A browser
driver also retained the old assertion count after adding boundary checks; the
fixed count is explicit, not a relaxed threshold. These are test-harness failures,
not evidence that the original product cryptography failed.

## Limits

This is local Chrome/Node candidate qualification, not deployed HTTPS or minimum
browser/compiler qualification. Expiry is an injected trusted-clock cut, not a
demonstration of real expired-policy renewal. Browser inventory maintenance,
connections, root/roster workflows and migration still require integration.
Current hosted CI/CodeQL, native package qualification, independent implementations,
performance and the broader recovery-security analysis remain separate. No release
or publication was performed and `release_claim_eligible` remains false.

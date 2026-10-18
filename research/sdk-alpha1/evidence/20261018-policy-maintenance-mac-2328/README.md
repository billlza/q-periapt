# Exact CI maintenance package consumed on Apple Silicon

The completed job `117682462549` in run `39129232908` produced the maintenance
package from `23280124efd2f0f3003d4ce85e3db665f6ec8a25`. Artifact `12147166313`
contains 44 members and 1,270,858 bytes, SHA-256
`5b8706a7fe4fcfb2cf015a8c858a0fc01273bbd5d5e7362545cb4271ec28a7db`.
No live job logs were fetched.

The downloaded archive was checked against its exact Git source: 39 explicit
package inputs, the canonical 383-file Rust workspace digest, all 206 payload
files and 90 dependency license packages. Its 303 tar entries have canonical
paths and modes, without links or special files. The package manifest SHA-256 is
`9341aba75748b9281e67cdfe0a3ed3e76637cb1255886fe3a9897b0bb8231b40`.
The actual Mach-O ARM64 executable SHA-256 is
`8c41247e36632253195805d9a35bc71277f05d977b301274a87960bd0ce215c7`.
The declared deployment target is macOS 13.0; this is not execution on macOS 13.

The actual downloaded binary was extracted and executed outside the checkout,
without rebuilding or installing globally. A retained real redb 2.6.3 fixture
was converted in place from slots `[2,2]` to `[3,3]`, preserving its inode and
independently expected trusted policy state. All seven cases passed: original
conversion, already-current retry, oversized trust input, missing storage, two
corrupted-slot refusals, and final retry. Refusals returned nonzero without a
success receipt and left their inputs unchanged. Producer outputs were also
checked against their recorded hashes.

The local adapter changes only the original qualification script's temporary
fixture lifetime and explicit source location. All fixtures, including refused
inputs, remain available after execution; it does not delete/recreate failed
state. The original acceptance assertions are unchanged. Only public fixture
materials were used; no user database was opened.

`CAPTURE.zip` is 1,287,849 bytes with 39 members, SHA-256
`573c567cbe167c61a67c175317585dd2cef7bf5724387ba18e97ddd792ab18c6`. It retains the original artifact, package readback,
local command receipts and the exact lifetime adapter with a verified manifest.

This is policy-store format migration qualification. It does not establish
Continuity storage migration, minimum-OS execution, actual power-loss durability,
full installed lifecycle or release readiness.

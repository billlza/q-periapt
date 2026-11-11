# Local SDK policy authority

Source: `e13efcaf23d38fb88ea52fd9aefa79724b6967e2`.

The native SDK policy authority provisions its own protected signing owner and
retains the original operation before signing. It commits the exact signed result
before export, allocates sequential policy versions, and preserves historical
results when private signing files are unavailable. The SDK and protocol signing
roles remain separate. The operator flow uses no fixture SDK signing key.

Verified locally:

- Native crypto: 16 entries, comprising 14 behavioral tests and two child-process
  dispatchers. SDK signatures are checked through the actual SDK policy loader.
- Reference application: 42 entries in both Debug and Release, comprising 39
  behavioral tests and three child-process dispatchers. The new authority covers
  eight real process-kill cuts during key creation, issuance and cancellation.
- Strict Clippy for the native library and all reference targets, formatting,
  workflow syntax and release builds.
- Installed independent Python implementation: eight adapter tests and 16 client
  tests, using cryptography 48.0.1 / OpenSSL 4.0.1.
- The two operator CLIs: 24 commands, including seven expected refusals, two SDK
  policy versions and three protocol policy versions. Public signatures and exact
  original export consistency were independently reverified.

Three initial native tests failed before key creation because their temporary
fixture directory was mode 0755. The fixture now explicitly establishes mode 0700;
production admission checks were unchanged. Failed empty directories remain local,
and the original failure output and fixture source are included in the capture.

`RECEIPT.json` binds the capture to its source. `PUBLIC_MANIFEST.json` inside the
capture inventories all 297 members except itself. The installed qualification
used an ordinary Git checkout, 134 bound source inputs and a 50-module wheel
installed outside the checkout. Private databases, signing keys and wrapping keys
are excluded. Native binary hashes are producer observations, not reproducible
build claims. Signature readback did not backdate activation.

Sequential allocation prevents accidental version jumps through this issuer; it
does not recover from a compromised root or remove the SDK's finite version space.
Local operator trust is assumed, and the witness pin remains a test input. Consumer
activation, independently authorized root replacement, real host-authorized device
enrollment and full lifecycle acceptance remain separate. These results do not
establish power-loss recovery, cryptographic erasure, PCS or release readiness.

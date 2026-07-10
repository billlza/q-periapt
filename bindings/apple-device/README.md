# Apple Device Runner

This runner is the physical-device lane for the Swift/C ABI face. It is intentionally
separate from the Swift Package tests: SwiftPM's tool-hosted XCTest can run on macOS,
but Xcode refuses to run it directly on an iPhone or iPad without a host app.

The app links the same generated C header and the same Rust `q-periapt-ffi` static
library built for `aarch64-apple-ios`. At launch it runs the shared vector
decapsulation, shared vector encapsulation, empty-ContextBound rejection,
CompatXWing seed-dk roundtrip, all combiner vectors, and the ML-DSA-65
signed-policy vector including rollback and tamper rejection. It prints exactly one
machine-readable result marker to stderr and to
`Documents/qperiapt-device-result.txt` plus a run-bound
`Documents/qperiapt-device-result-<run-id>.txt` file in the app data container:

- `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>`
- `QPERIAPT_DEVICE_FAIL <reason>`

Run through the repo-level wrapper:

```sh
QPERIAPT_DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
DEVELOPMENT_TEAM=<team-id> \
QPERIAPT_IOS_DEVICE_ID=<physical-device-udid> \
sh artifact/apple-device-smoke.sh
```

For iPhone+iPad matrix proof, pass both physical device ids explicitly:

```sh
QPERIAPT_DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
DEVELOPMENT_TEAM=<team-id> \
QPERIAPT_IOS_DEVICE_MATRIX='ipad:<ipad-udid>,iphone:<iphone-udid>' \
sh artifact/apple-device-xcode27-gate.sh
```

For a physical device, signing must be configured locally. Set `DEVELOPMENT_TEAM`
when Xcode cannot infer a team. Set `QPERIAPT_ALLOW_PROVISIONING_UPDATES=1` only
when allowing Xcode to create or update local development profiles is acceptable.
The wrapper fails closed when it cannot resolve the explicit physical
iOS/iPadOS destination(s), when the built bundle id differs from the requested
bundle id, or when the copied result marker does not match the per-run id. It
also emits per-device proof JSON, which binds the run id, source hashes,
app/staticlib hashes, build log hash, profile metadata, codesign entitlements,
signed-policy vector hash, device family, and weak-link checks for the Xcode 27
AppIntents workaround. The matrix wrapper adds `apple-device-matrix-proof.json`
and refuses to treat one device family as proof for the other. Proof verification
requires proof inputs under `artifact/device-runs`, app/staticlib artifacts under
`target`, and a positive `QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS` no larger than
seven days.

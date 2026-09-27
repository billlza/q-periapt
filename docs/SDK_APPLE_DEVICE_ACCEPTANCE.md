# Apple SDK device acceptance

The `sdk-alpha1` capture profile exercises the public Swift SDK owners against
the ABI 2 library built from the selected source. It identifies package
`0.2.0-alpha.1`, ABI major **2**, extension revision **1**. It does not change
the original nine C entry points or promote a historical 0.1.5 device proof.

The workload completes these four groups before it emits a success marker:

1. Existing compatibility and signed-policy vectors, with the SDK version check.
2. Owned key/secret roundtrips at context lengths 0, 32 and 65,536; all five
   named derivation purposes, pairwise purpose separation, implicit rejection,
   context-limit refusal, explicit close and runtime revocation.
3. Explicit expanded-key export/import, malformed import refusal, signed policy
   revocation, stale-owner refusal and recovery with a newer signed policy.
4. Key quota exhaustion/recovery, cancellation before the public asynchronous
   call, and four concurrent asynchronous decapsulations through one owner.

The policy-update fixture uses a **test-only in-memory state slot**. This suite
does not qualify durable iOS rollback protection, cancellation during a native
operation, installed Swift-package consumption, performance, energy use or
general constant-time behavior. Those requirements retain their separate gates.

## Build and host regression

From a clean macOS checkout with the configured Rust target installed:

```sh
sh artifact/apple-sdk-device-check.sh
```

This builds the native library, executes the same workload on macOS, and links
the full iOS runner for `arm64-apple-ios16.0`. Its output under
`target/apple-sdk-device-check` is retained on failure; an existing attempt is
refused. The CI Swift job runs this check and retains its logs. Its success
message explicitly says `physical_device_qualified=false`; it never emits the
device marker. This compile check does not install, sign or launch an iOS app.

The `QPeriaptSDKDeviceRunner` scheme in `bindings/apple-device/project.yml` is
the app build used by physical capture. Its source paths require the explicit
`QPERIAPT_SOURCE_ROOT` build setting; `apple-device-smoke.sh` provides it. Swift
strict concurrency and warnings-as-errors apply. Rust and C native dependencies
use the same existing iOS 16 deployment floor, avoiding their divergent defaults.

## Physical capture

The operator must explicitly select the devices and development team and
authorize signing/installation before running this command. It uses random
run-owned bundle identifiers and the existing ownership-checked cleanup path.
Automatic provisioning/profile updates remain disabled unless separately enabled.

```sh
QPERIAPT_APPLE_CAPTURE_PROFILE=sdk-alpha1 \
QPERIAPT_DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
QPERIAPT_IOS_DEVICE_MATRIX="ipad:$IPAD_ID,iphone:$IPHONE_ID" \
DEVELOPMENT_TEAM="$TEAM_ID" \
sh artifact/apple-device-matrix.sh
```

Both SDK devices must be wired. Each attempt requires fresh derived-data and
private evidence directories; earlier successes and failures are not cleared.
The two-device matrix records its observed OS versions. It does **not** also
qualify the minimum supported OS unless those devices actually run it; current
and minimum-OS acceptance need their own source-bound captures.

This SDK profile selects the Mac App Store installation at
`/Applications/Xcode.app/Contents/Developer`. It requires the complete App Store
certificate chain, Xcode identifier `com.apple.dt.Xcode`, Apple team
`59GAB85EFG`, deep strict signature verification and Gatekeeper acceptance with
`source=Mac App Store`. Root ownership, canonical paths, bounded reads and exact
tool/SDK hashes remain required. This is a fixed distribution choice, not an
arbitrary developer-directory override. Apple documents the App Store
[certificate identity](https://developer.apple.com/documentation/technotes/tn3161-inside-code-signing-certificates)
and [Xcode Gatekeeper result](https://developer.apple.com/library/archive/qa/qa1900/_index.html).
The legacy profile retains its distinct Xcode-27.0.app / Apple System contract.

## Proof identity and remaining gates

SDK device and matrix proofs use schema 1 with distinct kinds
`qperiapt.apple_sdk_device_proof` and `qperiapt.apple_sdk_matrix_proof`. Verification
must explicitly request `--capture-profile sdk-alpha1`; it never selects the
profile from proof-controlled fields. The device marker binds version, ABI,
extension, all four completed groups and a fresh run nonce. Missing groups,
wrong versions, mixed profiles, duplicate markers and legacy markers are refused.
The supplemental hashes include the SDK wrapper, workload, policy-update vectors
and ABI contract, in addition to the canonical source digest and existing binary,
toolchain, device, signing, freshness and private-evidence checks.

Historical device schema 4, matrix schema 5 and their release-manifest bindings
remain legacy-only. SDK captures are separate qualification inputs and cannot
be inserted into the old release manifest as equivalent evidence. A successful
host regression, unsigned app build or toolchain receipt is not a physical-device
proof. Physical/current/minimum-OS runs, packaged device acceptance, independent
review and the coordinated 0.2.0 release transaction remain open.

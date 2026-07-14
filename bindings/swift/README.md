# QPeriaptHybrid (Swift)

Swift face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI.

This is a stateless KEM/policy binding. It has no prekey directory, ratchet state,
message store, multi-device manager, or recovery API; its tests cannot establish
PQ3/Signal session parity. The future session plan and distinct evidence gates are in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

> **Verified** ✅ — `swift test` passes through the ABI 2 product path:
> signed policy, exact digest/state, OS-random key generation and encapsulation,
> context-bound roundtrip, rollback/tamper/legacy-state rejection, and secret wipe.
> Requires the static library to be built first.

## Build

```sh
# 1. Build the C ABI static library from the repo root:
cargo build -p q-periapt-ffi --release        # -> target/release/libq_periapt_ffi_abi2.a

# 2. Keep the vendored header in sync (Sources/CQPeriapt/q_periapt.h):
cp crates/q-periapt-ffi/include/q_periapt.h bindings/swift/Sources/CQPeriapt/q_periapt.h

# 3. Build / test the Swift package:
cd bindings/swift && swift test
```

`Package.swift` links `../../target/release` via `-lq_periapt_ffi_abi2`.

## Usage

```swift
import QPeriaptHybrid

precondition(QPeriaptHybrid.runtimeAbiVersion == QPeriaptHybrid.abiVersion)
precondition(QPeriaptHybrid.fixedSuiteId == Array("ML-KEM-768+X25519".utf8))
let decision = try QPeriaptHybrid.decisionFromSignedPolicy(
    toml: policyBytes, signature: signature, verificationKey: pinnedVerificationKey,
    lastTrustedState: storedState)
var keys = try QPeriaptHybrid.generateKeypair(decision: decision)
var enc = try QPeriaptHybrid.encapsulate(
    decision: decision, pkPq: keys.pkPq, pkTrad: keys.pkTrad,
    applicationContext: transcript)
let secret = try QPeriaptHybrid.decapsulate(
    decision: decision,
    skPq: keys.skPq, ctPq: enc.ctPq, pkPq: keys.pkPq,
    skTrad: keys.skTrad, ctTrad: enc.ctTrad, pkTrad: keys.pkTrad,
    applicationContext: transcript)
keys.wipeSecrets()
enc.wipeSecret()
```

The product binding exposes no caller-supplied key seeds or encapsulation coins and
no raw/CompatXWing/combine operation. Internal Rust KATs retain deterministic
conformance coverage. The test consumes `bindings/signed-policy-vectors.json` to
prove `decisionFromSignedPolicy` returns one
read-only, authenticated decision containing the profile, fixed-suite code, policy version,
policy digest, and next trusted state. The test reapplies the same trusted state successfully
and fails closed on rollback, a tampered ML-DSA-65 signature, or ABI 1's four-byte
version-only state. The verification key must be pinned independently of the policy
channel. Callers use the default empty trusted state only for explicitly provisioned
first acceptance, then persist each returned `trustedState` atomically and supply it
to the next policy verification; missing/corrupt storage must not silently become first use.

This package remains the source-tree development binding: `Package.swift` links the native
library from `../../target/release` so local Swift tests can exercise the live Rust build.
Product distribution is checked separately by:

```sh
sh artifact/swift-xcframework.sh
```

That release gate builds a universal macOS slice, iOS device slice, and iOS simulator slice into
`target/qperiapt-swift-xcframework/.../CQPeriapt.xcframework.zip`, computes the SwiftPM checksum,
executes three macOS tests through an isolated `binaryTarget(path:)` consumer, performs separate
warning-free SwiftPM final links for the `arm64` and `x86_64` macOS triples, and performs final
warning-free links of the same minimal executable for generic iOS device and simulator destinations.
Those link probes verify the selected `.a` bytes against the exact XCFramework slices. The
credentialed release lane also executes both macOS probes in their matching architecture execution
modes; the iOS probes are compile/link evidence, not physical-device execution or an
app-signing/provisioning result.
The gate requires a clean worktree for release proof; use
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics.

Credentialed Apple distribution is intentionally separate from that CI path:

```sh
QPERIAPT_APPLE_RELEASE_CONFIRM=0.1.0-alpha.2 \
QPERIAPT_NOTARY_KEYCHAIN_PROFILE=<prevalidated-profile> \
sh artifact/swift-xcframework-release.sh
```

It builds in a detached worktree pinned to one source commit, Developer ID-signs only the outer
static XCFramework, verifies that signing did not alter the three `.a` slices, exercises an exact
ZIP extraction through the isolated consumer, and submits that same ZIP to Apple Notary Service.
Before the only network submission, an immutable private ledger durably binds the source commit,
ZIP SHA-256, and signing evidence. The complete validated release tree is synchronized before that
ledger is created. The same bounded transaction also synchronizes the detached non-`target`
source tree and the main Git metadata/object tree, rejects external object stores and Git
environment/configuration overrides, validates the exact linked-worktree admin binding, and
performs one final Darwin device-cache barrier. All three captured trees are revalidated both
immediately before and after that barrier, so the exact ZIP, source, and recovery state remain
available to the UUID-bound recovery path after a power loss. The release runs under a dedicated
current-user/private-directory trust boundary; concurrent mutations are fail-closed, while a
separate malicious process running as that same user after validation is outside the boundary.
The returned UUID is bound separately, so a crash after Apple
accepts the upload cannot trigger an automatic re-submit. Supplying
`QPERIAPT_NOTARY_SUBMISSION_ID=<uuid>` resumes only those preserved bytes; it does not rebuild,
re-sign, re-zip, or submit again.

The release asset is an XCFramework for a SwiftPM binary target, not a complete remote Swift
package. Use the exact URL and checksum from the tag's verified `MANIFEST.json`:

```swift
.binaryTarget(
    name: "CQPeriapt",
    url: "<exact GitHub release asset URL>",
    checksum: "<MANIFEST.json artifacts.xcframework_zip.swiftpm_checksum>"
)
```

The `QPeriaptHybrid` wrapper source must come from the same source commit recorded by that
manifest. A release is accepted only after a URL-based consumer re-downloads the public asset,
passes the same three macOS tests, and repeats both per-architecture macOS final links and the iOS
device/simulator final-link probes through `artifact/swift-xcframework-remote-consumer.sh`, with the
URL, SwiftPM checksum, ZIP SHA-256, and source commit supplied from verified release evidence.
Developer ID/notary acceptance covers the submitted SDK ZIP; it is not
an iOS-app notarization. Consuming iOS apps still require their own signing and provisioning, while
consuming macOS apps require their own distribution signing and notarization. ZIP archives cannot
carry a stapled notarization ticket, so `stapled=false` is an explicit format boundary rather than a
silent omission. Published prerelease assets are immutable: a post-publication URL-consumer failure
invalidates that prerelease and requires a new version; it must never be repaired by replacing the
asset under the same tag.

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
and runs an isolated `binaryTarget(path:)` product consumer.
The gate requires a clean worktree for release proof; use
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics.

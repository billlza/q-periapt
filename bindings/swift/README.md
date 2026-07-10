# QPeriaptHybrid (Swift)

Swift face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI.

> **Verified** ✅ — `swift test` passes against the shared reference vector
> (Swift → C ABI → Rust core, byte-for-byte) and covers a CompatXWing seed-dk
> roundtrip. Gated in CI (`bindings-swift`,
> macOS). Requires the static lib to be built first (below).

## Build

```sh
# 1. Build the C ABI static library from the repo root:
cargo build -p q-periapt-ffi --release        # -> target/release/libq_periapt_ffi.a

# 2. Keep the vendored header in sync (Sources/CQPeriapt/q_periapt.h):
cp crates/q-periapt-ffi/include/q_periapt.h bindings/swift/Sources/CQPeriapt/q_periapt.h

# 3. Build / test the Swift package:
cd bindings/swift && swift test
```

`Package.swift` links `../../target/release` via `-lq_periapt_ffi`. On Linux the lib is
`libq_periapt_ffi.so`; adjust `linkerSettings` for your target as needed.

## Usage

```swift
import QPeriaptHybrid

let (skPq, pkPq) = try QPeriaptHybrid.mlkem768Keypair(seed: seed64)
let (skX,  pkX)  = try QPeriaptHybrid.x25519Keypair(secret: scalar32)
precondition(QPeriaptHybrid.runtimeAbiVersion == QPeriaptHybrid.abiVersion)
precondition(QPeriaptHybrid.fixedSuiteId == Array("ML-KEM-768+X25519".utf8))
let secret = try QPeriaptHybrid.decapsulate(
    profile: .contextBound, suiteId: suiteId, policyVersion: 1,
    skPq: skPq, ctPq: ctPq, pkPq: pkPq,
    skTrad: skX, ctTrad: ctX, pkTrad: pkX, context: context)

let (xwingSkPq, xwingPkPq) = try QPeriaptHybrid.mlkem768XWingKeypair(seed: seed32)
let xwingSecret = try QPeriaptHybrid.decapsulate(
    profile: .compatXWing, suiteId: suiteId, policyVersion: 1,
    skPq: xwingSkPq, ctPq: xwingCtPq, pkPq: xwingPkPq,
    skTrad: skX, ctTrad: xwingCtX, pkTrad: pkX, context: [])
```

Use `mlkem768Keypair(seed:)` for `ContextBound`'s expanded key path and
`mlkem768XWingKeypair(seed:)` for `CompatXWing`; passing an expanded ML-KEM secret
key to `CompatXWing` is rejected. The test (`Tests/QPeriaptHybridTests`) decapsulates
`bindings/shared-test-vectors.json`, vector-checks encapsulation, and asserts the
CompatXWing seed-dk roundtrip. It also consumes
`bindings/signed-policy-vectors.json` to prove `profileFromSignedPolicy` selects
the signed profile and fails closed on rollback or a tampered ML-DSA-65 signature.

This package remains the source-tree development binding: `Package.swift` links the native
library from `../../target/release` so local Swift tests can exercise the live Rust build.
Product distribution is checked separately by:

```sh
sh artifact/swift-xcframework.sh
```

That release gate builds a universal macOS slice, iOS device slice, and iOS simulator slice into
`target/qperiapt-swift-xcframework/.../CQPeriapt.xcframework.zip`, computes the SwiftPM checksum,
and runs an isolated `binaryTarget(path:)` consumer with the same seven Swift vector/policy tests.
The gate requires a clean worktree for release proof; use
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics.

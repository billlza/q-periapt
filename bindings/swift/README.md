# QPeriaptHybrid (Swift)

Swift face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI.

> **Verified** ✅ — `swift test` passes against the shared reference vector
> (Swift → C ABI → Rust core, byte-for-byte). Gated in CI (`bindings-swift`,
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
let secret = try QPeriaptHybrid.decapsulate(
    profile: .contextBound, suiteId: suiteId, policyVersion: 1,
    skPq: skPq, ctPq: ctPq, pkPq: pkPq,
    skTrad: skX, ctTrad: ctX, pkTrad: pkX, context: context)
```

The test (`Tests/QPeriaptHybridTests`) decapsulates `bindings/shared-test-vectors.json`
and asserts the secret matches the Rust core byte-for-byte.

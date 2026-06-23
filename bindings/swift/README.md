# PQTHybrid (Swift)

Swift face of the PQ/T hybrid suite over the `pqt-ffi` C ABI.

> **Scaffold** — not built in this repo's CI yet (needs an Xcode/Swift toolchain
> and the linked static lib). The wrapper and vector test are complete; wiring it
> into CI is tracked in `docs/ROADMAP.md` (M3).

## Build

```sh
# 1. Build the C ABI static library from the repo root:
cargo build -p pqt-ffi --release        # -> target/release/libpqt_ffi.a

# 2. Keep the vendored header in sync (Sources/CPQT/pqt.h):
cp crates/pqt-ffi/include/pqt.h bindings/swift/Sources/CPQT/pqt.h

# 3. Build / test the Swift package:
cd bindings/swift && swift test
```

`Package.swift` links `../../target/release` via `-lpqt_ffi`. On Linux the lib is
`libpqt_ffi.so`; adjust `linkerSettings` for your target as needed.

## Usage

```swift
import PQTHybrid

let (skPq, pkPq) = try PQTHybrid.mlkem768Keypair(seed: seed64)
let (skX,  pkX)  = try PQTHybrid.x25519Keypair(secret: scalar32)
let secret = try PQTHybrid.decapsulate(
    profile: .contextBound, suiteId: suiteId, policyVersion: 1,
    skPq: skPq, ctPq: ctPq, pkPq: pkPq,
    skTrad: skX, ctTrad: ctX, pkTrad: pkX, context: context)
```

The test (`Tests/PQTHybridTests`) decapsulates `bindings/shared-test-vectors.json`
and asserts the secret matches the Rust core byte-for-byte.

# pqt-hybrid (Kotlin)

Kotlin face of the PQ/T hybrid suite over the `pqt-ffi` C ABI, via the Foreign
Function & Memory API (Project Panama, **JDK 22+**).

> **Scaffold** — not built in this repo's CI yet (needs JDK 22+ and the linked
> native lib). The wrapper and vector test are complete; CI wiring is tracked in
> `docs/ROADMAP.md` (M3).

## Build

```sh
# 1. Build the native lib from the repo root:
cargo build -p pqt-ffi --release      # -> target/release/libpqt_ffi.{so,dylib}

# 2. Run the Kotlin tests:
cd bindings/kotlin && ./gradlew test
```

`build.gradle.kts` puts `../../target/release` on `java.library.path` and enables
native access. `System.mapLibraryName("pqt_ffi")` resolves the per-OS file name.

## Usage

```kotlin
val (skPq, pkPq) = PqtHybrid.mlkem768Keypair(seed64)
val (skX,  pkX)  = PqtHybrid.x25519Keypair(scalar32)
val secret = PqtHybrid.decapsulate(
    PqtHybrid.PROFILE_CONTEXT_BOUND, suiteId, policyVersion = 1,
    skPq, ctPq, pkPq, skX, ctX, pkX, context)
```

The test (`src/test`) decapsulates `bindings/shared-test-vectors.json` and asserts
the secret matches the Rust core byte-for-byte.

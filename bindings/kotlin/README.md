# q-periapt-hybrid (Kotlin)

Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
Function & Memory API (Project Panama, **JDK 22+**).

> **Verified** ✅ — `gradle test` passes against the shared reference vector
> (Kotlin → FFM → C ABI → Rust core, byte-for-byte). Gated in CI
> (`bindings-kotlin`, JDK 22 + Gradle 9.2.1). Needs a JDK ≥22 (stable FFM).

## Build

```sh
# 1. Build the native lib from the repo root:
cargo build -p q-periapt-ffi --release      # -> target/release/libq_periapt_ffi.{so,dylib}

# 2. Run the Kotlin tests on a JDK >= 22:
JAVA_HOME=/path/to/jdk22+ gradle -p bindings/kotlin test
```

`build.gradle.kts` passes the native lib's absolute path via `-Dqperiapt.lib` (robust on
macOS, where the loader ignores `java.library.path`), targets JVM bytecode 22, and
enables native access. The wrapper loads the lib by that path, falling back to
`System.mapLibraryName("q_periapt_ffi")`.

## Usage

```kotlin
val (skPq, pkPq) = QPeriaptHybrid.mlkem768Keypair(seed64)
val (skX,  pkX)  = QPeriaptHybrid.x25519Keypair(scalar32)
val secret = QPeriaptHybrid.decapsulate(
    QPeriaptHybrid.PROFILE_CONTEXT_BOUND, suiteId, policyVersion = 1,
    skPq, ctPq, pkPq, skX, ctX, pkX, context)
```

The test (`src/test`) decapsulates `bindings/shared-test-vectors.json` and asserts
the secret matches the Rust core byte-for-byte.

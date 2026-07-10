# q-periapt-hybrid (Kotlin)

Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
Function & Memory API (Project Panama, **JDK 22+**).

This is a host JVM binding, not the Android binding. Android apps should consume
the AAR/JNI surface under [`../android`](../android/), built by
`artifact/android-aar.sh`.

> **Verified** ✅ — `gradle test` passes against the shared reference vector
> (Kotlin → FFM → C ABI → Rust core, byte-for-byte) and covers a CompatXWing
> seed-dk roundtrip. Gated in CI
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
enables native access. The wrapper requires `qperiapt.lib` to be an absolute path to a
regular file, then validates the runtime ABI version and fixed suite id before exposing
cryptographic calls.

## Usage

```kotlin
val (skPq, pkPq) = QPeriaptHybrid.mlkem768Keypair(seed64)
val (skX,  pkX)  = QPeriaptHybrid.x25519Keypair(scalar32)
require(QPeriaptHybrid.runtimeAbiVersion() == QPeriaptHybrid.ABI_VERSION)
require(QPeriaptHybrid.fixedSuiteId().contentEquals("ML-KEM-768+X25519".encodeToByteArray()))
val secret = QPeriaptHybrid.decapsulate(
    QPeriaptHybrid.PROFILE_CONTEXT_BOUND, suiteId, policyVersion = 1,
    skPq, ctPq, pkPq, skX, ctX, pkX, context)

val (xwingSkPq, xwingPkPq) = QPeriaptHybrid.mlkem768XWingKeypair(seed32)
val xwingSecret = QPeriaptHybrid.decapsulate(
    QPeriaptHybrid.PROFILE_COMPAT_XWING, suiteId, policyVersion = 1,
    xwingSkPq, xwingCtPq, xwingPkPq, skX, xwingCtX, pkX, byteArrayOf())
```

Use `mlkem768Keypair(seed64)` for `ContextBound`'s expanded key path and
`mlkem768XWingKeypair(seed32)` for `CompatXWing`; passing an expanded ML-KEM secret
key to `CompatXWing` is rejected. The test (`src/test`) decapsulates
`bindings/shared-test-vectors.json`, vector-checks encapsulation, and asserts the
CompatXWing seed-dk roundtrip.

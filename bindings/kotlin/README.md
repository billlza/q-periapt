# q-periapt-hybrid (Kotlin)

Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
Function & Memory API (Project Panama, **JDK 22+**).

This binding exposes a stateless ABI2 KEM/policy operation surface and no prekey, ratchet, session-store,
multi-device, or recovery behavior. Its product tests cover signed policy/digest,
OS-random round trips, context separation, fail-closed state transitions, and secret
wipes rather than deterministic byte replay; none is session-protocol evidence. Future Continuity work is specified in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

This is a host JVM binding, not the Android binding. Android apps should consume
the AAR/JNI surface under [`../android`](../android/), built by
`artifact/android-aar.sh`.

> **Current-machine verification pending** — `gradle test` exercises
> signed-policy resolution, exact digest/state, OS-random key generation and
> encapsulation, context-bound roundtrip, legacy-state/rollback/tamper rejection,
> and secret wipe. It needs JDK 22+ (stable FFM); this machine currently has JDK 21.

## Build

```sh
# 1. Build the native lib from the repo root:
cargo build -p q-periapt-ffi --release      # -> target/release/libq_periapt_ffi_abi2.{so,dylib}

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
require(QPeriaptHybrid.runtimeAbiVersion() == QPeriaptHybrid.ABI_VERSION)
require(QPeriaptHybrid.fixedSuiteId().contentEquals("ML-KEM-768+X25519".encodeToByteArray()))
val decision = QPeriaptHybrid.decisionFromSignedPolicy(
    policyBytes, signature, pinnedVerificationKey, storedState)
val keys = QPeriaptHybrid.generateKeypair(decision)
val enc = QPeriaptHybrid.encapsulate(decision, keys.pkPq, keys.pkTrad, transcript)
val secret = QPeriaptHybrid.decapsulate(
    decision, keys.skPq, enc.ctPq, keys.pkPq,
    keys.skTrad, enc.ctTrad, keys.pkTrad, transcript)
keys.wipeSecrets()
enc.wipeSecret()
```

ABI2 does not expose deterministic seeds/coins, raw hybrid, CompatXWing, or combine
through the product FFM surface. Those remain Rust-internal KAT/conformance paths.
The host must pin the policy verification key and must not treat missing/corrupt
trusted-state storage as first enrollment.

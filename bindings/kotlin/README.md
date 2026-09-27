# q-periapt-hybrid (Kotlin)

The 0.2.0-alpha.1 product entry point is now `QPeriaptRuntime.fromSignedPolicy`.
Use `runtime.generateKey().use { key -> ... }`, `runtime.encapsulate(...)` and
`key.decapsulate(...)`; private keys remain in native owners unless transferred
through `QPeriaptExpert`. Public-key and
ciphertext wrappers are immutable; secret export is explicit. ABI major remains
2. See the [ownership contract](../../docs/SDK_OWNERSHIP.md) for close, Cleaner,
executor cancellation, limits and trusted-state persistence requirements.
`isEnabled()` reports whether the signed policy permits the fixed suite.
See [expert transfer](../../docs/SDK_KEY_TRANSFER.md) and
[policy updates](../../docs/SDK_POLICY_UPDATES.md) before integrating those APIs.

The commands below run both the owner SDK tests and legacy compatibility tests.
The `QPeriaptHybrid` byte-array interface remains available for existing consumers;
its example below documents that compatibility API. New product code should use
the owner entry point. No 0.2.0 package has been published yet.

Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
Function & Memory API (Project Panama, **JDK 25+**).

This binding exposes a stateless ABI2 KEM/policy operation surface and no prekey, ratchet, session-store,
multi-device, or recovery behavior. Its product tests cover signed policy/digest,
OS-random round trips, context separation, fail-closed state transitions, and secret
wipes rather than deterministic byte replay; none is session-protocol evidence. Future Continuity work is specified in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

This is a host JVM binding, not the Android binding. Android apps should consume
the AAR/JNI surface under [`../android`](../android/), built by
`artifact/android-aar.sh`.

> **Build toolchain** — CI uses Kotlin 2.4.10, JDK 25 LTS and Gradle 9.2.1.
> The binding targets JVM bytecode and the stable JDK 25 API. `gradle test` exercises
> signed-policy resolution, exact digest/state, OS-random key generation and
> encapsulation, context-bound roundtrip, legacy-state/rollback/tamper rejection,
> and secret wipe. The minimum consumer runtime is JDK 25; consumers of the
> earlier JDK 22 target must update their runtime. No preview features are enabled.

## Installable candidate

The Maven coordinate is `dev.qperiapt:q-periapt-hybrid:0.2.0-alpha.1`. The existing
Gradle project name stays `q-periapt-hybrid`. Binary and sources JARs include
version/ABI metadata and the project licenses. The only SDK dependency is
Kotlin stdlib 2.4.10. See [the packaged installation instructions](PackageREADME.md)
for classpath/module-path native access and explicit shared-library selection.

`publishSdkPublicationToSdkStagingRepository` writes only to a file repository.
It does not configure a remote registry or use Maven Central credentials.
The complete local qualification entry point consumes a matching C SDK produced
by `artifact/c-package.sh --profile sdk-alpha1`:

```sh
sh artifact/python-run.sh artifact/jvm_sdk_package.py \
  --output target/sdk-jvm-package \
  --native-archive /absolute/path/to/q-periapt-c-abi2-0.2.0-alpha.1-TARGET.tar.gz \
  --native-sha256 "$NATIVE_ARCHIVE_SHA256" \
  --native-manifest-sha256 "$NATIVE_MANIFEST_SHA256"
```

Select JDK 25 through `JAVA_HOME` and `PATH` for the invocation, as below. Gradle
9.2.1 and the existing strict dependency checksum policy are required. Add
`--offline` only when those tool/dependency artifacts are already cached. Every
output directory must be fresh. The native archive/manifest digests must come
from the inspected C candidate, not an unrelated package with the same name.

The producer rebuilds and tests the JAR against that native package, stages its
Maven version directory, checks bytecode/source/metadata/licenses, and installs
the resulting archive in a temporary project outside the checkout. That project
resolves the Maven coordinate and runs real owner/KDF/policy, cancellation and
concurrency calls. A Java module-path probe grants native access only to the SDK
module; six process-level negative controls cover configuration, permission and
missing-symbol failures. Logs and the final `INSTALLED_CONSUMER.json` retain the
actual resolved files and hashes. This is local diagnostic evidence; CI/platform
and stable-release requirements still apply.

Owner constructors are private and internal raw-handle accessors/factories are
hidden from Java source with `@JvmSynthetic`. This closes an accidental Java
construction/aliasing route; reflection and hostile code in the same JVM remain
outside that misuse-resistance boundary. The legacy public API is unchanged.

## Build

```sh
# 1. Build the native lib from the repo root:
cargo build -p q-periapt-ffi --release      # -> target/release/libq_periapt_ffi_abi2.{so,dylib}

# 2. Select the JDK 25 LTS build environment for this invocation:
(
  export JAVA_HOME=/path/to/jdk25
  export PATH="$JAVA_HOME/bin:$PATH"
  gradle -p bindings/kotlin test --no-daemon --warning-mode fail
)
```

`build.gradle.kts` passes the native lib's absolute path via `-Dqperiapt.lib` (robust on
macOS, where the loader ignores `java.library.path`), restricts Kotlin's available
JDK API and Kotlin/Java bytecode to 25, and enables native access. The wrapper
requires `qperiapt.lib` to be an absolute path to a
regular file, then validates the runtime ABI version and fixed suite id before exposing
cryptographic calls.

Missing required native symbols stop binding initialization with a
`NoSuchElementException` that names the symbol. Result descriptions redact shared
secrets and private keys; the data classes retain their existing copy and
destructuring behavior. Their secret arrays remain caller-owned and must still be
wiped after use.

Fixed-size key/ciphertext and signed-policy signature/key inputs are rejected
before native segment allocation or copying. The existing exception contract is
preserved: malformed KEM lengths throw `QPeriaptException` with the same operation
and code `-2`; malformed signature/key shapes use code `-3`. Null arguments,
context/TOML limits and trusted-state shape checks retain their existing
precedence and exception types. Eliminating the rejected input's temporary copy
also avoids its otherwise unnecessary native-memory demand. Binding length
constants are checked against the existing ABI2 contract, whose two new policy
length constants do not change the nine native function signatures.

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

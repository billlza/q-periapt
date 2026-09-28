# Q-Periapt JVM SDK 0.2.0

This local candidate contains a Maven repository with the fixed coordinate
`dev.qperiapt:q-periapt-hybrid:0.2.0` and one host-specific C SDK archive.
It has not been published to Maven Central. ABI major remains **2**; the owner
extension version is 1. Use a 64-bit **JDK 25** or later. The package producer
qualifies JDK 25; later JVMs and other operating systems need their own runs.
The Android binding is a separate AAR/JNI product.

Verify this archive against a trusted SHA-256 digest, then extract it. Configure
the extracted `maven` directory as a file Maven repository restricted to
`dev.qperiapt`, with Maven Central supplying Kotlin stdlib 2.4.10. Use the exact
coordinate above; this candidate does not provide dynamic-version metadata.
For example, a Kotlin Gradle consumer uses:

```kotlin
repositories {
    exclusiveContent {
        forRepository { maven { url = uri("/absolute/path/to/extracted-sdk/maven") } }
        filter { includeGroup("dev.qperiapt") }
    }
    mavenCentral()
}
dependencies { implementation("dev.qperiapt:q-periapt-hybrid:0.2.0") }
```

Extract the archive under `native/`, check its `MANIFEST.json` and library hashes
against `PACKAGE_CONTENTS.json`, and pass the full shared-library filename under
its `lib/` directory using `-Dqperiapt.lib=/absolute/path/to/library`. macOS uses
`libq_periapt_ffi.2.dylib`; GNU/Linux uses `libq_periapt_ffi.so.2`. The native
archive's target must match the JVM host. The JAR contains no native binaries and
does not download, extract or search for another library.

Classpath applications grant `--enable-native-access=ALL-UNNAMED`. With the SDK
on the module path, its automatic module is `dev.qperiapt.hybrid`; grant only
`--enable-native-access=dev.qperiapt.hybrid`. Include Kotlin stdlib on the module
path too. A classpath main using these modules must resolve both explicitly with
`--add-modules=dev.qperiapt.hybrid,kotlin.stdlib`; a named application declares
both dependencies in its module descriptor. `--illegal-native-access=deny`
enforces rejection of ungranted FFM access. JDK 25's default warning mode alone
does not enforce that rejection.

New integrations start with `QPeriaptRuntime.fromSignedPolicy(...)` and use
`use`/`close` for runtime, key, secret, derived key and pending update owners.
Java calls the Kotlin factory as `QPeriaptRuntime.Companion.fromSignedPolicy`.
Owner constructors and raw handle accessors are not Java source API. This is
misuse resistance, not isolation from reflection or hostile code in the same JVM.
The legacy `QPeriaptHybrid` byte-array API remains available.

Pin the policy root. Persist trusted state atomically before using a new runtime
or activating an update. Missing or corrupt storage must not become first
enrollment. JVM policy tests use an in-memory persistence fixture; this binding
does not supply a durable store. Private transfer through `QPeriaptExpert` and
secret export are explicit; erase every exported array after use. Closing an
owner cannot revoke a byte copy already exported to the application.

Async methods use the caller's bounded executor. Cancellation before execution
skips native work; a running native operation keeps its lease and disposes an
undelivered result. A cancelled future can finish before native work ends.
Runtime close revokes child owners. Cleaner disposal is a nondeterministic
backstop, not a replacement for explicit close.

The binary and sources JARs contain the project's Apache-2.0 and MIT license
texts. The native archive includes its own third-party notices and SBOM/CBOM.
External Kotlin dependencies are resolved separately with their upstream notices.
This unsigned diagnostic candidate is not a stable release qualification.

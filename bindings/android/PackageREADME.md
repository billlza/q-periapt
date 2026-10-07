# Q-Periapt Android SDK 0.2.0

This local candidate contains the Maven coordinate
`dev.qperiapt:q-periapt-android:0.2.0`, a sources JAR, project and native
dependency notices, and the source-bound AAR manifest. It has not been uploaded
to Maven Central. Native ABI major remains **2**, the owner extension is 1, and
the two library names remain `q_periapt_ffi_abi2` and `qperiapt_jni_abi2`.

Verify the archive and `PACKAGE_CONTENTS.json` against trusted SHA-256 pins,
then extract the archive and add its `maven` directory to your Android project's
repositories. For a Gradle settings file:

```kotlin
dependencyResolutionManagement {
    repositories {
        exclusiveContent {
            forRepository { maven { url = uri("/absolute/path/to/sdk/maven") } }
            filter { includeGroup("dev.qperiapt") }
        }
        google()
        mavenCentral()
    }
}
```

Add `implementation("dev.qperiapt:q-periapt-android:0.2.0")` in the
application module. Use this exact version; the candidate repository does not
provide dynamic-version metadata. The AAR has no Maven runtime dependencies.
AGP's own built-in Kotlin support may add Kotlin stdlib to the application;
that dependency is separate from the AAR's POM.

The SDK requires Android API 23 or later and ships arm64-v8a, armeabi-v7a, x86_64
and x86 native libraries. They are stripped, use 16 KiB ELF load alignment and
retain the closed 43-function C/26-method JNI contracts. The AAR supplies the
exact consumer keep rules for registered JNI methods and the native exception
callback constructor. Applications should use their normal optimized R8 rules;
do not add blanket Q-Periapt keep rules to conceal a registration defect. The
Java facade targets Java 11 and uses JNI, with no Panama/FFM dependency.

Product code starts with `QPeriaptSDK.Runtime.fromSignedPolicy(...)`. Pin the
trust root, reject missing/corrupt state as a storage failure, and compare/persist
the trusted state atomically before use. For policy updates, persist the prepared
next state before `activateAfterPersisting()`. This Android binding does not
supply a durable store or make a cross-process authority claim.

Use try-with-resources or explicit `close` for every runtime, key, secret, derived
key and pending update. Runtime close revokes children; already admitted native
operations keep their leases until they finish. Garbage collection is not a
disposal mechanism in this binding. Caller-supplied executors must have bounded
queues/concurrency. Cancellation before execution skips native work; a running
worker disposes an undelivered result after completion. A cancelled future is
not proof that a native call has ended.

Private transfer through `QPeriaptSDK.Expert` and secret/key export are explicit.
Erase all exported arrays after use. Closing an owner cannot erase bytes already
copied into application code. The older `QPeriaptAndroid` array API is retained
for compatibility; owner constructors stay private.

The package gate builds two outside-checkout, nondebuggable, minified Release
APKs through the Maven coordinate, preserving and checking all eight native
library bytes, JNI declarations, exception callback, source input sets and
16 KiB ZIP alignment. One workload exercises owners/KDF/expert transfer/policy
and cancellation; the minimal workload calls only `runtimeVersion()`. Building
these unsigned APKs does **not** execute them on ART, establish minimum-API or
physical-device support, sign a release, or complete stable-release qualification.

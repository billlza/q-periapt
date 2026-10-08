# Owned SDK contract for 0.2.0

This is the current, unpublished source API. Native library identity and ABI
major remain **2**. The original nine C entry points are unchanged; SDK extension
revision 1 adds seventeen owner entry points, fourteen connection entry points
and three persistent-runtime entry points, plus eight policy-recovery helpers and
persistent entry points, including existing-store enrollment. All previous 50 declarations and layouts are retained;
the current unpublished table has 51 exports. The frozen 0.1.5 nine-symbol contract and
header remain separately verifiable. A 0.1.5 library cannot satisfy a new SDK
binding's extension requirements.

## Product entry points

| Platform | Product API | Local verification |
| --- | --- | --- |
| Rust | `q_periapt_sdk::Runtime` | Workspace tests, non-clone compile-fail check |
| C | `q_periapt_sdk_*` from `q_periapt.h` | Independent C11 consumer and exact 51-export contract |
| Swift | `QPeriaptSDK` package product | Strict concurrency, warnings as errors, actual library tests |
| Kotlin/JVM | `dev.qperiapt.QPeriaptRuntime` | JDK 25 FFM, Kotlin warnings as errors, actual library tests |
| Android Java/Kotlin | `dev.qperiapt.android.QPeriaptSDK` | Host JNI execution, fault injection, NDK compilation; ART/device gate remains open |
| WASM | `q-periapt-sdk-wasm` | Generated Node package, platform entropy and lifecycle tests |

The old byte-oriented Swift/Kotlin/Android APIs and `q-periapt-wasm` remain expert
or compatibility surfaces. A serialized decision is not an authorization token.
For new C integrations, `q_periapt_decision_from_signed_policy`,
`q_periapt_generate_keypair`, `q_periapt_encapsulate` and `q_periapt_decapsulate`
are deprecated in the public API documentation. Their signatures, exported
symbols and existing behavior are retained for ABI 2 compatibility; no compiler
deprecation attribute is added to existing consumers. The five metadata/status
functions remain supported. Use the verified runtime and owner entry points
above instead of passing a caller-writable 40-byte decision between operations.
Default owner construction requires the signed policy, pinned root and previous
trusted state. Randomness is obtained from the OS/WebCrypto, never a caller seed.

The [persistent host runtime](SDK_HOST_STORE.md) supplies the stored state on
macOS/Linux. Its three C functions are present on other native targets but
return `ERR_UNSUPPORTED_PLATFORM`; the other owner operations remain available.
Swift exposes `QPeriaptPersistentRuntime` on macOS. Its immutable `.runtime`
works with the existing keys and connections, while policy changes must use
the persistent owner's `update`. Direct manual preparation is rejected, so it
cannot bypass the store. Use `await persistent.close()` to run potentially
blocking disposal off the caller's actor; destruction remains a fallback.

## Ownership and concurrency

The runtime holds one immutable verified policy configuration, which can enable
the fixed ContextBound suite or explicitly disable cryptographic operations. A hybrid
key owns its prepared ML-KEM secret, X25519 scalar and paired public key. Subsequent
decapsulation borrows this storage and keeps native import/integrity checks.
Public key and ciphertext encodings are 1216 and 1120 bytes respectively.

Rust owners cannot be cloned. Swift/JVM/Android references can alias the same
native owner; aliasing never clones private bytes, and close affects every alias.
There is no default private-key getter. [Expert transfer](SDK_KEY_TRANSFER.md)
explicitly imports/exports the specified plaintext expanded representation.
`exportForProtocol` / `export_for_protocol`
is an explicit combined-secret copy for a reviewed external protocol. It does
not supply authentication, key confirmation or a session protocol. The separate
`deriveKey` / `derive_key` operation supplies [purpose derivation](SDK_KEY_DERIVATION.md)
without exporting the KEM secret, returning a distinct application-key owner.
The application owns and must erase every exported copy.

Rust protocol integrations can explicitly borrow independently selected owned
components through `expert::PqKeySource` and `expert::TraditionalKeySource`.
`expert::component_public_key` and `expert::decapsulate_components` require both
owners to belong to the specified `Runtime`, even when another runtime verifies
identical policy bytes. The decapsulation uses one operation slot, retains that
runtime's revocation authority and preserves ContextBound and implicit rejection.
Borrowing copies no private key bytes and changes no C/JNI export. It grants no
permission to reuse ephemeral keys or consume a one-time key; a protocol must
authenticate the selected components and perform its own atomic state transition.

| Action | Contract |
| --- | --- |
| Close a key/secret | Reject subsequent use, erase owned storage when active borrows finish, release quota |
| Close native runtime | Revoke it and its children; remove child registrations and dispose their storage outside the registry lock |
| Close Rust/WASM runtime | Revoke subsequent key and secret operations; key storage remains until each owner closes/drops |
| Operation racing close | Already admitted native work retains a lease; it may finish. Native child publication fails if its runtime was revoked before publication |
| Cancel Swift/JVM/Android async operation | Do not interrupt crypto or free active inputs; close an undelivered result after the worker finishes |
| Cancel before queued execution | Skip native work; queued input snapshots are cleared when the queued task executes |
| Drop a Swift/JVM wrapper | Swift destruction or JVM Cleaner disposes the native owner; JVM collection has no timing guarantee |
| Abandon an Android wrapper | Explicit close is required; runtime close still drains abandoned child registrations. Android API 23 does not depend on Cleaner/finalizers |

Swift/JVM children retain their runtime wrapper to prevent collection from
revoking a still-referenced child. Android has no automatic runtime disposal.
Async JVM/Android APIs take an application executor, whose queue and worker
bounds are the application's responsibility. A cancelled Future can report done
before native work finishes. Cancellation is not a native-operation interrupt.
Cleanup failures are thrown by explicit close or logged if the cancelled
consumer/destructor cannot receive them.

The JVM Cleaner uses a separate cleanup state, and FFM calls keep owners reachable
until completion, following the JDK [Cleaner](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Cleaner.html)
and [reachabilityFence](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Reference.html#reachabilityFence(java.lang.Object)) contracts.

## Failure and resource boundary

Application context is limited to 64 KiB. Runtime limits are 1–1024 retained keys
and 1–64 active KEM operations. The native library instance additionally permits
at most 1024 live/pending owners and 64 active SDK calls. Close and prepared policy
activation are exempt from admission limits, so exhaustion cannot block cleanup
or revocation. These bounds do
not reserve all memory or turn process OOM into a recoverable condition.

Lengths are checked before WASM/JNI/FFM copies. JNI temporary inputs and explicit
secret-export buffers are wiped on normal and exceptional exits. Native owner
creation is rolled back if a Java wrapper/result cannot be delivered.

C shape/alias errors leave outputs untouched. After valid I/O has been admitted,
subsequent errors or caught Rust panics zero all outputs. JNI/Swift/JVM do not
return partially constructed results. ML-KEM implicit rejection remains a
correct-length ciphertext-to-secret operation; no classic fallback is added.
The five C runtime/store/endpoint constructors inspect the four-byte
`struct_size` word first, then the eight-byte size/revision prefix, before reading
any pointer-bearing fields. Unsupported size or revision returns `ERR_LIMITS`
with output untouched. An accepted prefix still requires the complete initialized
current structure and valid buffers. This safely rejects shorter/unknown layouts;
it does not accept them or promise automatic prefix compatibility. A caller must
provide the readable prefix and must not lie about a supported complete layout.
Native statuses retain their old values and add `ERR_CLOSED=-9`,
`ERR_RESOURCE_LIMIT=-10`, `ERR_LIMITS=-11`, `ERR_PURPOSE=-12`, and
`ERR_INVALID_PRIVATE_KEY=-13`.

Handles are library-local ownership identifiers, not credentials or isolation
from malicious code in the same address space. Trust-root pinning, atomic state
persistence and protection from host-storage rollback remain host obligations.
[Policy updates](SDK_POLICY_UPDATES.md) use prepare, host compare/persist and
activation. Verified revocations install a disabled runtime and revoke old
owners; future signed updates can re-enable it. This is an in-process lifecycle,
not proof of durable storage or a cross-process authority. Remaining requirements
are explicit in the [release-readiness ledger](SDK_0_2_RELEASE_READINESS.md).

## Reproducing host binding checks

Build `cargo build --locked -p q-periapt-ffi --release` first. Select JDK 25 for
both `JAVA_HOME` and `PATH`, then run:

```sh
gradle -p bindings/kotlin test --no-daemon --warning-mode fail
sh artifact/sdk-jni-host-smoke.sh
sh artifact/python-run.sh -m unittest discover -s artifact -p 'test_sdk*.py' -v
sh artifact/python-run.sh -m unittest discover -s artifact -p test_android_jni_input_shapes.py -v
```

The host JNI check compiles the actual Java/JNI sources, links the actual Rust
library and uses `-Xcheck:jni`; it does not instantiate Android or qualify an AAR.
The earlier API 23 R8 minimal-consumer checkpoint retained its 18 JNI registrations and the
exception callback from the compiled source classes using the existing keep
rules. The current source has 26 registrations, including purpose derivation,
expert transfer and policy activation; its compiled-descriptor checks are
separate from R8/ART acceptance.
The versioned DEX verifier still rejects an extended method dump under the
historical 0.1.5 contract, and rejects a nine-method dump for the SDK extension.
SDK fault injection is explicitly separate from cryptographic execution.
Historical package/device receipts do not qualify this changed source.

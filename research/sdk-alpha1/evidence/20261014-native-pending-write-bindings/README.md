# Installed native bindings for original pending-write recovery

Source commit: `54643b11791543c97d6def45d123f7655d9593e3`.
This is an unpublished candidate checkpoint, not release or protocol admission.

C, Swift, Kotlin and Android now expose the existing original pending-write
request and exact confirmation contract through their enrollment owners. The C
interface adds three exports, bringing the checked set to 157. Requests retain
the proposal, binding, complete source/target metadata and historical signature.
Preparation performs no network request or TLS credential load. Confirmation
uses a fresh signed witness Query, preserves the original sealed target, and
grants no runtime or traffic permission. An independent controller must approve
the original intended effect; the historical device signature is insufficient.

Six fresh installed-consumer cohorts passed, with 27 foreign process invocations:

| Consumer | Original Advance | Foreign calls | Result |
| --- | --- | ---: | --- |
| C | Not dispatched | 5 | Exact original target, approved confirmation and retry |
| C | Applied, reply lost | 4 | Exact original target, query-only confirmation and retry |
| Swift | Not dispatched | 5 | Complete metadata, tamper and unapproved-target rejection |
| Swift | Applied, reply lost | 4 | Complete metadata, tamper rejection and exact retry |
| Kotlin | Not dispatched | 5 | Complete metadata, tamper and unapproved-target rejection |
| Kotlin | Applied, reply lost | 4 | Complete metadata, tamper rejection and exact retry |

Each case first publishes a real four-role prekey artifact, independently retains
the intended retirement and complete metadata before expiry, then withholds the
original retirement's Advance or reply. The actual protocol policy expires on
the wall clock. Separate foreign processes inspect and confirm the same original
enrollment. Metadata/proposal bytes equal the independently retained originals;
other records and the fanout ordinal are unchanged. A mismatched C copy binding
leaves both outputs untouched. Damaged Swift/Kotlin metadata sends no witness
request. Without independent approval, the unapplied target is refused. Two
foreign confirmations and a native reference confirmation send exactly three
Queries and reach the same original target, with no additional Advance.

The C library and native controller consume actual Cargo archives outside the
checkout. Swift consumes an extracted source package and its selected library;
Kotlin consumes an extracted Maven package through a separate consumer and a
verified outside-checkout runtime dependency closure. All 29 implementation
inputs are byte-identical to those tested. Four README additions followed the
language-package builds; they do not change executable inputs. Archive identities,
dependency resolution and terminal commands are retained in `CAPTURE.zip`.

The actual Apple XCFramework includes only arm64 macOS, iOS and iOS simulator
slices. Export checks, licenses, archive readback, macOS execution and all three
consumer builds passed. A fresh separately signed application links the exact
installed iOS slice. On iPad Pro M4 (iPadOS 27.0.1) and iPhone 16 Pro (iOS 27.0),
the application verified all three new exports, the 436-byte structure and binding
offset, unchanged output on failure, argument rejection and the existing
cancelled-owner/no-created-state contract. Both actual processes exited with code
0 and no core dump. These are physical ABI/owner boundary checks, not positive
physical pending-write recovery or mobile lifecycle composition.

Other checks passed: 58 C tests with strict all-test Clippy, 77 Swift tests,
78 Kotlin tests, strict Java/JNI compilation and real JNI probes under `-Xcheck:jni`,
75 package/inventory controls, Rust 1.90 compilation, formatting and the exact
clean-source gate. The tracked Rust census is 677. New implementation modules
keep framing and native marshalling separate from the existing registration
methods. This change makes no throughput, allocation or latency claim.

Failed attempts remain in the capture: isolated-source dependency layout,
warnings-as-errors on an unused fixture reply (fixed by checking the reply),
linked-worktree provenance refusal and stale test-count fixture, invalid Kotlin
report label and checkout-cache refusal, and Xcode provisioning settings applied
to a Swift package library. The latter was resolved by unsigned compilation and
offline application signing with the existing authorized profile. The original
Swift packaging driver's final receipt was not retained; a separate read-only
verification checked every archive member and its successful build/link receipts.
An attempted evidence destination collided with the earlier native-core checkpoint
and was correctly refused before writing; that checkpoint remains unchanged.

Android has host JNI boundary coverage; its positive recovery flow must use the
existing public `ContinuityConfiguration` entry point and still needs its own
ART execution. The six process cases use a shared engine, one host and signed TCP.
They do not establish independent-implementation interoperability, business-message
unknown-outcome composition, physical power-loss behavior or PCS. New binding
storage/process/cancellation faults and integration into the permanent installed
qualifier remain separate work. CI/CodeQL for this new source commit has not run.

Private owners, signing keys, databases, provisioning contents and raw device
inventory are excluded. Device/signing identifiers in retained scripts and command
receipts are redacted; raw local observations are unchanged. All successful and
failed cohorts are sealed. Further runs require fresh identities, storage and
output directories. No package or release was published.

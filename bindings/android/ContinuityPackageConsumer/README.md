# Android Continuity owner candidate

This unpublished adapter calls the existing `qpc-owner/1` engine through JNI.
It is separate from the product SDK's ABI 2 Android package. Its present public
surface covers explicit configuration creation, reconciliation with original
inputs, reopening, registration requests, independently pinned grants, storage
preparation, device activation, explicitly configured peers, original-session
reopening, message status/retry, bidirectional transport, rekey and registry-backed
first activation and same-key credential renewal. Original-session traffic across
credential renewal, roster renewal, device retirement and root replacement
integration remain subsequent work. The current extracted AAR has a
minified AGP consumer; it is still an unpublished candidate.

`ConfigurationInputs` copies independently supplied SDK trust, signed policies,
protocol checkpoints and the local TLS identity. `prepareCreate`,
`prepareReconcile` and `prepareOpen` return an opaque owner without installation
I/O. Run `finishOpen` on a worker thread. Close the owner explicitly; garbage
collection does not release native owners. The JNI bridge and native engine have
process lifetime and support one application class loader, not dynamic unloading.

After opening configuration, call `createEnrollment` with the independently
approved original intent, or `resumeEnrollment` with that same intent. Supply a
`ConfigurationWitness` explicitly when required; absence never permits local
activation under a witness-required policy. Send `request()` to the independent
account issuer. Pass its certificate and roster to `accept`, with a separately
retained `AccountPin`. `prepareStorage()` identifies either local preparation or
the exact genesis that still requires witness enrollment. `activate()` applies
native authorization and transfers ownership to the device facade.

For same-key credential renewal, close active devices and resume the original
enrollment. Retain the independently approved grant, target `AccountPin`, original
`Ids.CredentialRenewal` and statement. `stageCredentialRenewal` preserves the
signing identity and journal. Under required-witness protection, export
`prepareWitnessedCredentialRenewal()` for independent witness approval before
calling `commitWitnessedCredentialRenewal`. A missing reply can follow a durable
commit: reopen the same enrollment and call `reconcileWitnessedCredentialRenewal`
with the original operation and statement. This query emits neither Commit nor
Close. `PENDING` does not establish that the operation is uncommitted; `COMMITTED`
is historical evidence and grants no current traffic permission. Select the live
account registry and use the ordinary `activate()` path for current authorization.

`prepareWitnessedCredentialCancellation` exports the original target-free
expectation for independent cancellation approval. `closeWitnessedCredentialRenewal`
can lose to an already applied target and must report it as committed. The
`reconcileExpiredCredentialRenewal` result is similarly an explicit native outcome;
unavailability never establishes that no commit occurred. All reported checkpoint
and operation values are immutable copies, with unsigned 64-bit counters preserved.

Successful configuration-to-enrollment and enrollment-to-device transfers make
the source facade unusable for operations. Closing that transferred source is a
no-op, so an outer `finally` cannot revoke the successor. Failed transfers retain
the original facade as the sole object responsible for closing the native slot;
an admitted native failure can still require explicit original-state recovery.
No blocking native operation runs under the Java ownership monitor. A previously
admitted cancellation may race a transfer and affect its successor; join the
cancelling thread before using the returned successor. All I/O-bearing operations
are synchronous and belong on a worker thread.

For managed first use, create a separate private registry directory, explicitly
call `ContinuityAccountAuthority.provisionWrappingKey`, then `prepareCreate` and
`finishOpen`. Retain `AccountAuthorityTrust` independently of journal backups.
After the issuer approves the original request, `associate` verifies its grant
against an independent `AccountPin` and returns a public checkpoint. Select it
with `enrollment.selectAccountAuthority` before storage preparation and activation.
Selection performs no storage I/O; successful activation durably binds the registry.
Subsequent `prepareOpen` never recreates missing storage, and managed enrollment
reopen requires explicit selection of the original checkpoint again.

Keep the registry open while its managed children operate. `cancel` stops calls
on that registry handle; `close` revokes retained child admission. Reopening the
same database does not revive an old selection. A checkpoint alone is never a
permission token. Association errors may follow commit, so retain the original
inputs and inspect the checkpoint before deciding the next action. Registry
creation, signature refusal, exact association replay, reopen, forged revision
refusal and these cancel/close boundaries pass through the actual AAR in fifty
ART processes on the same API 37 phone, across both witness carriers and both
root trust profiles.

`ContinuityDevice.preparePeer` copies an independently supplied
`PeerConfiguration`; bundle contents cannot select its account, device, directory
or TLS expectations. `preparePeerReopen` requires the original nonzero session ID
and never falls back to bootstrap. Finish the prepared peer explicitly. Closing
the parent revokes children; a busy parent must be cancelled and its active call
joined before close. Closing a peer does not retire the durable session.

Retain the initiation/message IDs before dispatch. `nextMessage` observes a slot
without reserving it. On an uncertain send, inspect `messageStatus` and retry the
original ID with identical plaintext and associated data. `SendResult` distinguishes
confirmed consumption from a pending prefix. Completing `rekey` reports an epoch;
it is not evidence that an attacker's retained state has stopped exposing messages.

An `ApplicationCommit` runs synchronously on the thread calling `serve`. Return
only after the business effect and session/message deduplication record commit
together. Throw on refusal or unknown outcome. The JNI bridge returns refusal to
the engine and preserves an application exception as the native failure's cause.
Exact retries can invoke the callback again, so it must reconcile the same IDs.
Its temporary plaintext array is cleared on return; caller-created copies and
historical GC copies are outside that guarantee. Bootstrap and already-consumed
duplicate results do not invoke the application callback.

Creation requires an absent destination beneath an application-owned `0700`
parent. Android's `Context.getFilesDir()` is not necessarily `0700`: the selected
phone returns `0771`. Create a dedicated private child; do not relax permissions
or change unrelated existing directories. Retain the canonical application path
because Android's app-data aliases can include symlinks. Native traversal pins
intermediate directories with `O_PATH | O_DIRECTORY | O_NOFOLLOW` on Android,
then opens the final private directory for reads and sync. This respects search-only
ancestors without weakening the final owner/mode or no-symlink checks.

Atomic publication uses the same descriptor-relative, non-replacing rename and
file/directory sync path as the other native consumers. There is no fallback for
unsupported syscalls or filesystems. Android's Linux UID sandbox applies to
[native code as well as Java code](https://source.android.com/docs/security/app-sandbox);
these checks do not isolate secrets from hostile code in the same application.

An exception retains the native reason code and bounded diagnostic. It does not
prove that no state was committed. After an uncertain first creation, cancel if
needed, join the operation, close and reconcile the exact original inputs. Missing
previous state is not permission to create a replacement. A busy close preserves
ownership; cancel and join before retrying. A second successful close is not
promised: the native engine reports `Closed` for an already released handle.

Close `LocalTlsIdentity` when its owned input copy is no longer needed. Callers
remain responsible for their original input arrays. JNI copies are wiped and
freed on every exit; native secret ownership remains in the existing engine.
Retain `consumer-rules.pro` when building a minified Android consumer because
JNI registration and error delivery require the exact internal class names.

The native build currently targets arm64/API 23 and 16-KiB ELF alignment. This
compilation floor is separate from runtime qualification. The API 37 physical
phone is the agreed device scope; additional API 36 hardware is not required.
The existing Android SDK physical acceptance remains complete.

The source includes public-API process probes, a JNI boundary probe and an API 37
instrumentation consumer. Its release APK consumes only the actual AAR, with R8
enabled and no app rules preserving the library. JNI's required name retention
comes from the AAR itself. Fresh signing inputs are issued by a separate Rust
process; the device generates its own enrollment identity. No installation,
signer, journal or wrapping key is copied from the issuer.

The initial 2026-10-11 registration qualification covers two trust profiles and twelve JVM
children, then twelve distinct ART processes using minified release APKs. The
issuer verifies identical original requests after restart and after a rejected
tampered grant; valid grants activate, and the durable ACTIVE registration opens
again. Both installed APK hashes and both packaged native libraries are checked,
and both test installations are removed.

The subsequent peer qualification extends each profile to twelve JVM children,
then twelve ART processes: bootstrap, a native receiver exiting with code 77
after its business write, original-message retry with unchanged effect, epoch-1
rekey, and reverse delivery. On reverse delivery the application commits its
effect and throws; the native result is APPLICATION with the original Java cause,
the temporary plaintext is cleared, and the exact retry observes the same effect
before consumption succeeds. This covers a concrete lost-acknowledgment cut and
an application-commit uncertainty boundary, not every storage crash cut.

The final process exercises an actual blocked listener under child and parent
cancellation. It observes native `Busy` admission, rejects concurrent peer/parent
close, closes an idle sibling, and requires cancellation to release the listener
within five seconds. Child cancellation preserves a sibling; parent cancellation
revokes it. A prepared child also refuses activation after its parent closes.
The observer itself can win admission: the test retries only pre-I/O `Busy`, at
most 64 times, and preserves every other failure. Both trust profiles pass these
checks on the same API 37 phone and through the host JNI bridge.

Required-witness registration now also runs through signed TCP and mutual TLS,
under both fixed-root and recoverable-root trust. The independent operator checks
the exported public genesis against the approved device and policy before enrolling
it. Missing witness configuration and a wrong witness identity are refused without
network traffic; a corrupted signed reply is refused. Correct activation and reopen
preserve the original enrollment request even when unrelated witness sidecars are
placed in the installation. These four routes pass in 30 distinct ART processes
on the same API 37 phone, using the actual AAR and minified release APKs. Test TLS
credentials are redacted from controller logs; device signing and wrapping keys
stay on the device. All four test installations are removed.

The native receiver and JNI consumer share the protocol engine; these runs do not
establish interoperability with an independent protocol implementation. Android
account-wide lifecycle, broader
unknown-commit cuts and release/CI admission remain separate work.

For repeatable host JNI qualification, add `--with-android-jni-consumer
--android-java-home "$JAVA_HOME"` to the installed-package command in
[`artifact/continuity_package.py`](../../../artifact/continuity_package.py), with
`--with-c-consumer` and an explicit JDK 25 installation. The existing Kotlin CI
lane selects these options on macOS arm64. It compiles the public classes for
Java 11 into a JAR, compiles the probes for Java 17 against that JAR, and builds
the real JNI bridge against each installed Debug/Release C library. Each profile
runs the JNI malformed-input probe, both twelve-process lifecycle traces and the
four required-witness routes (thirty additional foreign processes per profile),
and four managed registry routes (fifty additional processes per profile).
The result is `ANDROID_JNI_CONSUMER.json` with source, tool, JAR and binary hashes.
This host lane complements the recorded actual-AAR/ART physical run; the JNI
adapter remains an unpublished candidate.

# Android Continuity owner candidate

This unpublished adapter calls the existing `qpc-owner/1` engine through JNI.
It is separate from the product SDK's ABI 2 Android package. Its present public
surface covers explicit configuration creation, reconciliation with original
inputs, reopening, registration requests, independently pinned grants, storage
preparation, device activation, explicitly configured peers, original-session
reopening, message status/retry, bidirectional transport, rekey and registry-backed
first activation, same-key credential renewal, joint credential/policy renewal, independent policy/roster renewal
and original-message retry, device replacement, restricted old-device retirement
and independently authorized account-root replacement. The current extracted AAR has a
minified AGP consumer; it is still an unpublished candidate. The
[integrated Debug/Release checkpoint](../../../research/sdk-alpha1/evidence/20261012-android-root-integrated/README.md)
passes 4,294 Java calls, including all five root routes and 124 root process cuts.
The accepted single-phone AAR evidence remains valid.

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
enrollment. Export `credentialRenewalRequest(operation)` for local storage or
`witnessedCredentialRenewalRequest(operation)` for required-witness storage. Retain
the complete request before submitting it to the independent issuer. It includes
the original credential/roster and P0 digest, actual predecessor credential/roster,
and current policy authorization. An unknown submission reuses the same request;
the issuer must authenticate, authorize and deduplicate it independently.
After terminal completion, use a new operation ID for a new issuance; a completed
operation ID cannot be reused.
Retain the independently approved grant, target `AccountPin`, original
`Ids.CredentialRenewal` and statement. `stageCredentialRenewal` preserves the
signing identity and journal. Under required-witness protection, export
`prepareWitnessedCredentialRenewal()` for independent witness approval before
calling `commitWitnessedCredentialRenewal`. A missing reply can follow a durable
commit: reopen the same enrollment and call `reconcileWitnessedCredentialRenewal`
with the original operation and statement. This query emits neither Commit nor
Close. `PENDING` does not establish that the operation is uncommitted; `COMMITTED`
is historical evidence and grants no current traffic permission. Select the live
account registry and use the ordinary `activate()` path for current authorization.

After an independently approved P update, explicitly select its configuration and
use `stageContinuedCredentialRenewal`. Local G completes through
`activatePolicyRenewal`; `reconcilePolicyContinuation` is for joint G/T instead.
Required-witness G uses `prepareWitnessedPolicyContinuation`, independent witness
approval and `commitWitnessedPolicyContinuation`, followed by
`activatePolicyRenewal`. Its proposal exposes `independentPolicyStatement` for P;
`policyStatement` is reserved for joint T. The original G operation and statement
still identify historical reconciliation and Close, and Close can return Committed.

For an atomic credential and policy change (joint G/T), select the independently
trusted target configuration and use `stagePolicyContinuation` with the credential
grant, account pin, both independent policy approvals, historical predecessor
policy and its adopted `Ids.PolicyContinuationStatement` (null for the original
policy). Local storage uses `reconcilePolicyContinuation`; required-witness storage
uses the explicit prepare/approve/commit workflow above. Retain the original
operation and **T statement**, which is distinct from the credential grant's
statement. `activatePolicyContinuation` performs current admission and transfers
the same owner. Close active devices before resuming that original enrollment.
`recoverHistoricalPolicyContinuation` can recover an existing local commit using
the pinned historical target after expiry; an uncommitted target remains suspended.
Neither historical result grants traffic authority or permits a new operation.
The [local joint G/T qualification](../../../research/sdk-alpha1/evidence/20261014-android-joint-policy/README.md)
covers four host routes and the accepted phone's applied/pending routes, including
real policy expiry, original-message retry and refusal to create a historical commit.

For required-witness G/T, export `prepareWitnessedPolicyContinuation()` for the
witness's independent approval of both the grant and joint policy authorization.
Retain the original operation and T statement after a missing Commit reply.
Passive `reconcileWitnessedCredentialRenewal` sends no new Commit or Close;
explicit `closeWitnessedCredentialRenewal` may send Close and still return Committed
if Commit already won. Before preparing a sealed target, a target-free
`prepareWitnessedPolicyCancellation()` supports independently authorized closure.
Its reservation is not a Closed receipt and permits neither Commit nor activation.
The [required-witness qualification](../../../research/sdk-alpha1/evidence/20261014-android-witness-joint/README.md)
checks signed TCP and mutual TLS, real expiry, Applied/Closed recovery and the
accepted phone's actual package paths. Historical results still require fresh
current-policy admission before operational use.

For a later joint update, use the public renewal request's current credential,
roster, policy and previous T. Keep the original installation and session; the
original policy is no longer the immediate predecessor. The
[successive-renewal qualification](../../../research/sdk-alpha1/evidence/20261014-android-joint-cycle/README.md)
executes two G/T generations across all three storage/carrier profiles and both
trust profiles on the host, plus TLS/recoverable on the accepted phone. The
original unknown-delivery message survives both updates and produces one effect.

For registry-managed traffic, independently associate the peer account as well as
the local account. An unknown peer is refused even when its TLS certificate and
bootstrap bundle are valid. After local renewal, call `preparePeerReopen` with
the original peer expectations and session ID, then retry the original message
with the same payload and associated data. The counterparty must independently
admit the renewal grant before reopening that session.

For a local roster update, retain the previous checkpoint and independently pinned
target roster. `refreshRoster` defaults to the original protocol policy. After an
independently approved policy transition, select its configuration explicitly and
pass `RosterPolicySource.SELECTED`; an expired or absent selection never falls back
to the original policy. `resolveRosterRefresh` reconciles the original local update
and cannot substitute for required-witness history.

With a required witness, retain `Ids.RosterRefresh` and the exact proposal from
`prepareWitnessedRosterRefresh`. Obtain independent witness approval before Commit.
After an unknown result, reopen the original enrollment, recover retained preparation
if necessary, and reconcile that same proposal. Applied/Closed are historical
outcomes; activation separately checks current policy, membership and registry.
Recovery must not invent a new operation or infer non-commit from unavailability.

`ContinuityDevice.admitPeerRoster` admits an independently approved remote roster.
Retaining the same member can preserve its original session and pending message;
revocation refuses both retained-peer sends and reopening. A device-generation
replacement needs explicit target-roster admission on the counterparty before a
fresh session can be opened. Incoming bootstrap material cannot select this trust.

For one operation addressed to every current device in an account, retain
`nextAccountOperation()` before dispatch. Build the complete `AccountTarget[]`
from the independently approved roster and the original peer/session owners,
then call `sendAccountMember` once for each selected member with that same
operation, account, full target set, payload and associated data. The native
journal admits the complete transaction before delivering any selected member;
omitting a recipient or changing a retained input is refused. This API does not
turn remote business effects into an atomic transaction.

`accountStatus` reports local aggregate state. `COMMITTED` does not assert remote
consumption. `AccountDelivery` distinguishes confirmed, pending, unknown, retired
and abandoned results; zero exchanges describes a retained result, not necessarily
success. A failed or cancelled call may have committed. Close/reopen the original
owners and reconcile the same operation and inputs. Concurrent member close or
ordinary operations return Busy while the whole set is admitted; member cancellation
can interrupt the aggregate without permanently cancelling other peers.
The [focused host JNI checkpoint](../../../research/sdk-alpha1/evidence/20261012-android-account/README.md)
passes 108 independent Java processes across Debug/Release and fixed/recoverable
trust. It is integrated into the existing host qualification; the earlier accepted
physical Android AAR keeps its recorded artifact scope.

`ContinuityRecovery` opens the original installation for cleanup without granting
traffic permission. Prefer `beginAccountCleanupReport()` or
`beginSessionCleanupReport()` to collect a complete immutable report. Durably
record every field and original ID in the host transaction before acknowledging
that report. `reconcileAccount()` keeps acknowledged and unknown member outcomes
distinct; retirement requires settlement of all original members. Authenticated
archive restoration restores catalogue metadata only. Follow the
[recovery and host-accounting guide](../../../research/sdk-alpha1/ANDROID_RECOVERY.md)
for witness selection, unknown outcomes and the exact acknowledgement order.
The [recovery checkpoint](../../../research/sdk-alpha1/evidence/20261012-android-recovery/README.md)
passes 292 host Java processes across Debug/Release, including first-use recovery,
lost witness replies, complete account report comparison and original archive
restoration. Its witness cases use C setup/traffic and Java recovery explicitly.

For a remote peer's renewal, call `ContinuityDevice.admitPeerCredentialRenewal`
with the signed grant, an independently retained target `AccountPin` and the
original renewal ID. Keep the original device and registry alive. The returned
checkpoint describes the installed target; it is not a receipt proving absence
after a failed call. Close and reopen the original owners after an unknown result
and reconcile the same grant. This API cannot renew the local identity or create
a session. Existing peer objects retain their original authorization view: close
them and explicitly reopen each original session after successful admission.

Under required-witness protection, an expired target is not proof that it was
never committed. Reserve the exact cancellation expectation and obtain the
independent witness's Closed decision. Reconciliation can persist Closed before
losing its cleanup ACK, so resume that same operation after a transport error.
Close of an already committed target remains Committed. A cancelled target grants
no new authority; ordinary activation separately checks whether the preceding
credential, roster, registry and policy still permit traffic.

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

After independently authorized generation replacement, use
`ContinuityRetiredEnrollment.prepareOpen` with the original private installation,
original `EnrollmentIntent` and `RetiredEnrollmentAuthority`. `finishOpen` opens
existing state only. This owner cannot create a device, send traffic or expose a
signer. Retain the exact `inventory` and obtain the witness's matching inventory
receipt before `prepareReport`. Obtain its report receipt before `loadReport`.

The host must durably retain and account for the complete `canonicalBytes()` report,
including uncertain deliveries. Pass those exact bytes to `prepareAcknowledgement`;
native verification checks the private MAC and original inventory. Then obtain the
independent witness's host-acknowledgement receipt. A report receipt alone cannot
authorize erasure. Call `eraseJournal`, `prepareSignerErasure` and `eraseSigner` with
that original authority; the last operation consumes the cleanup resource even on
success. Close its handle afterwards. On an unknown result, reopen the same original
inputs, inspect `journalState`/`signerState`, and reconcile the same report and receipt.
These operations provide logical erasure, not a claim about old flash pages/backups.

A replacement installation creates its own keys and journal through the ordinary
configuration/enrollment APIs, with the independently approved next generation.
The issuer verifies its public request and authorizes the witness's generation
replacement. Keep device private state local. The existing counterparty must
explicitly admit the signed target roster before opening a fresh session; copying
new bootstrap bytes is insufficient. The old installation remains cleanup-only.

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

Local-only credential renewal has a separate real-clock qualification. Expiry
leaves the original intent Pending until explicit reconciliation records
ExpiredUncommitted against the preceding roster head. This fact does not
authorize activation: a separate independently approved successor must first
be staged and activated. The peer explicitly admits that successor, and the
same identity, journal, original session and next message slot resume communication.
Required-witness expiry retains its distinct Pending/Closed workflow.

Expired protocol-policy cleanup retains the original signed P0 snapshot for
history only. A pre-expiry Applied outcome can be recovered after its reply was
lost; an uncommitted prepared proposal can be explicitly Closed. Exact proposal
and terminal retries preserve their identities. Expired P0 still refuses staging
a new grant, dispatching a new Commit and activating an operational device.
This path is distinct from expiry or revocation of the underlying SDK authority.

Independent protocol-policy renewal uses `PolicyRenewalRequest` and distinct
policy operation/statement IDs. Retain the complete request fields and the first
account-root plus policy-root approvals across process restarts. After opening a
separately provisioned target `ContinuityConfiguration`, call
`selectContinuedPolicy(originalEnrollment)`; close that configuration after the
selection. The original enrollment retains the moved target lease. Selection
itself neither approves nor commits an update.

Local-only journals use `policyRenewalRequest`, `stagePolicyRenewal`,
`reconcilePolicyRenewal` and `activatePolicyRenewal`. Required-witness journals use
the independently typed request, complete `IndependentPolicyProposal`, explicit
witness approval, commit and historical reconciliation. Keep the complete proposal;
`Unavailable` is not proof of non-commit. `resolvePolicyRenewal` is local-only and
refuses witness-protected policies; use their proposal-based reconciliation and
progress APIs. A managed journal requires witness protection and its original
live account registry selected again after each resume, including before a
journal-backed renewal request. No API automatically falls back to local mode.

The JNI layer copies and bounds every input before native admission. Request and
approval output records are heap allocated; its 17-field stage shape is checked
against the shared field bound at compile time. Public request/status framing is
explicit big endian, not a Java view over native struct memory. Policy renewal
passes the retained host and ART routes. The complete integrated retirement
qualifier passes 3,570 Debug/Release host calls at the retirement checkpoint, with
source-bound public readback. The accepted single phone remains sufficient.

## Account-root replacement

`ContinuityAccountAuthority` now owns the independently authorized account-root
replacement flow. Keep the original registry, installation path, enrollment intent,
checkpoint, pinned witness and approved `RootReplacementPlan`. Constructing a Java
plan/proposal value checks framing; native operations authenticate its authority.
Create the successor through its own configuration and enrollment, without copying
the original device's private state.

Use `beginRootReplacement`, `bindRootFreeze`, `retainRootRetirement` and
`activateRootSuccessor` for the original approved target. Beginning consumes the
old device's operational resource; close its facade and keep the replacement
controller open while its successor operates. Resume the exact original inputs
with `resumeRootReplacement`; an unknown activation result may follow commit and
consumes the attempted controller/enrollment handles.

`RootReplacementTransition` carries signed original noncommit plus a separately
approved next plan and freeze. `RootReplacementAdoption` carries a separately
approved committed winner, its retirement receipt and original noncommit. Use the
matching transition/adoption and resume methods. `retainRootNoncommit` keeps the
old plan Closed; it does not unfreeze it or authorize an arbitrary new target.

The controller delegates original-device report, acknowledgement and erasure
through its retired methods. Erasing the old signer preserves this controller and
successor. Idle cancellation stops controller calls; closing it revokes managed
successor operations. Historical state is not current traffic authorization.

All five routes pass 724 host calls and 362 ART calls on the same accepted phone,
including 124 host and 62 ART process cuts. The shared package qualifier
requires every test in its current catalog and all five bounded public exports; its
combined current-source run is a separate integration check. The interface remains
an unpublished candidate.

### Original pending-write confirmation

Resume the original enrollment through `ContinuityConfiguration.resumeEnrollment`
with its original intent and pinned `ConfigurationWitness`. Its
`pendingWriteRecoveryRequest()` returns a `PendingWriteRecoveryRequest` containing
the proposal, binding, complete metadata and signed request as owned byte copies.
Retain all four fields in protected host storage. Preparation reads historical
policy and the original witness pin without a network request or TLS credential
load; it grants no traffic permission.

An independent controller must approve the exact original effect after comparing
both metadata views with its retained intent. The historical signature alone is
not approval. Call `confirmPendingWriteRecovery(approved, recordedMetadata)` with
the retained proposal and full metadata after that approval. It performs a fresh
signed Query and confirms only the original target. An unknown result requires
closing the affected owner, reopening the same configuration/enrollment, and
retrying those exact inputs. Success neither activates a device nor renews its
credentials or policy. Run these synchronous operations off the UI thread and
retain the existing explicit cancellation/join/close discipline.

Host JNI boundary checks cover this interface. Positive recovery through this
configured Android entry point and physical-device lifecycle execution retain
their own qualification; JVM/Swift process results do not establish ART behavior.

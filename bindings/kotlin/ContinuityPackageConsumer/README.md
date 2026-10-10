# Continuity Kotlin/JVM candidate

This separate, unpublished `dev.qperiapt:q-periapt-continuity-kotlin:0.0.0`
module calls the existing `qpc-owner/1` C/Rust engine. It is not product ABI 2,
an Android JNI implementation, or an admitted 0.2.0 release artifact.

For a new installation, start with [first-use configuration](#first-use-configuration-unpublished-candidate):
`ContinuityConfiguration.prepareCreate(path, input)`, `finishOpen()`, then
`createEnrollment(intent, witness)`. The SDK publishes its wrapping key and owns
the original registration identity; the host supplies independent trust inputs,
authenticates the account and obtains its signed approval. Uncertain publication
uses `prepareReconcile` with the original inputs; known committed configuration
uses `prepareOpen`. The older file-configuration and `ContinuitySetup` routes
below serve independently preconfigured installations.

The source targets Kotlin 2.4.20 and non-preview, 64-bit JDK 25. Select the exact
installed native library with `-Dqperiapt.continuity.lib=/absolute/library/path`.
Classpath consumers need `--enable-native-access=ALL-UNNAMED`; named-module
consumers must authorize `dev.qperiapt.continuity`. There is no library-path
search or carrier fallback. The Java FFM [linker contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/foreign/Linker.html)
governs the explicitly aligned C layouts and synchronous callback lifetime.

`ContinuityOwner` and `ContinuityRecoveryOwner` are distinct authority types.
`prepare` copies bounded configuration without installation I/O. `finishOpen`
activates once on the calling thread and may be cancelled by another thread.
Failure consumes activation and grants no operation authority. `open` closes
failed preparations explicitly, retaining a disposal failure as a suppressed
cause. No method exposes a raw handle or converts recovery authority into an
operational owner. IDs and public byte records own immutable copies. `Counter64`
represents the entire native unsigned range without signed truncation.

`ContinuityEnrollment` adds original key registration using the matching native
library's nine enrollment exports. Explicitly provision the wrapping key once,
then `prepareCreate(path, intent)` and `finishOpen`; restart uses only
`prepareResume` with the original `EnrollmentIntent`. `request` returns the exact
committed public proof of possession. `accept` takes certificate/roster bytes and
an independently supplied `AccountPin`, never trust derived from those response
bytes. Opening/status/request need no SDK policy or TLS files. Acceptance and
storage require the separately provisioned policy/store; activation also requires
TLS configuration and any policy-required witness. Authority transport and account
authentication remain host responsibilities.

Registration and installation setup share one owner-transfer implementation.
`activate` transfers the same `NativeOwner` to `ContinuityDevice`, preserving its
Cleaner and native enrollment lease. Closing a successfully transferred registration
does not close the device. Failed admitted work may leave durable Active while no
device was returned; close this wrapper and resume its original identity.
`refreshRoster` only continues the same credential under an independently pinned
roster, with separate operator witness authorization. Restore the original session
through the returned device; no missing-state fallback or key replacement occurs.
Six-phase `EnrollmentStatus` distinguishes a missing pre-acceptance journal and a
pending roster transition. Its Active phase is never a live authorization receipt.

Same-key credential renewal uses four additional native exports. After closing
and joining the device and its active calls, resume the original enrollment and
call `stageCredentialRenewal(wire, independentPin, originalOperation)`, then the
same consuming `activate()`. The grant is nonempty and bounded to 65,536 bytes;
`CredentialRenewalID` and `CredentialRenewalStatementID` retain distinct, nonzero
32-byte identities. The root, complete signing key, original installation and
exact configured policy cannot be replaced through this operation. Do not update
local credential files or create another registration after an unknown result.
Required-witness renewal must use the additional witnessed operations described
below before activation; there is no local fallback.

`credentialRenewalStatus()` is passive and requires no live policy or TLS files.
Its separate sealed `CredentialRenewalStatus` has `Absent`, `Pending`, `Committed`
`ExpiredUncommitted`, and `Closed` cases. Pending does not prove the journal is uncommitted;
Committed reports the historical operation/statement/target and does not override
current expiry or revocation. `reconcileExpiredCredentialRenewal(operation,
statement)` reads the original retained intent without demanding fresh validation
of its expired target. It returns no device. Only the native monotonic history
check can produce ExpiredUncommitted, with its observed checkpoint and nonzero
full-width unsigned time. No error is translated into an empty or successful state.

`ContinuityDevice.admitPeerCredentialRenewal` admits an independent remote grant
through the same owned service. It neither renews the local device nor replaces
cached peer contexts. Explicitly reopen each existing session from its original
bundle and pins; old children continue to undergo current-grant checks. The FFM
bridge checks every conditional status field and the exact 120-byte native layout.
All calls retain the existing one-owner transfer, cancellation, close and error
propagation rules; no handle or storage-owner override is exposed.

The independent consumer implements `enrollment-credential-status`, `-stage`,
`-reject`, `-reconcile`, `-activate-refused`, and `credential-peer-check` with the
same public record formats and command output as the C qualification client.
It checks exact native refusal codes, readback, retained original registration,
stale child refusal, unchanged next message slot, and persisted peer/outbox status.
Raw C output-buffer sentinels and cross-kind handle probes remain C ABI checks;
the Kotlin public API exposes neither failed outputs nor a registration-to-device
cast. The new decoder/boundary tests and consumer paths require execution against
the matching current native library; this source increment alone is not a new
installed-package or independent-engine qualification.

This registration increment requires its own installed-consumer, GC, cancellation
and connection qualification; earlier setup/package receipts do not cover it.
It is not Android integration or a complete credential/root/upgrade lifecycle.

`ContinuitySetup.prepareCreate/prepareResume` explicitly selects creation or
original-intent restart. `finishOpen` acquires setup authority; `status` retains
Creating/Active and the original `JournalID`. `prepareStorage` returns local
protection or original public witness genesis for independent enrollment. It
does not generate keys, issue credentials, repair stores or authorize enrollment.
`activate` moves the existing `NativeOwner` reference into a `ContinuityDevice`,
preserving its one Cleaner registration. No raw handle is copied or exposed.
Successful transfer makes old setup `close` harmless, so `setup.use { it.activate() }`
does not close the returned device. Other old-setup methods return Closed. During
transfer, status/storage/finish, close and repeated activation return Busy; cancel
remains available. Short monitor sections only change references; native work and
releases occur outside, and reachability fences protect active snapshots.
Cancellation admitted before/during handoff may affect the successor. Join it
before treating a racing result as usable. Failed activation may follow durable
commit: close and resume the original configuration rather than create another
installation. Wrapper lifetime checks produce Closed/Busy diagnostics; native
records retain their exact code, text and truncation flag.

The setup consumer checks closed aliases, observes collection of the old setup
within 32 test-only GC rounds, and then uses the successor. Its native fixture
checks original state through local and witnessed restart, bad signatures,
held-reply cancellation, and explicit signed TCP/mutual-TLS activation. This is
bounded runtime evidence; it does not establish every JVM or mobile lifecycle.
The installation sync-interruption matrix injects its test-only probe directly
into the selected JVM and actual native library, preserving the verified JAR
closure. It calibrates activation/close syncs, checks each before/after process
cut, distinguishes observed from unknown replies, and reopens original Creating
or Active state. Ordinary device access follows that persisted phase, and resume
must preserve the original journal/account position. This finite local workload
does not qualify power loss, returned I/O errors or required-witness commit cuts.

The separate `setup_io` workload returns actual EIO directly inside the verified
JVM/native-library process. Phase receipts distinguish opening (204), activation
commit (207) and post-commit close syncs. Failure releases no successor and leaves
the setup closed to work but still disposable. Unknown commits must resume the
original installation, which may already be Active. Close releases ownership; it
is not another durability receipt for recoverable redb shutdown metadata. The
reader binds actual response codes to their sync phase, original identity and
account position. Required-witness commits and physical power loss remain separate.

`ContinuityOwner.prepareReopen(path, quality, session, witness)` copies an
explicit existing `SessionID` and returns the same kind of pending operational
owner. `finishOpen` performs native historical-snapshot and Active-installation
admission; `reopen` closes a failed preparation while preserving its original
failure and any suppressed disposal error. It does not extend credential/policy
validity, bypass current rosters/witnesses, create missing state or fall back from
fresh admission. This requires the matching native library's additive
`qpc_owner_v1_prepare_reopen` symbol; an older missing-symbol library is refused.
The prepared-owner Serial/G1 matrix now interleaves fresh, restoration and cleanup
preparations in the shared 64-slot registry. Every 64-owner round includes 21
restoration preparations. The local restoration trace uses the public Kotlin
method with its real current clock and independent Rust TLS receiver processes;
unknown application commitment is reconciled using the same message identity.
A separate development trace restores the responder's original session with
required signed TCP and mutual-TLS witnesses. Missing/wrong pins and bad signatures
refuse admission; partial reply and stalled handshake cancellation must allow the
same session to reopen afterward. Independent readback checks the public records.
Fresh archive qualification remains required. Advertisement expiry, witnessed
constructor cancellation and Kotlin interruption retain separate workloads.

All native calls are synchronous. The wrapper adds no operation executor or
automatic retry. Native BUSY preserves the owner; cancellation remains available
while another invocation is active. Deterministic `use`/`close` is required for
normal lifecycle management. A Cleaner is a nondeterministic backstop and reports
unexpected disposal failure. Its state never references its registered owner;
each call uses a [reachability fence](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Reference.html#reachabilityFence(java.lang.Object))
to keep that owner alive through return. Handles are process-local references,
not permissions against hostile code inside the same process.

`ContinuityDevice` prepares/opens an already Active original installation. Its
`preparePeer`/`preparePeerReopen` methods take public peer configuration, quality,
an explicit bootstrap role and (for restoration) the original session. A live
peer retains the hidden native parent independently of the public device wrapper.
Closing the device explicitly invalidates its children; closing a peer releases
its parent link after success or known CLOSED. BUSY and unknown failures preserve
the link and original diagnostic. Each native call takes a strong atomic parent
snapshot and fences it through return. The Cleaner action retains upstream
parents only, never its own registered object; there is no parent-to-child cycle.
After the last child releases a hidden parent, its Cleaner still runs
nondeterministically. Retain and explicitly close the device when deterministic
store release is required.

Use `PeerConfiguration` to supply peer material without constructing a sidecar
directory. Its `PeerDeviceExpectation` values contain independently approved
account pins, exact device IDs and unsigned generations. Bundle bytes remain
untrusted input, separate from the directory expectation and TLS pin/name:

```kotlin
val input = PeerConfiguration(expectedInitiator, expectedResponder, expectedDirectory,
    signedBundle, pinnedPeerCertificate, peerName)
device.preparePeer(input, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR).use { peer ->
    peer.finishOpen()
    // Use this admitted peer through the existing connection API.
}
```

Public arrays are copied and returned through immutable `PublicBytes` values;
the FFM arena only borrows its owned buffers for native preparation. Use
`preparePeerReopen(input, quality, role, originalSession)` for exact restoration,
with no fresh-bootstrap fallback. Preparing a descriptor does not authenticate a
remote TLS endpoint. Keep the original initiation/session/message ID after an
uncertain connection result. Explicit parent close remains the deterministic
store-release operation; Cleaner is an asynchronous backstop.

Account APIs expose `nextAccountOperation`, typed aggregate status and
`sendAccountMember` with the complete original target list. Every target wrapper
remains reachable through native return. Native admission verifies distinct live
children of the exact selected parent, original sessions and the complete required
recipient set. Committed aggregate state does not imply remote consumption;
retained member outcomes distinguish confirmation, pending resolution, unknown
delivery, retired history and abandoned reservations. Keep the original operation
and inputs after failure; the wrapper does not retry, generate replacement IDs
or fall back to unary sends. The separate
[required-TLS-witness delivery trace](../../c/ContinuityPackageConsumer/README.md#complete-account-delivery-with-a-required-tls-witness)
now verifies receiver exit after application commit, original-ID replay and both
member confirmations through actual Kotlin processes in own-account and
peer-account layouts. The
[own-account trace](../../c/ContinuityPackageConsumer/README.md#own-account-delivery-and-cleanup)
also requires complete-recipient refusal and original-roster public readback,
and reconciles four committed TLS witness reply losses during cleanup.
Provisioning/renewal and broader fault/concurrency coverage retain separate
qualification requirements.

The complete-account consumer additionally observes collection of the public
device before prepared peer activation, races two explicit peer closes, and keeps
closed aliases alive while checking all 64 native slots can be reclaimed and the
original store reopens. Its bounded test-only Cleaner oracle retries only native
capacity status 4; no protocol or installation operation is retried. Serial and
G1 account runs are separate from the explicitly C2-compiled in-flight server
tests below. New archive qualification must include both owner and account paths.

The client surface includes establishment, original-ID send/status and rekey.
The server surface binds one owned listener and serves bootstrap/application or
control exchanges. Application callbacks receive owned copies and must return
only after effect and session/message deduplication are durably committed
together. Every thrown callback exception becomes a nonzero native callback
result; its original JVM cause and native error remain associated. No JVM
exception may unwind through C. A consumed duplicate must skip the callback.

Recovery exposes every header, reservation, epoch, unknown-send, delivery and
skipped-position field. `begin` freezes; it does not acknowledge. Read and durably
persist the complete original report and ID before `acknowledge`. Retain the
authenticated archive before retiring catalogue metadata. Restoration grants no
operational authority. Any failed/unknown operation requires reconciliation with
the same installation and IDs, never an inferred empty result or a new ID.

`ContinuityRecoveryOwner.selectAccount(operation)` consumes discovery and selects
the complete original account operation, retaining all three native storage owners.
It accepts no recipient subset and authenticates original member authority before
recovery writes. Session and account selection are mutually exclusive.
`beginAccountCleanup()` freezes all original members and returns the operation,
report and member count. Traverse every `accountMemberAt`, `accountReservation`,
`accountEpochAt`, `accountUnconfirmedAt`, `accountDeliveryAt` and
`accountSkippedPosition` before host accounting. These records retain full-width
unsigned counters and immutable copies of public identities. A failed read leaves
an incomplete report, never an empty loss set.

Only after the complete report and original IDs are durable in one deduplicated
host transaction may `acknowledgeAccount(report)` discharge the reserved loss.
Reconcile an unknown result with `accountCleanupStatus()` under the original
operation/report. `retireAccount()` removes acknowledged batch metadata while
retaining session/bootstrap tombstones and consumed capacity. It never reactivates
keys. Cancellation blocks mutation but permits reading a retained immutable
snapshot until close. Fresh required-witness status still requires the original
witness. Independent session cleanup cannot discharge a whole-account loss.

The separate account-cleanup collector drives actual JVM processes from the
installed Maven consumer and pins its Java executable, full JAR classpath and
native library. It injects calibrated sync interruptions directly into Java;
setup helpers use the separately retained launcher. After durable SDK revocation,
Kotlin retains the whole report, checks invalid indices/wrong-ID/cancellation
refusals, acknowledges, retires and reopens. Independent native and Python readers
compare every field with original pre-fault identities and ciphertext commitments.
The local development trace covers native Debug/Release and minimum-Rust Release
libraries, each with 28 commands and 139 public records. These are same-host,
local-profile process cuts, not power loss, witnessed/own-account aggregate cleanup
or Android JNI qualification. The actual distribution collector also requires this
trace before accepting a Kotlin profile.

The separate required-witness trace uses actual Kotlin bootstrap/cleanup processes
and drops committed witness responses during reservation, freeze, acknowledgement
and retirement. Every unknown result is reconciled using the original operation
and report. A reopen that resolves pending retirement can return a selected owner
whose status is `Retired`; repeated retirement is a metadata-only no-op, and the
next reopen refuses with Retired. No operational permission is reconstructed.
Missing/wrong pins, corrupt signatures and witness unavailability after retirement
remain failures. Its 68 public files include the parent collection/close receipt;
independent replay binds all four lost commands to fresh challenges and the complete
loss report. This is explicit signed TCP with unencrypted metadata, not encrypted
witness account, own-account, power-loss or independent-engine qualification.

The initial eight development tests execute native preparation, cancellation,
failed activation, shared owner capacity, close and stale-handle behavior; compare
C/JVM structure sizes/alignment; and verify unsigned counters and input copies.
An independent Java JAR consumer runs, while direct raw-owner access fails to
compile. These are scoped checks, not a proof of all JVM lifetime behavior.

The separate `consumer` project installs this module from its exact local Maven
GAV with strict dependency checks and warnings-as-errors. On macOS arm64 with
Temurin 25.0.4.1 and Gradle 9.8.0, that installed consumer has executed the existing
Rust-driven client, server and recovery workloads against the f753e75d native
package. They cover actual TLS bootstrap, original-ID sends, lost acknowledgements,
network rekey, concurrent BUSY close and cancellation/reopen, application callback
exceptions, commit uncertainty and process exit, duplicate callback suppression,
SDK revocation, complete prepared two-epoch loss accounting, original-report
reconciliation, metadata retirement and closed-archive restoration. Receiver
effects, command logs, retained reports and archive bytes are independently read
back. Both endpoints share the existing native protocol engine. The prepared
recovery history has zero reservations; it does not qualify positive reservations.

The executable's raw `NativeKindProbe` is an intentional C-ABI negative control,
isolated from the SDK JAR. Its application and report records use no-clobber files
in a trusted, harness-owned local POSIX directory. They qualify process exits,
not a production application transaction layer, power loss or adversarial
parent-directory replacement. A failure to persist, verify or remove an owned
temporary record remains a failure. Terminal success is printed after owner close.

The `artifact/continuity_package.py --with-c-consumer --with-kotlin-consumer`
collector builds this SDK outside the checkout, stages its fixed Maven version,
archives and extracts each native Debug/Release package, and builds the independent
consumer from the extracted repository. It requires explicit
`--kotlin-java-home /absolute/jdk/home` and
`--kotlin-gradle-home /absolute/gradle/installation`. The selected JDK 25 and Gradle
9.8.0 distributions are hashed before/after execution, including JVM modules and
Gradle implementation JARs. Gradle uses a fresh private user home, strict upstream
and candidate checksums, no automatic JDK downloads, and an explicitly selected
in-process Kotlin compiler. Shared Maven validation keeps this coordinate and
`qpc-owner/1` manifest distinct from product ABI 2.

The collector checks each complete JUnit record, exact resolved/installed JARs,
both archives and licenses, all three public traces, and Java named-module calls.
Missing native permission, absent/relative/directory library paths, missing symbols
and private-owner construction must fail. The private-constructor control uses
javac diagnostic codes so localized messages cannot change its meaning. Selected
public records are exported for independent replay; private installations are not.
The existing macOS installed-binding CI job now requests this collector alongside
Swift. A successful development run of this producer still uses the retained
f753e75d native libraries and explicitly recorded controller; it is not complete
current-source CI qualification. That separate checkpoint is now closed for
commit `2523be07`: macOS arm64 run `36918986946`, job `110563064062`, completes
both profiles. Independent readback binds 229 collector source inputs to that
commit, verifies both 247-file packages, all 188 public trace records, sixteen
owner test executions, Java module calls and fourteen refusal controls. It does
not qualify subsequent source changes.

The installed consumer now also executes the existing signed-TCP and mutual-TLS
witness workloads, including lost witness advances, cancellation, reconciliation,
scoped recovery, retirement and refusal of altered authority. Two-stage activation
checks both owner kinds, pre-cancellation, bounded copied configuration after the
preparation arena closes, BUSY behavior during network admission, failed activation,
socket closure and reopening the same installation. Development runs against the
retained f753e75d Debug/Release native libraries independently replay these traces.
The collector requires them for each newly built native profile.

A separate test-host invocation interrupts the controlling JVM thread during
blocked activation. The host explicitly calls native cancel, joins its owned
worker, retains native error 218 and the controlling thread's interrupt flag,
and closes the owner before writing its receipt and terminal output. Both TCP
and TLS cases are required and independently read back alongside the full
constructor trace. This is not automatic cancellation of synchronous FFM calls
by `Thread.interrupt`, nor a GC-pressure qualification. The SDK adds no worker
thread. Failures in the barrier, cancellation or worker retain their causes;
the host joins the worker even when the controlling thread is interrupted.

The collector also requires the shared journal sync-interruption matrix. It
calibrates real send, freeze and acknowledgement syncs, interrupts before and
after each boundary, and compares Kotlin and native observations after reopening.
Development execution against retained f753e75d Debug/Release libraries completes
59 cases and 771 commands per profile, including eight Reserved send outcomes.
Independent replay checks 96 raw sync receipts and 342 public records per profile,
including complete reserved lengths/IDs, unknown-commit phases, the original loss
report and closed archive, operational revocation and retirement/restoration.
The two native profiles take 309.132 and 308.407 seconds on the observed macOS host.
This qualifies the selected process-interruption cases; it is not power-loss
or full current-source package qualification.

The fault driver launches the explicitly identified JVM directly, with fixed
native-access flags and a closed four-JAR classpath. All executable, JAR, native
library and probe bytes are checked before and after the matrix; the collector
also binds the full JDK distribution. The ordinary installed launcher remains
the setup helper's entry point. A retained preflight found no injected-probe
receipt through the shell launcher but 13 real syncs through the direct JVM.
Apple documents [dyld environment removal for protected-process launches](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html).
The injector remains isolated to owned test children. Missing or changed receipts,
incomplete cuts, altered loss fields and a substituted original report fail.

Required follow-up includes current-source Debug/Release collection and CI,
other native-call lifetime paths, broader JVM interruption, additional JVM/OS targets,
and Android ART/JNI. This candidate does not yet satisfy full 0.2.0 admission.

The collector separately runs bounded prepared-owner lifetime checks under Serial
GC and G1, with an explicit 32-MiB initial / 128-MiB maximum heap, for each native
profile. Sixteen rounds per JVM observe collection of 1,024 forgotten owner graphs
and restoration of every native slot. A collected sentinel establishes actual GC
while another full pool remains strongly reachable and usable. After explicit
close and slot reuse, all 1,024 stale owners must reject cancel, activation and
close; replacement owners must still reach their original installation-admission
failure rather than becoming cancelled or closed. Operational configuration status
500 and recovery private-file status 203 are checked separately against direct C
controls; both cancelled preparations retain status 302.

Development execution uses the unchanged installed SDK JAR and retained f753e75d
Debug/Release libraries. All four collector/profile combinations pass, as do the
existing opening/interruption regressions. An isolated SDK source copy with its
Cleaner release action deliberately disabled fails the same GC fixture in round
one, with all original slots unavailable. That mutant is a negative oracle only
and is excluded from product packages. The first GC fixture's incorrect shared
500 assertion is retained; only its role-specific expectation was corrected.
These checks cover prepared owners, bounded observation of the nondeterministic
Cleaner, and stale references. Explicit close remains the normal lifecycle
contract; collection within a fixed time, all collectors, and in-flight safety
are not established by this workload.

A separate installed server workload releases both external owner references
inside the real application callback, after retaining the original BUSY-close
assertion. It observes collection of the public wrapper while the native call
remains active. Serial GC and G1 each run the complete server workload against
both retained native profiles: eight callbacks per run preserve their copied
delivery bytes through GC; seven returning calls retain those bytes after the
FFM arena closes and restore all 64 native slots. The crash-after-effect callback
intentionally exits and has no return receipt. Callback exceptions retain their
exact original JVM object; duplicate suppression and unknown-commit/rekey checks
remain required.

This fixture explicitly compiles three lifetime-sensitive frames with C2 and
retains the JVM compilation logs; the verifier requires those compilations for
each invocation. It does not rely on an interpreter retaining otherwise dead
receiver variables. An isolated SDK copy with only the native-call reachability
fence removed fails under both collectors: the Cleaner observes BUSY status 3
during the callback and the original native slot is not recovered after return.
Neither that mutant nor these JVM stress flags enter the SDK artifact or normal
launcher. These bounded tests establish this selected server path on the observed
JDK, not a general collection deadline or all native-call/JVM lifetime behavior.

The hosted c3c217e1 installed-package job also has independent source/archive and
execution readback: 231 committed inputs, two 249-file packages, and 526 selected
public files across local and witnessed traces. That exact commit predates the
sync-fault/GC additions. Its separate Android 16-KiB job failed before
instrumentation, so the overall run is not a successful release qualification.

The Gradle publication repository is local to `build/candidate-maven`. No public
registry, signing credentials or remote publication task is configured.

For an explicitly selected JDK 25 and Gradle 9.8.0, stage the SDK with
`gradle publishContinuityPublicationToCandidateRepository --dependency-verification strict --warning-mode fail`.
Run its tests with `gradle test -Pqperiapt.continuity.lib=/absolute/installed/library`
and the same strict verification flags. The independent consumer requires
`-Pqperiapt.repository=/absolute/local/maven`; before `installDist`, pin the exact
candidate JAR, POM and module checksums in its own verification metadata, retaining
the upstream dependency checksums. A missing or changed artifact must fail.


The separate complete-account TLS workload bootstraps two original peer sessions
and freezes, acknowledges and retires the reserved account after SDK revocation.
It uses the existing native mutual TLS witness with three exact certificate/subject
bindings. Wrong witness pins, TLS names and certificate subjects refuse selection;
missing or unreachable original authority remains a failure after retirement.
Every measured foreign TLS phase must leave the plaintext witness's request count
unchanged. The complete loss report retains two reservations, two older unknown
sends, five unconsumed deliveries and two skipped positions across fresh processes.

The reserved state is deliberately prepared by losing one committed response over
signed TCP; native fixture preparation and report readback also use that original
witness. This workload therefore qualifies encrypted account bootstrap and cleanup,
not loss of TLS commit responses or a complete witnessed account-delivery/fault
matrix. The collector retains this carrier distinction and all eleven phase ranges
in its separate account-TLS public export. The original signed-TCP four-loss trace
remains mandatory. No raw owner handle, new native export or alternate TLS engine
is added. Current/native-minimum development runs remain separate from a complete
archive-produced cohort and final distribution admission.

For required-witness renewal, call `prepareWitnessedCredentialRenewal` and retain
the immutable 296-byte proposal for independent approval. Then call
`commitWitnessedCredentialRenewal`, `closeWitnessedCredentialRenewal` or
`reconcileWitnessedCredentialRenewal` with the original operation and statement.
These borrow the enrollment owner and return no Device. New Commit requires current
authority; terminal history can use the original pinned signed policy without an
SDK runtime. `Closed` rejects the exact target while its predecessor may remain
live. Source TCP/TLS Applied/Closed checks are separate from installed archives,
the complete expiry/fault matrix and physical platforms.

For a staged grant without a proposal, `prepareWitnessedCredentialCancellation()`
returns an immutable 248-byte descriptor for independent cancellation approval.
It reserves the original journal without a target image, SDK database or witness
request; the original pinned historical policy is sufficient after expiry. Resume
the same enrollment and reconcile the original operation/statement after the
witness approves `Closed`. `Unavailable` keeps the reservation pending. Durable
local `Closed` precedes ACK and exact reservation removal; an interrupted ACK is
retried on reopen. The descriptor does not grant current device authority.
The package collector requires the eight real-process cancellation cases described
in the [C consumer](../../c/ContinuityPackageConsumer/README.md), using this Kotlin
client and the shared native engine. This remains separate from Android and
independent protocol-implementation qualification.


### Explicit policy continuation

`PolicyDocument` owns a copied signed document plus the independently supplied
policy root, family and `PolicyCheckpoint`. A checkpoint is not a roster head,
and reading a document is not a current-authority claim. Keep the original P0
configuration at the enrollment path. On each resumed enrollment select P1 with
`selectContinuedPolicy(sdkPath, targetDocument)`; C retains that SDK store/runtime
until close or transfers it with the original signer to the activated device.

Stage the original account grant and both policy approvals with
`stagePolicyContinuation(grant, accountPin, operation, approvals, previousDocument,
previousT)`. `previousT` is null only for original P0. `stageContinuedCredentialRenewal`
advances G while carrying the already adopted T. Local coordination uses
`reconcilePolicyContinuation`; required witness coordination uses
`prepareWitnessedPolicyContinuation` and an independently approved exact proposal
before `commitWitnessedPolicyContinuation`. Target-free reservation uses
`prepareWitnessedPolicyCancellation`; the existing witnessed close/reconcile calls
accept the original transaction operation/statement for both G and G/T.

`PolicyRenewalProposal` and `PolicyRenewalCancellation` retain exact public bytes,
G, optional T and adopt/carry mode. Their `statement` is T for adopt and G for
carry or legacy. These are neither approvals nor terminal receipts. The old
296/248-byte credential metadata types remain unchanged. New native output
records check exact supported lengths, grammar and unused byte-array tails;
C alignment padding is not part of this wire contract.

`recoverHistoricalPolicyContinuation(operation, statement, targetDocument)` loads
independently pinned history without selecting P1 or opening its runtime. It can
finish only an already committed local target and never publishes a device.
`activatePolicyContinuation` transfers the same `NativeOwner` only after native
current G/T admission. The old registration becomes closed to operations and its
close is harmless after transfer. On an admitted failure, close the original
wrapper and explicitly resume the same stored registration; retain the original
operation and statement after unknown outcomes. Continued devices restore
existing sessions; this does not authorize fresh bootstrap.

The consumer exposes `enrollment-policy-stage`, `enrollment-policy-carry-stage`,
`enrollment-policy-reconcile`, `enrollment-policy-activate`,
`enrollment-policy-current-refused`, `enrollment-policy-recover-history` and
`enrollment-policy-history-pending` using the shared C fixture file convention.
`enrollment-policy-witness-prepare` retains the exact 329-byte joint proposal;
after independent witness approval, `enrollment-policy-witness-commit` submits
the original operation and transaction statement through the selected TCP/TLS carrier.
The original P0 documents stay in the registered directory; P1 and its SDK store
are in `continued-sdk`, and independent predecessor metadata is in `previous-policy`.

After `selectAccount(operation)`, `reconcileAccount()` returns the complete
original member set in canonical device order. Each `AccountReconciledMember`
retains its device, session and message IDs. `AccountMemberState` keeps committed,
acknowledged, resolution-pending, delivery-unknown, history-retired and
reservation-abandoned distinct. Only acknowledged proves authenticated
consumption; history-retired cannot distinguish earlier acknowledgement from
accounted unknown delivery. Returned bytes and the member list are immutable.
Native errors never become an empty successful result.

Persist the needed complete result and settle every original member before
`retireAccount()`. Native retirement rechecks eligibility and preserves original
session records and consumed capacity. The `recover-account-results` and
`recover-account-settled-retire` consumer commands exercise real revoked-account
recovery across signed-TCP and mutual-TLS interruptions. The same Kotlin client
now admits the peer roster and performs the interruption path described below.
That client also performs registration, witnessed local P/R updates, and durable
acknowledgement of each original member loss report. The combined workload does
not qualify P/R interruption, Android Continuity persistence, physical devices
or the final release. The separate optional OpenSSL
workload below covers pre-processing loss over mutual TLS.


### Independent policy updates

`PolicyRenewalID`, `PolicyRenewalScope` and `PolicyRenewalRequest` describe a
policy-only operation, separately from credential renewal and joint G/T.
Persist the original operation, complete request and exact approval bytes.
`policyRenewalRequest` reads the local-profile request;
`witnessedPolicyRenewalRequest` uses the explicitly configured original witness.
The request includes signed identity material and independent expected scope;
its public fields are not proof of user approval or current permission.

On each resumed enrollment, select the independently pinned current target with
`selectContinuedPolicy`, then call `stagePolicyRenewal` with the retained request,
original/current account pins, both policy-root approvals and the previous policy
document. Native staging re-verifies the actual predecessor, signatures and scope.
For the local profile, `reconcilePolicyRenewal` completes the original pending
transaction. `pendingPolicyRenewalApproval` returns its first saved signatures;
retrying never replaces the original operation or approvals.

For required witnesses, `prepareWitnessedPolicyRenewal` returns the complete
296-byte `IndependentPolicyProposal` in the separate `QPPWNP01` domain. Retain it
before requesting independent witness approval. Use that exact proposal with
`commitWitnessedPolicyRenewal`, `reconcileWitnessedPolicyRenewal` or
`closeWitnessedPolicyRenewal`. Commit requires current target authorization.
Historical reconciliation still uses the original witness configuration and can
operate without the current SDK store or application TLS inputs. It persists the
original terminal before ACK and exact pending cleanup.

`recoverWitnessedPolicyRenewalPreparation` reports only local presence or absence.
`witnessedPolicyRenewalProgress` preserves Reserved, Applied, Closed and terminal
retirement without acquiring a current runtime or private signing owner.
Unavailable witness history never proves no commit. `resolvePolicyRenewal`
returns the original local transaction's historical result. None of these result
queries grants a device. `activatePolicyRenewal` transfers the same original
owner only after native current-authority checks; after an admitted failure,
close and explicitly resume the original enrollment with the retained identities.

The installed-package collector requires ten real scenarios for each selected
language/profile: local restart/retry, typed refusals, original TLS message
recovery, TCP/TLS Applied and Closed, and three signed-TCP commit/ACK reply losses.
Every successful run must include 117 policy dispatches and seven foreign
transport calls. Registration and unrepresentable invalid raw-buffer controls
remain C operations and are reported as such. This uses one shared native engine;
TLS policy reply-loss, post-dispatch policy cancellation, physical process cuts,
platform persistence and independent implementation/security review remain
separate qualification gates. The roster-resolution types additionally decode
historical outcomes, including SupersededUnknown. The separate required-witness
roster and peer-roster surfaces are described below.

The Gradle test task tracks the selected native library file as an input.
Replacing its contents at the same path reruns native-bound unit tests; an
unchanged file can reuse a valid result. A library path alone is not sufficient
qualification identity.


### Witnessed roster updates

`RosterRefreshID` and the complete 417-byte `RosterRefreshProposal` identify one
same-credential roster/head update under the separate `QPRWNP01` domain.
`prepareWitnessedRosterRefresh` takes the independently pinned current root roster
and certificate. `RosterPolicySource` explicitly chooses original P0 or the
already selected current P; admission failure never selects another authority.
The native owner derives the actual predecessor and policy authorization.
Retain the returned proposal before obtaining independent witness approval, then
use exactly that proposal with `commitWitnessedRosterRefresh`,
`reconcileWitnessedRosterRefresh` or `closeWitnessedRosterRefresh`.

`recoverWitnessedRosterRefreshPreparation` and `witnessedRosterRefreshProgress`
read original historical metadata without current SDK or private signing input.
Local absence and Unavailable witness history do not prove no commit. Progress
keeps Staged, Reserved, Applied, Closed and AbandonedBeforePreparation separate;
terminal retirement is durable cleanup, not a new operational lease. Scope fields
must agree with the full retained proposal. `abandonUnpreparedRosterRefresh` is
allowed only before any proposal was released and when the original local
pending state is absent. It never manufactures a witness Closed outcome.
After an admitted failure, close and resume the original enrollment with the
same operation and proposal; commit and activation still require current authority.

The installed collector requires twelve scenarios and 141 foreign R dispatches:
eight TCP/mTLS P0/current-P Applied/Closed combinations, three processed TCP
commit/ACK reply losses, and an initial head-query failure followed by explicit
local abandonment without current runtime or network. C still performs enrollment,
P adoption, invalid native grammar controls, activation and successor P requests.
This is one shared protocol engine. The foreign R qualification does not cover
TLS commit reply loss, post-dispatch cancellation, process cuts, peer-roster
admission, platform persistence or independent security review.


### Current peer rosters and original account recovery

`ContinuityDevice.admitPeerRoster` accepts authentic public roster bytes
(1..65536 bytes) and an independently selected account/root/family/checkpoint.
It updates a known remote account through the original device service. It cannot
update the local account, replace policy or create a session. The returned
checkpoint describes installed current state; it is not a transaction receipt.
Rollback and same-version forks remain native errors. Exact retries still need
current local authorization and the configured original witness.

After I/O, witness or cancellation failure, close the original parent and reopen
it under current authority, then retry the same target. Unknown commit must not
be converted to absence or a new identity. Previously opened peers remain fenced
by native current-roster checks. Complete-account recovery preserves every
original member, including authenticated consumption versus unknown delivery,
before durable host accounting permits final metadata retirement.

The installed collector selects this same language for registration, local P/R
updates, account traffic, peer admission and full account recovery. It obtains the original account operation,
sends to both original sessions, observes a lost application receipt, and reads
status before and after local P/R updates. Exact retained retries preserve the
original effects; changed membership/input, unary release and cancelled peers
remain refusals. This adds 99 foreign traffic calls across the nine scenarios,
plus 11 in the optional OpenSSL scenario. The selected language also establishes
both original sessions and executes the receivers: 18 sender establishments and
36 receiver processes across the nine scenarios, including nine actual exits
after the application effect is durable but before its receipt is sent. The
OpenSSL scenario adds two establishments and four receivers with one such exit.
The original sessions, message IDs and independently read application files must
remain unchanged through recovery. Each scenario also requires seven registration
calls, seven witnessed policy calls and five roster calls from the same selected
client. Registration verifies the original signer and signed request before
activation; P/R adoption preserves the original enrollment and established sessions.
The native host supplies independent root/policy authorities, SDK setup and
witness approvals. The combined path covers normal P/R adoption; separate
policy/roster workloads retain their interruption coverage.
Selecting an enrollment parent cannot bootstrap a new session through the
account commands; initial establishment uses the original enrollment's explicit
connect path. It requires nine scenarios: ordinary revocation over signed
TCP and mTLS; unprocessed TCP loss; processed reply loss, in-flight cancellation
and an observed process kill over each carrier. Every language run includes
25 completed foreign peer-control dispatches and two actual killed clients.
The same foreign client performs 36 member-closure calls: it writes and syncs
each original loss report, reopens that exact report, then acknowledges the
original report twice and checks its closed identity. C retains 27 raw
input/output-buffer controls. Foreign post-dispatch failures are checked as typed
errors; the separate C baseline checks untouched raw success outputs. This is
one shared native protocol engine, not an independent implementation.

When `--witness-openssl-prefix` is selected, a separate tenth scenario uses the
pinned independent OpenSSL endpoint. It authenticates the complete mutual-TLS
request and drops it before the native witness store handles it. The witness
image must remain unchanged. Recovery retains the original sealed target, uses
a fresh challenge for the same command, and preserves all original account
member results through retirement. This adds three foreign peer calls, four foreign member-closure calls and
three C raw-input controls. The collector requires the C baseline first and
pins the endpoint executable and its OpenSSL dependencies. This qualifies the
independent TLS endpoint; native TLS server pre-processing interruption,
physical platforms and platform persistence remain separate gates.

## Permanently retired enrolled devices

`ContinuityRetiredEnrollment` is a separate cleanup-only owner over the existing
native engine. Supply the original `EnrollmentIntent` and independently retained
`RetiredEnrollmentAuthority`: witness identity/key, exact replacement proposal,
old subject and signed permanent retirement proof. Construction checks widths;
native preparation verifies authority. Never use an untrusted response to choose
its own pin. `prepareOpen` snapshots inputs and `finishOpen` opens existing state.
Close operational device/peer owners first.

Read `inventory()`, obtain independent inventory retention, and prepare the report.
Retain its original proposal and obtain the matching witness report receipt.
`loadReport` returns every canonical byte in `RetiredDeviceReport.canonicalBytes`
and a separate keyed report ID. Local proposal absence is not witness non-commit.
Durably save the complete bytes/proposal and account by report ID before calling
`prepareAcknowledgement` with the actual saved bytes. The SDK does not infer
external host effects. Only the independently signed purpose-21 ACK authorizes
`eraseJournal`; report-retention signatures have a different purpose.

After an unknown outcome, inspect the original journal state, prepare the exact
signer erasure, inspect signer state and erase. Successful `eraseSigner` consumes
the resource too; close the registry handle afterwards. Native errors after
admission consume it, while static width rejection precedes admission. Reopen
the exact original inputs to reconcile, without resetting or changing backups.
The wrapper retains the existing native owner through each invocation and reuses
its Cleaner/explicit-close rules. It exposes no raw handle, operational device or
signer. Java source cannot invoke its private owner constructor.

macOS arm64/JDK 25 private Maven consumers now pass eight actual cleanup processes
with each Debug/Release C engine under Serial and G1 configurations. Both native
profiles pass 54 named JVM tests; original registration and wrong-purpose ACK
refusal also pass. This does not assert that every run triggered collection or
qualify every JVM's GC behavior. Complete Kotlin distribution qualification,
Android/WASM persistence, complete foreign replacement and physical erasure or
power-loss guarantees remain separate. The replacement fixture also requires ten
Kotlin processes through the existing registration API: generation-2 creation,
original-request reopen, grant acceptance/retry, original genesis preparation,
refusal before witness replacement and activation/reopen after authorization.
After an activation failure, retained `Activating` state resumes that genesis;
it cannot prepare another installation. Two more Kotlin processes serve the
successor's fresh TLS bootstrap and reopen the same session for durable message
consumption. Exact returned identities, callback counts and complete host effect
bytes must match the native sender. Three additional Kotlin processes retain the
next publication ID, prepare its complete advertisement and recover the exact
bytes after reopening. Both actual connection bundles use that manifest and all
four proofs. Account issuance and witness replacement approval remain with the
native Rust controller; device clients receive no account-root signing authority.

## Local prekey publication

An activated `ContinuityDevice`, including one returned by
`ContinuityEnrollment`, prepares a complete local publication without exposing its
signer. Construct an immutable `PublicationPlan` with an independently trusted
directory expectation, finite `Counter64` validity and ordered `PublicationKey`
members. Explicit reuse names a `PrekeyInventoryID`; native admission checks its
role, availability, policy and interval.

Read `nextPublication()` and durably retain the ID and full plan before calling
`preparePublication(id, plan)`. After an uncertain result, reopen the original
enrollment and retry the same inputs. `PreparedPublication.canonicalBytes` holds
the entire `QPPUBA01` result. Inventory IDs follow original plan order; membership
proofs follow canonical manifest order. The wrapper checks bounds, unique IDs,
reuse identities, proof order and trailing bytes; the shared native engine
performs cryptographic verification and current authorization. Parsing retained
bytes alone establishes neither signature validity nor current permission.

`publicationStatus(id)` distinguishes absent, reserved, prepared and retired
local history. Prepared may no longer be releasable after expiry, revocation or
key consumption. `retirePublication(id, artifact)` reclaims acknowledged public
history without revoking inventory. `abandonPublication(id, intent)` applies only
to the original reserved intent and retires fresh unshared members. Neither
operation asserts remote directory publication or physical erasure. Cancellation,
owner closure and uncertain-result recovery use the existing native owner rules.

## First-use configuration (unpublished candidate)

Start with `ContinuityConfiguration.prepareCreate(path, input)`. Provide the original
SDK `SdkPolicyTrust`, exact `InitialSdkPolicy`, independently pinned protocol
`PolicyDocument`, and a `LocalTlsIdentity` containing your own DER certificate and
private key. `prepareCreate` copies the inputs synchronously and does no filesystem
work. Close the Kotlin TLS input after preparation, then call `finishOpen()`.
The native owner validates signatures and TLS key matching before publishing the
configuration, initial SDK store and generated wrapping key together. This does
not yet create or approve a registered device.

After an unknown creation result, retain the exact initial inputs and use
`prepareReconcile`; it compares the original committed configuration without
updating it. A mismatch, missing key, or corrupt store is an error, never permission
to reset state. To open known committed configuration, use `prepareOpen` with
original host SDK trust and pinned protocol metadata. Mutable root sidecar files
are not sources of authority for this route.

After `finishOpen`, use `createEnrollment(intent, witness)` or
`resumeEnrollment(originalIntent, witness)`. Both move the SAME native owner into
`ContinuityEnrollment`; closing or retaining the transferred configuration object
cannot dispose or pin the successor. The host still authenticates the account,
approves registration, supplies the independent account pin, obtains the signed
grant, and explicitly enrolls required witness genesis before activation. Supply
`ConfigurationWitness.signedTCP` or `mutualTLS` with the original witness identity,
key and endpoint. Mutual TLS also needs the independently provisioned exact peer
certificate and local TLS identity. Close that Kotlin TLS input after the
create/resume call returns. Omitting the witness never permits activation when the
signed policy requires one.

A current continuation target may be opened with its own explicit inputs and
moved into the original registration using `selectContinuationTarget(enrollment)`.
This only selects the target and transfers its SDK lease; the existing signed
policy renewal and activation transaction is still required. An admitted failure
may consume both volatile owners: close both and reopen their original inputs and
intent. Busy/admission errors do not imply adoption or grant permission to retry a
new operation.

Use `close`/`use` deterministically. Cleaner is a bounded-test-observed backstop,
not an application scheduling mechanism. Calls are synchronous; no coroutine
cancellation behavior is promised. `LocalTlsIdentity.close` clears its owned key
array and refuses later snapshots. An already admitted call completes with its
own snapshot; FFM key buffers are explicitly cleared before their confined arena
is closed. This cannot erase caller arrays or historical copies retained by JVM
implementation details. The legacy file configuration entry points remain for
existing consumers; new integrations should use the explicit configuration path.

The installed first-use workload combines that path with independently approved
protocol-policy renewal after the original message has an uncertain delivery
result. It then recovers the same session/message and observes one receiver
effect. Fixed/recoverable trust and local/signed-TCP/mutual-TLS carriers run under
both Serial and G1 GC with Debug and Release native libraries; see the
[integrated checkpoint](../../../research/sdk-alpha1/evidence/20261010-first-configuration-policy-integration/CHECKS.json).
That checkpoint covers renewal while P0 remained valid. The current workload
also requires actual P0 expiry, activation refusal 104, the unchanged original
request and independently approved P1 on the native reference receiver before
expiry. The reader binds the public observations to the original signed policy
and message. Credentials, rosters and the SDK policy remain unchanged;
SDK-policy replacement still needs its own qualification.

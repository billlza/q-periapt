# Continuity Kotlin/JVM candidate

This separate, unpublished `dev.qperiapt:q-periapt-continuity-kotlin:0.0.0`
module calls the existing `qpc-owner/1` C/Rust engine. It is not product ABI 2,
an Android JNI implementation, or an admitted 0.2.0 release artifact. The current
configuration opens the original private qualification installation; it does
not provision, replace trust, repair a journal or enroll a witness.

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

Account APIs expose `nextAccountOperation`, typed aggregate status and
`sendAccountMember` with the complete original target list. Every target wrapper
remains reachable through native return. Native admission verifies distinct live
children of the exact selected parent, original sessions and the complete required
recipient set. Committed aggregate state does not imply remote consumption;
retained member outcomes distinguish confirmation, pending resolution, unknown
delivery, retired history and abandoned reservations. Keep the original operation
and inputs after failure; the wrapper does not retry, generate replacement IDs
or fall back to unary sends. Whole-account abandonment/report traversal,
provisioning/renewal, required-witness and own-account foreign delivery retain
separate qualification requirements.

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

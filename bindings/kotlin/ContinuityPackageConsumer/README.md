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

All native calls are synchronous. The wrapper adds no operation executor or
automatic retry. Native BUSY preserves the owner; cancellation remains available
while another invocation is active. Deterministic `use`/`close` is required for
normal lifecycle management. A Cleaner is a nondeterministic backstop and reports
unexpected disposal failure. Its state never references its registered owner;
each call uses a [reachability fence](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Reference.html#reachabilityFence(java.lang.Object))
to keep that owner alive through return. Handles are process-local references,
not permissions against hostile code inside the same process.

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

Development execution remains separate from a committed-source package collector
and CI qualification. Required follow-up includes the final-source Debug/Release
package pipeline, witness and two-stage activation workloads, positive-reservation
sync-interruption matrix, JVM interrupt and GC pressure, additional JVM/OS targets,
and Android ART/JNI. This candidate does not yet satisfy full 0.2.0 admission.

The Gradle publication repository is local to `build/candidate-maven`. No public
registry, signing credentials or remote publication task is configured.

For an explicitly selected JDK 25 and Gradle 9.8.0, stage the SDK with
`gradle publishContinuityPublicationToCandidateRepository --dependency-verification strict --warning-mode fail`.
Run its tests with `gradle test -Pqperiapt.continuity.lib=/absolute/installed/library`
and the same strict verification flags. The independent consumer requires
`-Pqperiapt.repository=/absolute/local/maven`; before `installDist`, pin the exact
candidate JAR, POM and module checksums in its own verification metadata, retaining
the upstream dependency checksums. A missing or changed artifact must fail.

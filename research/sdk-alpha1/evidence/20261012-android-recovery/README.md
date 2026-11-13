# Android recovery facade checkpoint

The Java/JNI candidate now exposes cleanup-only recovery of the original
installation, complete immutable session/account reports, explicit report
acknowledgement, committed-member reconciliation and authenticated catalogue
restoration. The [usage guide](../../ANDROID_RECOVERY.md) leads with complete
reports and the application's durable accounting obligation. Unknown delivery
stays unknown; metadata retirement is not physical erasure.

The completed host qualifier runs **292 independent Java processes** across
Debug and Release:

- 168 first-use calls: 42 per SDK trust profile and build. These start with a
  Java-created installation, send to two original members, retain original IDs
  through receiver interruption and cancellation, then close sessions, restore
  authenticated archives and retire the aggregate without moving its counter.
- 88 recovery calls in four required-witness scenarios per build. C performs
  registration and operational traffic (36 additional C child processes); Java
  performs recovery. Signed TCP and native mutual TLS exercise lost reservation,
  freeze, acknowledgement and retirement replies, including own-account cleanup.
- 36 committed-member recovery calls after C peer revocation: one original member
  remains confirmed while the other progresses through pending resolution to
  delivery unknown. Java preserves the full original member set and report before
  retirement; it cannot relabel unknown delivery as acknowledged consumption.

Of the 292 calls, 176 use recovery-only APIs (52 first-use recovery calls plus
88 witness and 36 committed-member calls). Eight other first-use calls query the
account position and 108 exercise original setup/send. These counts overlap by
purpose, not by independent execution.

Every account loss report is compared field-for-field with native readback and
the prepared original history. The archive reader also binds every Java report
copy to that exact native report hash. Every counted epoch, reservation,
unconfirmed message, pending delivery and skipped position is collected before
host acknowledgement. Member reconciliation retains the original device, session
and message IDs across four observations. Tampered closure archives return 208;
retired aggregate selection returns 112. Native repeated acknowledgement,
retirement and index restoration checks retain their idempotency contract.

The public Java classes compile for Java 11 with `-Xlint:all -Werror`; probes use
Java 17 source level on JDK 25. Both real JNI bridges compile with strict C
warnings and run under `-Xcheck:jni` without diagnostics. Native Clippy and Rustfmt
checks cover the changed fixture. The existing parent JNI qualifier invokes this
same recovery qualifier and verifies the current 32-test inventory; older
30/31-test evidence keeps its explicit historical inventory. The complete parent
cohort was not redundantly rerun locally.

Three failed integration attempts remain in the archive. A test evidence parent
had the wrong permissions and was replaced with an owned private temporary
directory. Three redundant Java pre-operation queries then exceeded the exact
native witness census; the probe now uses its already obtained pre-operation
observation while preserving post-mutation queries. Finally, normal retirement
omitted the native reference's final negative assertion that beginning cleanup
again must return 112. Adding that assertion restores the exact workload. No
oracle count, assertion, trust check or directory security rule was weakened.

[CHECKS.json](CHECKS.json) identifies the 1,916 archived files and the
[HOST_CAPTURE.zip](HOST_CAPTURE.zip), SHA-256
`b8dfebef7e6a1ae1515bdaf7da3e054ad565a18cbfe710a52d0be5e0ad7f1c30`.
All member hashes and extracted public records were reread. The retained driver
is `qualify_integrated_complete.py`; it calls the canonical artifact qualifier
through the repository Python bootstrap. The archive includes frozen sources,
actual command receipts, public records, strict build/boundary logs and failed
attempts. It excludes private keys, journals and environment snapshots.

This is host Java/JNI validation with a shared native engine, not independent
protocol implementation or execution of this new API on ART. The previously
accepted single Android phone remains sufficient for its physical gate. No extra
phone or API 36 hardware is required. WASM persistence, independent implementation,
PCS/research, controlled performance and release admission remain separate work.

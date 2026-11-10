# Android whole-account facade checkpoint

The Java/JNI candidate now exposes `nextAccountOperation`, `accountStatus` and
`sendAccountMember` on the activated device. Typed operation/report IDs, immutable
target and result values, a bounded JNI input copy and one native aggregate call
preserve the existing complete-roster transaction contract. This is not a Java
loop of unary sends. All selected peer facades stay borrowed across the native
call, without holding a Java monitor. Caller payloads are copied and the facade
and JNI owned copies are cleared on exit.

The focused macOS arm64 host lane passes Debug and Release against the admitted
installed C libraries, with fixed and recoverable SDK trust. Its four cases use
108 independent Java processes. Each case creates an original registration and
two recipient sessions; omission, duplicate owners/sessions and prior cancellation
are refused before aggregate commitment. A native receiver exits with code 77
after recording an effect. Reopening and retrying the same operation recovers that
same message/effect. Changed payloads and incomplete retained target sets return
211. Both members then return retained confirmed results with zero exchanges,
including when the target array is reordered.

A second original operation blocks in real TLS. Concurrent parent query/close,
member close and other-member query return Busy. Cancelling the nonselected member
interrupts the active call with 302; local commitment is retained, and the other
peer is not permanently cancelled. New processes reopen that operation and
deliver both members. This is a test of local transaction and application commit
contracts, not a guarantee of arbitrary remote exactly-once effects or PCS.

Public Java sources compile with `--release 11 -Xlint:all -Werror`; the probes use
Java 17 source level on JDK 25. Both JNI bridges compile with strict C warnings
and run under `-Xcheck:jni` without diagnostics. Native Clippy passes with
`-D warnings`. Its initial rejection of potentially panicking test indices was
fixed with explicit bounds checks; the rejected source and logs are retained.
No lint rule or assertion was disabled. The final run uses the same dispatcher,
31-test inventory and account reader now wired into the normal host qualifier.
Historical 30-test root captures retain their explicit catalog.

[CHECKS.json](CHECKS.json) pins native/bridge/test identities and the 500-member
[HOST_CAPTURE.zip](HOST_CAPTURE.zip). All archive hashes and extracted public
records are reread. The new reader tests alter operation/session identities,
status, retry exchange counts, original effects and JNI diagnostics, and reject
missing execution/workload markers. The actual producer commands are retained;
the local final entry point is `check_final_retry.py` under
`target/continuity-android-account-facade/` using the repository Python bootstrap.

The full parent JNI lifecycle cohort is scheduled through its existing CI entry;
it was not redundantly rerun locally. This host result does not claim execution of
the new API on ART or a newly admitted AAR. The previously accepted single Android
phone remains sufficient for its physical gate; no second phone or API 36 device
is required. Account abandonment/retirement authority, WASM persistence, independent
implementation, research/performance and release work remain separately scoped.

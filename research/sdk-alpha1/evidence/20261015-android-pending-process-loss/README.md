# Android pending confirmation process loss

Two actual-package host routes passed: signed TCP/fixed trust/unapplied original
write and TLS/recoverable trust/already applied original write. Their 47 Java/JNI
calls include four abrupt process exits. The accepted API 37 arm64 phone passed
the TLS route in 23 distinct ART processes, including two abrupt exits. The same
source also passed the prior two cancellation routes in 43 fresh Java/JNI calls.
These counts are distinct executions. One current phone suffices for this
physical acceptance; no API 36 or second-phone requirement is added.

| Cut | Required observation and recovery |
| --- | --- |
| Query response withheld | The real witness handles Query and sends only a response prefix. A separate control channel binds the cut to the original proposal. The public owner is Busy. The process abruptly exits before confirmation can complete; reopening returns the same proposal and metadata. |
| Confirmation result lost | The public confirmation API returns, then the application abruptly exits before publishing its success result. Reopening observes pending absence; subsequent confirmation must still authenticate the exact original target and command through fresh Queries. |

Both cuts use `Runtime.halt(77)` without owner cleanup. On ART, the driver
requires the exact cut status, phase, proposal binding, installed APK hash and PID,
the platform's process-crash result, absence of a successful result and actual
process absence. It then reports the expected exit to the native harness. A
timeout, generic crash or ordinary force-stop after success cannot satisfy this
contract. The held TLS reply is released only after both the scoped disconnect
and independent process-exit observation. The second cut is after the public API
returned; it does not establish behavior during an internal database commit or
physical power loss.

The four Query challenges are distinct and nonzero, all carry the same Query
command and original subject. Only the first reply is withheld. The original
witness image does not change during these read-only calls. Original identity,
unknown-delivery accounting and the real business effect remain intact. Expired
activation still fails. For the already-applied route, confirmation and both
cuts precede any privileged controller completion; existing history needs no
new approval. For the unapplied route, exact independent approval comes first.

Qualification source: `226f1c161f9faec697e4d5395614b91d29b91177`. The unchanged actual engine remains
`610234b0b684e4e39bad97a953f5c66e74df2e91`. The ten extracted archives, reused C/JNI/JAR
binaries and unchanged AAR implementation inputs were verified. The new signed,
non-debuggable R8 APK contains the same native library bytes. No product API,
persistence format, error mapping or security policy was changed.

The barrier helper is shared with cancellation. The flow selects explicit cut
variants, and interruption result validation is separate from ordinary recovery
validation. The existing foreign-cut runner now returns its error instead of
panicking, preserving its exact exit77 and empty-output requirements so control
threads can be joined even when a child fails. Strict Clippy across all C test
targets, strict Java, AGP/R8, signature/native-member checks, 42 focused controls
and 86 clean-clone controls passed (control counts overlap). Source inventory is
689 Rust files; the Android catalog contains 68 tests. The permanent installed
qualifier includes the new routes in each native profile. This checkpoint runs
the Debug host harness and one Release APK route, not that full combined qualifier.

| Artifact | SHA-256 |
| --- | --- |
| Candidate archive | `81927540a53e6fa5fe5dc48ec8527f051f5603b1d72932aee9bdd31ee5a53d18` |
| Android release AAR | `6aee320502c5217a71f4f9f8af5d24dccd64f4e4344ab2caf9def28214b6b6f6` |
| Installed APK | `d651483c35b0d5515f8d5f3e007f770e659f8b41a1bfffaba56d452b4fa324fb` |
| Evidence capture | `a151edcaad64bcbc31252af6511157b2259cb6edf2822a723a08b44528e34518` |

`CAPTURE.zip` retains 876 public members, including transcripts, exact
cut receipts, process and binary identities, source and recipes. Every member was
read back and every public result reader rerun. Private keys/databases are
excluded and hardware selectors redacted. Each phone process was checked absent;
the newly owned app and reverse maps were removed. All execution cohorts are sealed.

Storage-internal interruption, subsequent operational continuation, full binding
lifecycle composition and positive Apple recovery remain open. These tests do
not establish power-loss behavior, PCS or an independent Continuity implementation.
CI for this source has not run; no release was published. The full 0.2.0 goal
remains active.

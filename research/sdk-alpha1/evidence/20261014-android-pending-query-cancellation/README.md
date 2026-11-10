# Android pending Query cancellation

Actual installed-package consumers passed two in-flight cancellation routes:
signed TCP/fixed trust/unapplied original write and TLS/recoverable trust/already
applied original write. Together they executed 43 Java/JNI calls. The accepted
API 37 arm64 phone also passed the TLS route in 21 distinct ART processes using a
fresh signed, non-debuggable R8 APK. One current phone is sufficient for this
physical acceptance; no API 36 or second-phone gap is assigned.

The test waits until the witness has handled the original Query and sent only a
prefix of its response. A separate bounded control connection binds that barrier
to the original proposal. The public owner refuses close while the operation is
busy. The caller then invokes public `cancel()`, joins the operation and checks
the untruncated native cancellation diagnostic. The witness releases its retained
TLS response only after that result. A fresh process reopens the original owner,
observes identical proposal/metadata and confirms/retries with distinct nonzero
Query challenges and the same Query command. The witness image remains unchanged
by the interrupted Query. Original identity, unknown message and business effect
remain intact; expired activation still fails.

The original expectation of error 302 after dispatch was incorrect. Existing C
contracts retain witness error 218 with the cause `witness dispatch cancelled;
reconcile original command`. Pre-dispatch cancellation still returns 302. Stopping
the wait cannot establish the old pending write outcome. No product error mapping
was changed to satisfy the test. The Java probe requires both 218 and its native
cancellation cause; a generic transport drop cannot satisfy that check.

The first run failed in both routes and is retained. The signed route exposed
that incorrect expectation. The TLS control fixture inherited `O_NONBLOCK` on
Darwin and failed before receiving the complete control frame. An isolated Rust
socket probe reproduced an immediate `WouldBlock` despite a 200-ms read timeout;
explicit blocking mode observed the timeout at 201 ms. The fixture now explicitly
sets bounded blocking mode on the accepted control socket. Fresh identities and
storage were used after correction. The earlier missing test-only MessageId
generator compile failure is also retained; the control token now uses platform
entropy and is not a protocol message ID.

Qualification source: `5cf825754e4b03f7d3fdef22dead2e110a829e60`. The unchanged actual candidate
engine source remains `610234b0b684e4e39bad97a953f5c66e74df2e91`. All ten extracted Cargo
archives and reused C/JNI/JAR binaries were verified. AAR main-Java/JNI inputs
and native members match the preceding accepted artifact. This increment changes
qualification fixtures, result readers and documentation, not product code.

| Artifact | SHA-256 |
| --- | --- |
| Candidate archive | `81927540a53e6fa5fe5dc48ec8527f051f5603b1d72932aee9bdd31ee5a53d18` |
| Android release AAR | `6aee320502c5217a71f4f9f8af5d24dccd64f4e4344ab2caf9def28214b6b6f6` |
| Installed APK | `aa497fe67bc81be4be4ea98087c6bbcb3c16dbc423d495590e187028bc6a99ff` |
| Evidence capture | `878aa35f2a8f2322673704bb22c35e1ed8a48cb9c24e52232a9c610c3e686998` |

Strict Rust Clippy across all C test targets, strict Java compilation, AGP/R8,
APK signature and exact native member checks passed. The 39 focused controls and
83-test clean-clone suite passed (overlapping counts). The source gate checks 687
tracked Rust files and the Android catalog contains 66 tests. The permanent
installed host qualifier includes both new routes in each build profile. This
checkpoint runs the Debug host harness and one Release phone APK; it does not
claim a full rerun of that combined qualifier.

`CAPTURE.zip` contains 685 public files, including failed receipts,
source preimages, successful transcripts, process/hash identities and recipes.
`READBACK.json` verifies every member and reruns the public result readers. The
phone application and owned reverse ports were removed; each test process was
stopped and checked absent. Private test keys and databases are excluded, and
hardware selectors are redacted. All execution cohorts are sealed.

This closes the two specified Query cancellation cuts, not every pending-write
failure. Process/storage cuts during confirmation, subsequent operational
continuation, full binding lifecycle composition and positive Apple recovery
remain open. It does not establish power-loss behavior, PCS or an independent
Continuity implementation. CI for this source has not run; no release was
published. The full 0.2.0 goal remains active.

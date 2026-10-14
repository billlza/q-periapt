# Configured pending-write inspection and Android recovery

This checkpoint supplies a public, bounded controller-side decoder for complete
pending-write source/target metadata and exercises original recovery through the
public Android configuration entry point. Actual installed Cargo archives passed
the external controller build and an 18-call Java/JNI flow. The same scenario
passed on the accepted API 37 arm64 phone in 18 separate ART processes, using a
fresh non-debuggable R8 APK and the actual release AAR. This is one
signed-TCP/fixed-SDK/unapplied-write route, not full lifecycle qualification.

The engine and C/Java consumer source is `610234b0b684e4e39bad97a953f5c66e74df2e91`.
The APK qualification source is `af3cc37c8d251a88cc010352253cf5a01e7b0d9d`; its only additional
changes admit bounded fresh enrollment inputs into the test instrumentation.
Both clean source gates passed. The nine unchanged SDK archives retain their
previous clean source identity; the candidate archive was freshly produced and
verified from the current clean source. Consumers resolve all ten real archives
outside the checkout, with no source-overlay engine.

| Artifact | SHA-256 |
| --- | --- |
| Candidate Cargo archive | `81927540a53e6fa5fe5dc48ec8527f051f5603b1d72932aee9bdd31ee5a53d18` |
| Android release AAR | `6aee320502c5217a71f4f9f8af5d24dccd64f4e4344ab2caf9def28214b6b6f6` |
| Installed Android APK | `cfaf110c8cce9b2e288185382298567d3ed8de73e57020cf40dbc975a4361352` |
| Evidence capture | `857f87854d3526aab417a72e7071d5a35afbf6f12517c1a00bcd2a57978f7d68` |

The route creates a fresh configuration, identity and independent account
association, establishes a real session and loses an acknowledgement after the
receiver records the original business effect. A separately issued R2 roster
then reaches an unknown local-write outcome because the original witness Advance
was withheld before processing. Before causing this fault, the controller fixes
the exact expected R1/R2 public history and original session/message identities.
Complete inspection verifies that only the approved roster and its checkpoint
context change; every other record and the original unknown delivery remain.

After real policy expiry, the original request remains byte-identical in proposal,
binding and metadata. Damaged metadata is refused without a witness request;
unapproved recovery is refused. Independently approved completion and exact retry
send two fresh Queries and no Advance. The original pending intent disappears,
activation still returns the expired-policy error, original identity is unchanged,
and the receiver's original effect is unchanged. All 18 phone result hashes,
distinct process IDs, installed APK digests and process termination checks agree.
The newly owned APK and reverse ports are removed at completion. The current
API 37 phone satisfies this physical route; another phone or API 36 is not required.

`AnchorPendingWriteRecoveryProposal::inspect_metadata` checks the full metadata
commitment, scope, exact heads, bounded grammar, record ordering and canonical
round-trip. It performs no signature verification, privileged mutation or device
activation. It cannot establish that a sender's claims match its encrypted image
or independently approved business intent. The controller still verifies the
historical signature and makes its own approval; signed roster/publication
history bytes require their domain-specific verification. Parsing is split into
record, bootstrap/fanout and session modules rather than expanding the enrollment
state machine. This checkpoint makes no throughput or allocation improvement claim.

Six decoder/mutation tests cover all six record variants, all fanout member
states, complete live/terminal epochs, malformed bounds/tags/options, duplicate
record IDs, substituted heads and tails. Three real persisted pending-write tests
also compare decoded views with actual authenticated local views. Strict Rust
library/tests Clippy, Rust 1.90 compilation, product WASM Clippy and the installed
Android harness Clippy passed. The unchanged external source fails against the
old archive with only the missing-method E0599 and compiles against the new one.
There are 46 affected integration controls and 77 clean-clone package/inventory
controls. The tracked Rust inventory is 682; the Android harness inventory is 57.
These bounded mutation controls are not a libFuzzer run or a security proof.

Strict Java/JNI and AGP compilation, R8, exact 157 C exports, 16 KiB load alignment,
native dependency notices, APK signatures and byte-for-byte AAR/APK native member
checks passed. The permanent host JNI qualifier now includes this configured
pending-write scenario. Its entire Debug/Release suite was not rerun here; this
checkpoint runs the scoped actual-archive host case and physical Release APK case.

Locally retained failures include a prototype assertion that initially omitted the
roster record's checkpoint context, an unused fixture import, a receiver link
recipe missing existing translation units, an incorrect baseline tool invocation,
a WASM command missing its explicit compiler, and two historical-catalog reader
failures after adding the new test. Exact historical catalog selection fixes the
latter while current qualification still requires the full current catalog.
The first APK recipe also included a desktop-only ABI test fixture; its Android
compile failed on a ByteBuffer return type. The corrected recipe selects the
actual instrumentation consumers, preserving strict checks and the failed output.
No product exception or test failure is converted into a successful result.

`CAPTURE.zip` retains 570 public files, command receipts, source
identities, the prototype assertion, historical-catalog, WASM and APK failures,
and local recipes. `READBACK.json` records manifest
and hash verification plus independent reruns of both public result readers.
Private signing/wrapping keys, databases and the APK signing key are excluded;
test TLS credentials and hardware selectors are redacted from retained text.
All successful and failed cohorts are sealed. New execution requires fresh
identities, storage and output directories.

Applied-write/TLS/recoverable-SDK variants, pending-write storage/cancellation
cuts, subsequent operational continuation and full lifecycle composition remain
open. Earlier iPhone/iPad results cover ABI/owner boundaries; this checkpoint
does not convert those into positive Apple recovery results. These routes share
the same protocol engine and do not establish independent-implementation
interoperability, mobile-browser behavior, physical power-loss behavior or PCS.
CI for these new commits has not run; the previous e07 run remains distinct.
No package or release was published, and the full 0.2.0 goal remains active.

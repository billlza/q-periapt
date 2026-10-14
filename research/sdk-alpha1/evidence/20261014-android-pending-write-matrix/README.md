# Android pending-write recovery matrix

All eight actual-package host routes passed: signed TCP or TLS, fixed or
recoverable SDK trust, and an original write either unapplied or already applied
with its reply lost. The routes used 156 separate Java/JNI calls and fresh
identities, storage and business messages. The accepted API 37 arm64 phone also
passed the TLS/recoverable/applied route in 19 distinct ART processes using a fresh
non-debuggable R8 APK. The phone's earlier signed/fixed/unapplied result remains
in the [preceding checkpoint](../20261014-configured-pending-write-inspection/README.md).
No additional phone or API 36 hardware is required for this physical acceptance.

| Carrier | SDK trust | Original write | Calls |
| --- | --- | --- | --- |
| Signed TCP | fixed | unapplied | 20 |
| Signed TCP | fixed | applied | 19 |
| Signed TCP | recoverable | unapplied | 20 |
| Signed TCP | recoverable | applied | 19 |
| TLS | fixed | unapplied | 20 |
| TLS | fixed | applied | 19 |
| TLS | recoverable | unapplied | 20 |
| TLS | recoverable | applied | 19 |

The two outcomes deliberately have different authority requirements. If the
witness already applied the original authorized Advance before policy expiry,
the device confirms that history before any privileged recovery call. The later
controller completion is proved read-only by an unchanged actual witness image.
For an unapplied write, unapproved confirmation fails and independent exact R2
approval is required before the witness changes. Both paths preserve the original
unknown-delivery record and business effect; neither restores expired activation.

Each route verifies complete source/target metadata against the independently
issued R1/R2 roster and original session/message. Damaged metadata and a cancelled
owner fail without a witness call. After cancellation, a fresh owner recovers the
same proposal and metadata. The test then confirms/retries using two Queries and
no Advance, checks the pending intent is absent, and rejects activation under the
expired policy. This is pre-call cancellation coverage; it does not establish
cancellation after a Query has reached the server.

The native TLS reply-loss helper applies the real write and withholds its
encrypted reply. The unapplied TLS helper uses the existing independent OpenSSL
process: it authenticates the exact TLS peer/subject and complete frame before
withholding the native store call. Its retained negotiation logs require TLS 1.3,
X25519MLKEM768 and `q-periapt-anchor/1`. The two endpoints are explicitly pinned.
Registration inputs initially select signed transport; from activation through
business traffic and recovery the TLS routes use the encrypted endpoint. These
are independent TLS implementations sharing one Continuity engine, not two
independent implementations of the entire protocol.

Consumer source is `d20483402e11d116bbabec40b74177fe2979f6bb`. The actual candidate engine
archive remains `610234b0b684e4e39bad97a953f5c66e74df2e91`; this increment changes
qualification code, not the engine or published binding implementation. Every
file extracted from the ten original Cargo archives was rechecked, as were all
reused C/JNI/JAR binary identities and OpenSSL headers/libraries. The Android AAR
is byte-identical to the preceding checkpoint; its complete main-Java/JNI source
inventory was checked unchanged. The new APK compiles the current public probe
and test input adapter, with no package-private JNI or raw handle access.

| Artifact | SHA-256 |
| --- | --- |
| Candidate archive | `81927540a53e6fa5fe5dc48ec8527f051f5603b1d72932aee9bdd31ee5a53d18` |
| Android release AAR | `6aee320502c5217a71f4f9f8af5d24dccd64f4e4344ab2caf9def28214b6b6f6` |
| Installed Android APK | `4fd24302c10dbd8826c2693eb0f5b47f9ef8b13e1fc72b487a55b2fcf324814d` |
| Evidence capture | `9c1602b726e27099de4b0e890aecad8a080fded44aefcc4d7abc902677233d55` |

Strict Rust test Clippy, Java compilation, AGP/R8, APK signature and exact AAR/APK
native member checks passed. The 36 focused reader/integration controls and the
80-test clean-clone control suite passed; these counts overlap. The tracked Rust
inventory is 685 and Android harness inventory is 64. The permanent host qualifier
requires the qualified OpenSSL peer and runs all eight routes with two test
threads in each native build profile. This checkpoint executes the Debug host
matrix and one physical Release APK route; it is not a completed rerun of the
entire installed Debug/Release qualifier.

Accounting, flow and carrier faults are separate fixture modules. Pre-run review
caught an incomplete native TLS setup with only the phone leaf; it was corrected
to pin both actual endpoints before any matrix execution. The original compiled
fixture is retained as a preflight artifact, not represented as a runtime failure.
No runtime failure was suppressed or converted into a successful outcome.

`CAPTURE.zip` contains 1005 public files and receipts, including all
eight host results, the phone's 19 result hashes and distinct process IDs, TLS
negotiation logs, source/compiled identities and local recipes. `READBACK.json`
records complete hash/inventory verification and reruns of every public result
reader. The newly owned phone application and reverse ports were removed, with
process termination checked after each call. Private keys/databases are excluded;
both test TLS private keys and hardware selectors are redacted from retained text.
All cohorts are sealed; future execution needs fresh identities, storage and output.

In-flight Query cancellation, process/storage cuts during pending confirmation,
subsequent operational continuation and full lifecycle composition remain open.
The earlier Apple checks remain ABI/owner checks, not positive Apple recovery.
These results do not establish physical power-loss behavior, PCS, full protocol
interoperability or complete 0.2.0 release readiness. CI for this new source has
not run. No package or release was published; the full goal remains active.

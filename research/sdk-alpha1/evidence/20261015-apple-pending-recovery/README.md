# Physical Swift pending-write recovery

The offered iPad Pro 11-inch (M4) running iPadOS 27.0.1 completed two
fresh public Swift configuration routes: signed TCP with fixed SDK trust and an
unapplied original write, and signed TCP with recoverable SDK trust and an already
applied original write. The routes executed 20 and 19 separate application
processes. Every launch has an exact run-bound startup admission, an explicit
exit-zero observation and a matching public result copied from the application.

The device generates its own signing identity, installation and account-authority
store through public APIs. An independent native controller issues the initial
grant. Actual TLS traffic to the C reference application retains a message whose
effect committed but whose delivery result was lost. The pending R2 roster update
is captured before the original protocol policy expires on the wall clock.

Reopening preserves the original request, complete metadata, session, message and
business effect. Damaged metadata and pre-call cancellation are refused without
sending a witness request. Cancellation leaves the same intent recoverable.
The unapplied route refuses confirmation before independent exact approval. The
already-applied route confirms existing witness history with a read-only Query
before any privileged recovery call. Confirmation and retry obtain fresh Query
responses and preserve the original target. The completed old write does not
restore traffic permission: expired activation still fails with code 104.

The same native fixture and public-record reader used for Android drive these
Swift operations. The fixture's historical Android name does not make these
Java/JNI or ART executions. The iOS application consumes the actual local Swift
package and packaged native iOS arm64 slice. USB forwarding transports opaque
protocol/TLS bytes to the owned loopback endpoints; it does not replace signing,
verification or witness decisions. No on-device private keys or journals were
copied back to the host.

Qualification source is `84d2a029f745b915b38ac4b7999f0ccb05343386`. The candidate Cargo archive was
regenerated, compiled and checked against this exact source; all ten dependencies
resolve to their actual extracted archives outside the checkout. The Apple
producer built arm64 macOS, iOS and simulator slices, checked all 157 C exports,
licenses and archive readback, and completed the existing macOS consumer execution
and three consumer builds. The physical application used warnings-as-errors,
an exact native slice/link-map check and the existing offline development signing
profile. SDK implementation, protocol and storage admission did not change.

The first physical cohort completed ten operations, then its post-expiry launch
returned exit 1 before startup admission, with no SDK or observation-file receipt.
That cohort failed and was cleaned. A fresh diagnostic application added UIKit
lifecycle records and structured CoreDevice termination results. Two startup-only
launches, separated by 190 seconds idle and calling no SDK operation, passed.
The next functional cohort completed its fixed/unapplied route in 20 processes,
then its recoverable/applied route failed after ten operations at the same
post-expiry launch boundary. Its structured result confirms exit 1 without a core
dump; no UIKit lifecycle or startup admission appeared. Both failed runs were
cleaned; their source and execution records are retained.

CoreDevice documents that console launch may attach to an existing application.
The original driver did not explicitly require a new process, despite that being
the fixture's contract. The accepted driver records prelaunch process inventory,
uses `--terminate-existing` for its owned test bundle, requires a fresh distinct
PID and structured exit-zero/no-core-dump result, and queries that PID absent
after exit. It does not retry a failed SDK operation or weaken any recovery check.
This enforces the process contract; no existing-process cause for the earlier
exits is asserted. Their cause remains unresolved, and later successful execution
does not retrospectively fix them.

Preparing the diagnostic build also exposed an operator recipe error: a fresh
source directory reused the earlier DerivedData and link-map locations. The old
signed app and link map were overwritten before signing refused an existing
entitlements file. Original source, build/sign/run receipts and recorded hashes
remain; the old signed executable is no longer asserted available. The unsigned
replacement is retained locally. The accepted build uses independent DerivedData,
link-map and signing paths, with absence checks before mutation. SDK source and
private runtime state were not modified by this error.

The initial preparation rejected an older archive whose recovery document no
longer matched current source. Its dependent recipe then refused the missing
preparation receipt. Both failures occurred before installation and are retained;
the strict archive comparison was preserved. Current-source packaging and later
dependent producers ran only after the preceding terminal success.

| Artifact | SHA-256 |
| --- | --- |
| Candidate Cargo archive | `75ef9337d54c8cab7c84e392c76bc1f399449178d71a1e80065494f9e822c714` |
| Apple binary package | `207dae7fbd4c6c42599595cc86309bb425836dfdc0803f12f7be665c21f4fe12` |
| Packaged iOS static library | `7322ac8bdb3749fb8d50bf402f7ba8a28f8abb429a7edb07392750d8dfc9ba43` |
| Signed physical application | `d0d76946d4ce1d6a116e9ff93377ce3de1578ad71c0df0aaa238dce21b45d450` |
| Public capture | `77dcce8247378a60c8fdec643f9ec59c0fc7cfb1ee67623eea951dc447ccaf7c` |

`CAPTURE.zip` contains 2494 public members. All hashes and both recovery
readers passed extraction/readback. A separate verifier checks the exact operation
census for each profile, all 39 startup admissions and structured app exits, container result
hashes and source/driver identities. The owned application was uninstalled and its
absence checked. Private test TLS keys and device/signing identifiers are excluded
or redacted. The local binary package remains in the recorded package producer
output; this checkpoint does not publish it.

These are positive physical pending-write recovery results, beyond the earlier
Apple ABI/owner checks. This cohort does not test an iOS process cut inside Query
or storage, in-flight cancellation, subsequent policy renewal/rekey/fresh traffic,
physical power loss, background/Data Protection behavior or PCS. Earlier Apple
account-root lifecycle evidence retains its own artifact scope. Signed witness
transport here is distinct from a mutual-TLS witness route. The endpoints share
one protocol implementation. Broader binding composition, independent/Linux
interoperability, performance, maintenance and the remaining 0.2.0 gates stay open.
The accepted single Android phone remains sufficient for its recorded acceptance.
CI has not yet executed this checkpoint; no release or Intel Mac slice was added.

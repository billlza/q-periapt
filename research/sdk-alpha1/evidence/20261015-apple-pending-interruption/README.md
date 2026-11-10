# Physical Swift pending-write interruption

The offered iPad Pro 11-inch (M4) running iPadOS 27.0.1
completed four fresh public Swift routes using the actual Apple binary package.
All 90 invocations have distinct process IDs, run-bound startup admissions,
structured termination results and matching public application-container records.
Four deliberate process exits returned 77; the other 86 returned zero. The owned
test application was removed and its absence checked.

| Witness / SDK trust / original write | In-flight cancellation | Process-loss recovery |
| --- | --- | --- |
| Signed TCP / fixed / unapplied | 22 processes | 24 processes, two exits |
| Mutual TLS / recoverable / already applied | 21 processes | 23 processes, two exits |

All routes perform the first three identity, authority and genesis preparation
steps with the signed setup carrier. The TLS routes switch to mutual TLS before
activation and retain that carrier for traffic, cancellation and process loss.

Each route begins with a new device-generated identity, public configuration and
independent registration. Actual traffic to the C reference application retains
one message whose business effect committed but whose delivery result was lost.
The R2 roster intent is retained before the original policy expires on the wall
clock. Exact pending request, metadata, session, message and business effect
identities survive the subsequent interruptions.

For cancellation, the native witness fixture withholds the remainder of a real
Query response. Closing the busy owner returns Busy. Cancelling through the public
Swift owner returns native code 218 with the complete diagnostic
`witness dispatch cancelled; reconcile original command`. Pre-call cancellation
remains code 302. Both cases retain the original recovery intent. Fresh-owner
retries use distinct Query challenges for the same original command, and the
witness's read-only history is unchanged.

For process loss, the application first exits while the Query response is held.
The host checks the exact original binding, the control transcript, transport
closure and independently reaped exit 77. A fresh application process retains the
same pending intent. A second exit occurs after the public confirmation API has
returned but before a successful application result is published. Reopening and
exact confirmation/retry authenticate the same target. This is lost-result
recovery; it does not claim an interruption inside the storage transaction.
All routes still reject activation under the expired policy with code 104.

The test app's USB relay forwards opaque protocol and TLS bytes to the existing
native fixture. Its extra control channel identifies the exact test operation;
it does not grant protocol authority or replace witness decisions. Before the
first process cut, a bounded local drain barrier confirms that the cut-control
byte was forwarded upstream. The native fixture still independently requires
that byte, transport closure and actual process exit. Cut container copies occur
after that exit gate so CoreDevice file-copy latency cannot hold the gate open.
Every deferred copy is mandatory before accepting a route and matches the public
record emitted by the exiting app. Ordinary relay failures remain errors.

Qualification source is `bb543744b03885e271fe74f095417656e1f5188e`. The unchanged SDK package
was produced at `84d2a029f745b915b38ac4b7999f0ccb05343386` and is the same package used by
the [positive Swift recovery checkpoint](../20261015-apple-pending-recovery/README.md).
Preparation verifies package contents, current Swift binding bytes and native
reference executable hashes. The new consumer uses separate build/signing paths,
warnings-as-errors, the exact packaged arm64 iOS slice and a checked link map.
No SDK, protocol or storage implementation was changed for these results.

| Artifact | SHA-256 |
| --- | --- |
| Apple binary package | `207dae7fbd4c6c42599595cc86309bb425836dfdc0803f12f7be665c21f4fe12` |
| Packaged iOS static library | `7322ac8bdb3749fb8d50bf402f7ba8a28f8abb429a7edb07392750d8dfc9ba43` |
| Signed physical application | `b75d41b641d501b346abf71e7cc6113b547e130b793e1572dedfdc78e1529551` |
| Public capture | `d53ccb1707abfcc51a773354c6fed8c97c6e3aabcc1fad3eab74f52898e923c0` |

The capture has 3025 members. Independent extraction checks every
member hash, all four public-record readers, exact per-route operation counts,
90 process identities and all four cut-container readbacks. Private fixture TLS
keys and runtime stores are excluded by explicit public file selection; hardware
and signing identifiers are redacted. No on-device
private keys or journals were exported. The package and signed application remain
local; this checkpoint publishes no release.

The original outer producer returned failure after all four native route tests
and public copies had succeeded. Its final census incorrectly required every
invocation in a TLS route to use TLS, including the three preceding registration
preparation steps. The unchanged fixture initializes those steps as signed and
selects the TLS carrier only afterward. The original failed result, executed
driver and all receipts remain unchanged in the capture. A separate offline
review checks the exact carrier for every phase, all 90 process records and the
complete public recovery results. Controls reject each of 90 individual carrier
substitutions, missing/extra invocations, reused run IDs and changed modes,
profiles or case identities. No failed private runtime was reopened or rerun.
The successful offline review does not rewrite the original producer as passed.

These results add physical Apple in-flight cancellation and process-loss recovery
to the earlier positive confirmation checks. They do not resolve the earlier
startup failures retrospectively. Apple post-recovery policy renewal, rekey and
fresh traffic remain separate work. Power loss, storage-internal crash cuts,
background/Data Protection behavior, PCS, independent protocol implementations,
Linux interoperability and performance qualification retain their own gates.
The existing accepted Android phone remains sufficient for its recorded scope.
No Intel Mac slice or broader release-readiness claim is added.

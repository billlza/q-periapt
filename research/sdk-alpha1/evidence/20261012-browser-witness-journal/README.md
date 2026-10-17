# Asynchronous witness calls and original browser journal recovery

Shared witness-dependent engine operations now use async/await on
`wasm32-unknown-unknown`. Pinned `maybe-async` converts the same bodies to the
existing native synchronous API. Operation helpers retain the original error
cleanup boundaries; converting an async block directly into a native block
could otherwise let `?` bypass the enclosing cleanup.

`AnchorClient` moves its signing owner into an exchange until it verifies a
timely, complete reply. Failure or dropping a polled future closes that owner.
Dropping an unpolled future does not dispatch or change it. Real Chrome page and
Worker tests cover these cases, transport errors, malformed replies and refused
retries. A counterfactual build which restores the signer before suspension
fails the same assertions in both realms. These fault carriers never return
fabricated authenticated success.

The required-journal recovery body also has a private database-admission seam.
Native callers still perform their original private-file admission first. No
public arbitrary-backend constructor or fixture signing-key importer is added.

The isolated browser adapter uses real Fetch, DedicatedWorker OPFS sync access
handles, Web Locks and the original encrypted journal/write-intent code. Each
case has a freshly generated identity and a separate native witness process
with its own durable state. The loopback HTTP harness carries the original
signed request/reply bytes; only the shared verifier grants witness authority.
It records the witness's authenticated stored head after each request.

| Case | Witness revision before recovery | Local image / pending intent | Result |
| --- | --- | --- | --- |
| Normal commit | 2 | Revision 2, no pending intent | Exact retry |
| Disconnect before dispatch | 1 | Revision 1 plus original target | Original advance applied |
| Reply lost after commit | 2 | Revision 1 plus original target | Exact committed advance recovered |
| Deadline after commit | 2 | Revision 1 plus original target | `TimedOut`; original target recovered |
| Explicit cancel after commit | 2 | Revision 1 plus original target | `Interrupted`; original target recovered |
| Worker terminated after commit | 2 | Revision 1 plus original target | Lease released; original target recovered |
| Modified signed reply | 2 | Revision 1 plus original target | `Authentication`; original target recovered |

The controller's witness observations are test evidence, not information inferred
by a failed client. Disconnects still return an unknown outcome. Failed live
journals refuse reuse. Concurrent owner operations during a suspended request
return `Busy`; explicit cancellation aborts Fetch and settles the original call.
The Worker termination case waits for the actual Web Lock to disappear before
reopening. Every recovered exact retry performs zero journal writes and syncs.

All seven snapshots also reopen through the native private-file admission and
the same original witness. For the six pending snapshots, a separate native
redb reader checks that the **5,986-byte encrypted target in the original intent
equals the browser and native committed images byte for byte**. Both recovered
images have removed the pending row. This is cross-target shared-engine
verification, not an independent protocol implementation.

The first archive audit caught a harness custody error: the comparator opened
the original browser snapshots, and redb open/close changed their storage
metadata. Protocol image equality passed, but whole-file capture hashes failed.
That cohort is retained. A second cohort uses new identities and witness stores;
native verification and comparison operate on copies. Both the original pending
files and browser-recovered files still match their captured SHA-256 values
after verification. No protocol assertion or hash check was relaxed.

The fixture uses public wrapping bytes `171` repeated 32 times for freshly
generated device test material. The browser's private test importer calls the
original sealed-owner role, identity and public-component checks. This does not
qualify browser key generation or provisioning. Native witness wrapping keys,
private signing files and witness databases are excluded from the archive.
Trusted fixture pins are provisioned by the harness; this is not a discovery or
registration trust mechanism, or a browser HTTPS/TLS qualification.

The native full suite passes **959 tests** on the preserved first async source
snapshot. Subsequent request-helper changes pass **7 policy-request and
10 credential-request tests**. The archive distinguishes these source snapshots.
Integrated production sources pass native all-feature and WASM Clippy with
`-D warnings`, and the native Rust **1.90.0** all-feature check. The full new
installed-package qualification remains separate work.

[CHECKS.json](CHECKS.json) pins the 644-member [CAPTURE.zip](CAPTURE.zip), SHA-256
`1672936a8cdb0fb8f12ca2437f3cb77472bc86bb5713363936cf60ab22006d60`.
Every archived member was reread. [RESULT.json](RESULT.json) retains browser,
native and witness observations. The owned browser and all eight server/witness
processes are closed. Empty stdout files have a separate exact inventory in
CHECKS; nonempty and failed output is retained.

Public browser installation and signing/wrapping-key owners, operation packaging,
peer transport, whole-profile rollback/eviction recovery and the complete product
lifecycle remain open. This checkpoint does not admit the full browser
Continuity owner or the 0.2.0 release.

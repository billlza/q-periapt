# Browser original-state recovery and loss accounting

The installed WASM package now selects an original account or session for
restricted cleanup without constructing a current runtime. Shared native storage
opening retains the enrollment, installation, archive and journal leases and
checks the original journal/device/policy binding before any pending write can
reconcile. Browser recovery uses its existing IndexedDB storage owner. It exposes
no active session, signing key, provisioning or traffic interface.

The five fresh Chrome scenarios contain 118 Worker invocations:

| Scenario | Observed result |
| --- | --- |
| Local protection after actual credential and policy expiry | A cached previously valid owner refuses sending; two original committed messages are reported as unknown, complete reports are persisted, exact reports survive reopen, and aggregate metadata retires after both sessions are accounted |
| Current required witness, closed local runtime | The same complete committed-account cleanup survives actual Advance/Advanced reply loss during each freeze, acknowledgement and final retirement |
| Current required witness, reserved whole account | Loss after the actual reservation leaves both original members reserved with no peer dispatch; independent member closure is refused; one complete two-member report is frozen, persisted, acknowledged and retired through lost replies |
| Expired witness, no applied cleanup | Historical status/member reads succeed; a fresh freeze is rejected, and reopening cannot advance the retained unapplied intent |
| Expired witness, original freeze already applied | A freeze actually advances before expiry and its reply is lost; after real expiry the exact report is recovered repeatedly, but a new acknowledgement is refused |

The last two rows qualify the authorization boundary; they do **not** mean cleanup
completed without renewed authority. The witness's effective validity intersects
credential, roster and policy validity. After expiry, only historical reads and
exact already-applied confirmation remain possible. New freezes, acknowledgements
and metadata retirement need current independent authority. No validity check,
signed policy or clock was relaxed to obtain these results.

Complete loss snapshots include every original session, reservation, retained
epoch, unknown ciphertext identity, unconsumed delivery and skipped index. Schema-1
JSON preserves u64 values as decimal strings and byte identities as hexadecimal.
The host controller writes the entire report, syncs the file and directory and
reads it back before acknowledging. Reopen preserves report bytes, IDs and host
file identity. These are process/commit tests, not physical power-loss or media
erasure tests. Logical cleanup does not erase retained backups.

Wrong original policy, operation and witness pins are refused; missing required
witnesses do not select local protection. Recovery cannot call ordinary account
operations. Committed messages cannot be relabeled as uncommitted reservations,
and unaccounted members block retirement. Unknown delivery stays distinct from
authenticated consumption. Cleanup sends no application traffic and does not
rewrite the receiver's already-recorded business effect.

Two failed browser attempts are retained. run02 originally expected a new cleanup
write to succeed after witness expiry. Native Rejected(Validity), the store's
Advance/Fence check and existing expiry regressions show that expectation was
wrong. The SDK received an unsigned HTTP failure and correctly reported transport
uncertainty; the controller's observed rejection is not an authenticated client
receipt. run03 reused credential Commit/Applied tags for a generic journal advance,
so no reply-loss fault fired and the strict gate failed. A separate fixture now
recognizes authenticated Advance/Advanced tags 2/2. Neither attempt is counted as
passed, and neither old cohort was reopened.

The first native negative fixture also compared identical deterministic policies;
it now asserts the intended checkpoints differ before testing refusal. A pre-run
py_compile invocation was rejected by the hardened launcher's cache guard. AST
validation replaced that invocation; the guard remains unchanged. Both failures
and their relevant source/receipts are preserved.

Native regression suites passed 14 portable-session, 61 fanout, 3 installation
recovery and 15 session-closure tests. Native/WASM strict Clippy, Rust 1.90 WASM,
installed Node tests, TypeScript strict NodeNext and 53 inventory/package controls
passed. The exact Rust source inventory is 658. The package producer's
browser_runtime: not-run receipt remains unchanged; the Chrome runs are separate
terminal evidence. Package02 corrects the witness documentation; every packaged
file except README and its manifest is byte-identical to package01, including all
JS, WASM and types. The local-expiry run used package01; later scenarios used
package02. CHECKS.json and PACKAGE_RUNTIME_EQUIVALENCE.json inside CAPTURE.zip bind
these facts to the actual archives and sources.

This is one shared implementation on one macOS arm64 host. Composition with
independently renewed witness authority or permanent device/account retirement,
additional local reservation/commit cuts, cancellation/concurrent close and
nonempty inbox/skipped-report workloads remain. Independent implementation/host
interoperability, complete platform lifecycle, PCS, performance, current CI and
final release admission remain separate. Private runtime keys, storage databases
and browser profiles are excluded from the capture; prior accepted physical-device
and protected historical cohorts were not reopened.

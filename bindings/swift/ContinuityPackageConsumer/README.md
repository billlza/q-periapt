# Installed Continuity Swift owner

This unpublished Swift package uses the existing `qpc-owner/1` owner and shared
Rust Continuity engine. It adds no ratchet, KDF, credential parser or private-key
export. It is a language-admission step toward 0.2.0, not a frozen product package
or an addition to ABI 2. The manifest declares a macOS 13 source floor; execution
qualifies only the actual host. Minimum OS, iOS and Linux runtime coverage need
their own results.

`ContinuityOwner.prepare` snapshots bounded original-installation configuration
without opening storage. `finishOpen` activates that same owner synchronously.
Another thread can cancel while it is opening. Failed activation leaves only
cancel/close available. An open never provisions, repairs, replaces trust pins or
downgrades a required witness. Carrier choice is explicit and never falls back.
The directory still follows the native candidate qualification layout; production
provisioning and migration remain separate unfinished interfaces.

`ContinuityDevice.prepare/open` opens one already Active original device. Its
`preparePeer/openPeer` and `preparePeerReopen/reopenPeer` methods return the same
operational `ContinuityOwner` interface for a separately configured peer, with an
explicit `BootstrapRole`. The peer retains the original native parent even when
the public device wrapper leaves scope. Prepared and active peers keep that
ownership until successful close or disposal; each in-flight call separately
retains a snapshot. A closed peer's aliases no longer keep a hidden parent alive.
Peer close preserves a device still owned by its caller or other live peers;
successful explicit device close releases storage and invalidates all children.
Busy preserves the device; cancel, join and explicitly close again after active
work drains. Retained closed aliases do not prevent that
explicit teardown. Ownership points from peers to parents, with no reverse link.
The small parent-reference cell uses a lock only to snapshot or clear a reference;
native work and final parent release run after unlocking. Busy and unknown close
failures retain the link. Confirmed close clears it, while in-flight snapshots
continue to pin the parent through return.

`nextAccountOperation` returns a journal-bound ID to retain before dispatch.
`sendAccountMember` takes an `AccountID`, that original `AccountOperationID`, the
complete `[AccountTarget]`, shared plaintext/AD and a selected member index.
Every target retains its peer, and the wrapper explicitly keeps all targets and
the selected device alive through native return. The native owner checks the exact
parent, current complete roster, session archives and original input; passing a
legacy pairwise owner or a child of another parent grants no account authority.
Each call delivers one member. Remote account delivery is not atomic, and any
failure/cancellation may follow local or remote commit. Reconcile the original ID
and input; do not omit a failed target or replace the operation.

`AccountStatus` distinguishes local reservation/commit, retained abandonment
reports and retired history. `AccountDeliveryOutcome` separately represents
confirmed or prefix-pending consumption, resolution pending, delivery unknown,
history retired and abandoned reservation. A retained result with zero exchanges
does not necessarily mean consumed. Malformed output, a changed selected session,
unknown states or an inconsistent report fail explicitly.

The account qualification CLI uses three original installations and two distinct
recipient devices. Its bootstrap helper observes release of the public device
wrapper while prepared peers remain, races two closes of one peer with exactly
one winner, then verifies in-process lease reopening while closed peer aliases
remain alive and again after they leave scope. It uses actual Swift operations for complete-set refusal, original
message retry after receiver process exit, unary bypass refusal, target reordering
and cancellation of an unselected target during TLS. The common Rust harness
records the client language and uses independently owned receiver processes;
the native protocol engine remains shared. Required-witness account delivery,
own-account fanout, credential lifecycle and
platform-specific execution remain
separate qualifications.

`ContinuityOwner.prepareReopen(path:quality:session:witness:)` copies an explicit
existing `SessionID` into the same pending native owner. `finishOpen` restores
only original Active state with current authority; `reopen` is the synchronous
convenience form. Expired advertisements and old roster snapshots may authenticate
the original identity, but expired credentials/policy, revoked membership,
missing archives/state and closure cannot obtain operational authority. Ordinary
`open` keeps fresh-bootstrap admission. Neither path implicitly switches to the
other, changes its witness profile or creates missing storage.
The owner-test ARC workload covers fresh and restoration preparations. The foreign
restore trace uses the public Swift method, its actual loaded library and current
clock, independently owned Rust TLS receiver processes and application readbacks.
This trace qualifies a local profile. A separate development trace restores the
responder's original session with required signed TCP and mutual-TLS witnesses,
rejects missing/wrong witness pins and bad signatures, cancels partial replies and
stalled TLS handshakes, then reopens the same session. The collector checks original
public records independently. Fresh archive qualification remains required; the
expiry and witnessed-constructor workloads retain their separate scopes.

Swift references alias one immutable native handle. Native synchronization and
monotonic handle identities govern races. Every call retains the wrapper until
return. `close` throws on Busy and preserves the handle; `cancel` is one-way.
Cancel, join the active call, close, then reopen the **same original installation**
to reconcile unknown work. ARC releases an idle owner; unexpected destructor
failure is logged by status without private paths. Applications use explicit
throwing close when they need its result. There is no automatic background task
or implicit retry in the library.

Initiation, session and message IDs have distinct Swift types. The caller retains
the original initiation/message ID across retries. `committed`, `acknowledged`,
`resolutionPending`, `deliveryUnknown` and `reservationAbandoned` remain distinct;
successful transport with a pending consumption prefix is not consumption.
Native errors preserve code, UTF-8 diagnostic and truncation. Malformed diagnostics
or outputs fail explicitly. Caller-provided plaintext remains in caller-owned
Swift memory; this wrapper promises no erasure of those copies.

The current surface covers operational client establishment, exact-message status
and sending, rekey, listener/receive callbacks, restricted cleanup, and lifecycle
cancellation/close. The collector also executes explicitly witnessed constructor,
client/server and cleanup traces. Other platforms and integration
into the published Swift SDK remain unfinished. These are required for the full
0.2.0 goal, not silently excluded from it.

Run the existing package collector with `--with-c-consumer --with-swift-consumer`
on macOS. It first qualifies the actual installed native engine, then creates
profile-specific ZIP packages containing this Swift source, the exact C header,
library and licenses. Fresh installations outside the checkout build and run
Swift Debug/Release with warnings treated as errors. The shared protocol harness
executes both Swift client and Swift server against separate native Rust peer processes, retaining
actual receiver bytes, committed-reply loss, original-ID reconciliation, rekey,
pre-cancel refusal, concurrent Busy/close/cancel, reopen and durable SDK revocation.
The report explicitly identifies Swift; historical C command/test labels simply
identify the reused ABI contract harness. No C CLI implements Swift operations.

Each Swift client checks the actually loaded library path before opening an owner.
The collector verifies its installed bytes and executable hash before and after
execution, preserves raw build/linker output, and exports selected public data for
independent replay. Private fixture stores and keys are never included in a ZIP
or public evidence closure. Correctness timings are not performance guarantees.

The receive callback receives owned Swift copies only after authentication and
native durable inbox commit. It returns normally only after the host transaction
has persisted the application effect and session/message deduplication together.
An arbitrary thrown Swift error returns nonzero across the C boundary and is
retained alongside the native failure. `ApplicationCommitRefusal` can preserve an
explicit nonzero application status; zero is rejected. Unknown outcomes remain
unconsumed and require original-ID reconciliation. A duplicate of already consumed
traffic does not invoke the callback. A successful callback followed by a transport
failure is still an unknown peer-delivery outcome, not permission for a new send.
The listener shares the owner's cancellation and deadline; callbacks are
synchronous and cooperative. Reentrant close returns Busy and retains the owner.

The Swift test application persists effect+deduplication bytes atomically under
the exact message ID with file and directory sync, checks existing bytes on replay,
and refuses conflicts, symlinks and nonregular effects. The server trace includes
failure before effect, unknown result after effect, actual process exit after
effect, exact retries, consumed duplicates, rekey and cancelled listener release.
Its intervening recovery consumption still uses the native public API and is not
represented as a Swift restricted-recovery interface. A separate installed Swift
cleanup trace exercises the recovery surface described below.

`ContinuityRecoveryOwner` shares the native owner registry, cancellation and ARC
lifetime implementation but has no operational methods, raw handle or conversion
to `ContinuityOwner`. Opening it never needs live SDK permission. Session IDs from
discovery are hints; selecting one or its retained archive authenticates original
durable state. Native selection failure closes discovery; close and reopen the
same installation to reconcile. The explicit witness choice cannot fall back.

`select(account:)` instead selects the exact original `AccountOperationID` and
consumes discovery. Native admission authenticates all original members before
recovery writes, retaining the installation, key-vault and journal owners. It
accepts no recipient subset. Session and account selection are mutually exclusive;
an account loss cannot be discharged by closing its sessions independently.
`beginAccountCleanup()` freezes the complete account and returns the operation ID,
report ID and member count. `accountMember`, `accountReservation`, `accountEpoch`,
`accountUnconfirmed`, `accountDelivery` and `accountSkippedPosition` expose all
fields of the immutable snapshot, including original device/context/session
identities, generations and full-width counters. Every read may fail; a partial
traversal is never a complete report.

Persist the complete report and original IDs in a deduplicated host transaction
before `acknowledgeAccount(report:)`. Use `accountCleanupStatus()` to reconcile an
unknown result against the original operation and report. `retireAccount()` is
admitted only after exact acknowledgement; it retires batch metadata while
retaining session/bootstrap tombstones and consumed capacity. It cannot reactivate
keys. Cancellation blocks mutation but leaves a retained immutable snapshot
readable until close; a required-witness status read still needs that witness.

The installed collector includes a separate Swift whole-account trace. It observes
actual calibrated pre-sync process interruptions until a Reserved batch exists,
revokes operational SDK permission, and freezes, traverses, acknowledges and
retires via Swift. The host durably retains the full report before acknowledgement.
Independent native and Python readbacks check both original members, reservations,
older unknown ciphertext commitments, unconsumed deliveries and skipped positions.
It also checks absent/committed dispositions, invalid indices, wrong-report and
cancellation refusals, same-ID reopen and terminal tombstones. Reports explicitly
identify Swift and retain the original shared harness file format. This is a
same-host local-profile process-interruption test, not power-loss, required-witness
or own-account aggregate-cleanup qualification. A separate required-witness path
uses the same C/Swift/Kotlin report contract, as described below. Product SDK
integration, Android and durable WASM aggregate cleanup remain separate work.

The required-witness account trace withholds real committed witness responses at
reservation, freeze, acknowledgement and retirement. Swift preserves each unknown
outcome, reopens the original operation, and reconciles the original report before
continuing. The first reopen after an unknown retirement may return a selected
owner with `.retired` status after resolving its pending write; the following reopen
refuses with Retired. That successful selected owner grants no operational authority.
Missing/wrong pins, a corrupted response signature and an unavailable witness after
retirement are refused. Native and independent public readbacks preserve the whole
report and all four original witness command IDs with fresh challenges. The explicit
signed-TCP profile has 67 public files per configuration; metadata confidentiality,
own-account cleanup and physical power loss require separate qualification.

`begin` permanently freezes the session and returns every scalar/count of its
immutable loss snapshot. Read every reservation, epoch, unconfirmed ciphertext
commitment, unconsumed delivery and skipped position using the typed getters.
Any failed read leaves an incomplete report, not an empty list. Persist the full
report and its original ID in one host transaction before `acknowledge`. Native
status distinguishes open, pending and closed; unknown commit requires original-ID
status reconciliation. Retain the authenticated archive before retiring the index
row. Restoring that index restores metadata only, never operational keys.

The cleanup trace revokes SDK operations, reads a two-epoch history (including
unconfirmed outgoing ciphertext, old/new unconsumed deliveries, a skipped position
and pending rekey/resolution), exits after freezing and after acknowledgement,
reopens and checks the unchanged durable report, then retires/restores metadata.
It also checks cancellation, missing IDs, malformed/tampered archives and wrong
report acknowledgement. A raw-ABI negative control inside the test executable
checks native owner-kind denial in both directions; all actual cleanup operations
use the Swift wrapper. That history contains zero uncommitted reservations; its
report retains that explicit limitation.

The separate installed Swift sync-interruption matrix uses the same native
fixture and separately hashed probe as C. It calibrates real journal syncs in the
actual Swift process, interrupts every before/after boundary, and requires Absent,
Reserved and Committed outcomes after reopening. A real post-sync reservation
must retain its original message ID and 29-byte plaintext/13-byte associated-data
lengths after SDK revocation. Positive reservations also precede every calibrated
cleanup-begin and acknowledgement cut. Open/Pending and Pending/Closed outcomes
must reconcile the same complete host report, with exact acknowledgement and
metadata-only restoration. Send, status and recovery completion markers follow
a successful owner close; an interrupted close cannot publish those markers.

The collector records Swift as the executing language, binds each native helper,
probe, client and installed-library hash, and keeps the loaded-library check in
every Swift process. It exports selected public loss/closure records and replays
them without private journals. Raw command logs and real sync receipts remain
separate retained evidence. The probe is injected only into the selected test
processes and is never linked into the SDK. This covers process interruption in
the local profile, not power loss, injected EIO, witnessed cleanup faults or
concurrent updates. Historical sync reports use their original pinned verifier.

The installed witness traces select `.signedTCP` or `.mutualTLS` explicitly for
both operational and cleanup owners. They retain the same native signing pins,
subject bindings and exact operation IDs, including after SDK revocation. There
is no local-profile fallback. Missing/wrong pins, credentials, TLS names or witness
subjects must fail. TCP authenticates public metadata but does not encrypt it;
the explicit TLS carrier retains the native mutual TLS 1.3 and hybrid group
contract. The witness engine is still shared with the C qualification, not an
independent deployed witness implementation.

The constructor trace exercises all three carrier choices, both owner kinds,
pre-cancelled activation, configuration copied at preparation, Busy-preserving
close during activation, a cancelled partial signed reply and a stalled TLS
handshake. The Swift executable joins its own workers even when a test barrier
fails. Native witness failure remains status 218 when its outcome is unavailable;
it is never relabeled as successful activation or known absence. The signed TCP
trace also cancels after witness commitment, then reopens and reconciles the
original ID, and repeats this discipline for an unknown cleanup freeze. The TLS
trace repeats real messaging and revoked cleanup using the original authority.
Observed cancellation timing is a fixture gate, not an OS-preemption guarantee.

Constructor and native-witness public reports use schema version 2 with an
explicit C/Swift language field. Their verifiers require the selected language,
complete raw command/data readbacks and original signed-transcript accounting.
Earlier reports retain their original source/verifier version; a historical C
success cannot be relabeled as Swift evidence.

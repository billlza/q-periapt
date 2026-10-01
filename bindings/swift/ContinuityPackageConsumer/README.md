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

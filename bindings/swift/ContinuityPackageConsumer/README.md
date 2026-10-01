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
cancellation/close. Witness runtime traces, other platforms and integration
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
use the Swift wrapper. Positive reservation accounting is not exercised by that
history and is explicitly reported as unqualified. These traces use the local
profile; witnessed recovery execution remains open.

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
and sending, rekey, and lifecycle cancellation/close. Server callbacks, restricted
cleanup-owner methods, witness runtime traces, other platforms and integration
into the published Swift SDK remain unfinished. These are required for the full
0.2.0 goal, not silently excluded from it.

Run the existing package collector with `--with-c-consumer --with-swift-consumer`
on macOS. It first qualifies the actual installed native engine, then creates
profile-specific ZIP packages containing this Swift source, the exact C header,
library and licenses. Fresh installations outside the checkout build and run
Swift Debug/Release with warnings treated as errors. The shared protocol harness
executes a Swift client against separate native Rust peer processes, retaining
actual receiver bytes, committed-reply loss, original-ID reconciliation, rekey,
pre-cancel refusal, concurrent Busy/close/cancel, reopen and durable SDK revocation.
The report explicitly identifies Swift; historical C command/test labels simply
identify the reused ABI contract harness. No C CLI implements Swift operations.

Each Swift client checks the actually loaded library path before opening an owner.
The collector verifies its installed bytes and executable hash before and after
execution, preserves raw build/linker output, and exports selected public data for
independent replay. Private fixture stores and keys are never included in a ZIP
or public evidence closure. Correctness timings are not performance guarantees.

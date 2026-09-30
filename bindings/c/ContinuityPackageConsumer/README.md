# Installed Continuity C owner candidate

This is an unpublished `qpc-owner/1` consumer of the same Rust Continuity engine,
not an addition to product ABI 2 or a frozen C API. Its header is
[`qpc_owner.h`](qpc_owner.h). The collector builds it outside the checkout from a
Cargo-produced candidate archive and the same nine pinned SDK archives used by
the native Rust consumer. It must execute the C program and independently read
both peers' application records before reporting completion.

The library holds original `DeviceService`, signing, verified context, SDK policy
and TLS-key owners. It delegates every bootstrap/message/rekey transition to that
shared engine. It exposes no raw private-key/root getter and implements no second
ratchet, KDF or state machine. Independently retained account, device, policy and
directory pins remain separate from untrusted public bundle bytes.

## Scope and original configuration

The C caller opens an already provisioned installation on macOS/Linux. It does
not initialize a new lineage. Ordinary constructors require the original local
profile; required-witness activation returns the native refusal. Explicit
`qpc_owner_v1_open_witness` and `qpc_recovery_v1_open_witness` accept a numeric
socket address and a 1..10000-ms per-exchange bound. They use independently retained
`witness-id` and `witness-public` files and the original encrypted device signer;
incoming replies never select the witness. Local/required mismatch is an error.
Missing pins, wrong identity, invalid signatures, unavailable transport and stale
witness state cannot enroll, reset or downgrade an installation. This adapter
reuses the native signed TCP witness protocol; it authenticates messages but does
not encrypt public metadata. Witness TLS/service deployment, other language
surfaces and product dependency/ABI admission remain unfinished.

The consumer configuration is the same private fixture layout used by the
archive's public Rust workload: original installation/journal/archive/SDK policy
databases, wrapping and signing files, independently retained policy/account/root/
roster/device-generation/directory pins, canonical bootstrap bundle and local TLS
credentials with an exact peer certificate/name. Public policies are actually
verified when opening. Incoming bundle contents never supply the trust pins or
choose the caller's requested prekey mode. This directory layout is qualification
input, not a frozen product provisioning or migration API.

Missing, corrupt, wrong-role, busy, revoked or expired state is an error. Opening
never provisions, repairs, rewinds or recreates files. An error cannot be treated
as a fresh empty installation. Fixing trusted configuration does not refund any
original operation ID or consumed key.

## Call and lifetime contract

Each loaded library has an explicit registry of up to 64 pending/active owners and
a 64-call admission budget taken before foreign input copies. Handles are
monotonic, process-local references; they never authorize hostile code in the same
address space. An operation obtains exclusive access without blocking another
caller. A conflicting operation or close returns `QPC_BUSY`. Close and cancellation
are exempt from call capacity, so a full budget cannot prevent draining it.

Cancellation is one-way for that owner. Cancel, join the active invocation, close,
then reopen the same original installation to reconcile retained work. A successful
close releases its owned state/leases and invalidates the handle. It neither rolls
back a commit nor acknowledges application consumption/loss accounting. No caller
pointer is retained past the call; inputs must remain valid and immutable while
the call runs, and outputs/diagnostics must be nonoverlapping, aligned and exclusive.

Each invocation returns its own caller-owned, bounded UTF-8 error record, including
an explicit truncation flag. There is no shared last-error buffer. SDK policy
denial, host-store uncertainty/activation failure, durable outcomes and transport
cancellation remain distinct; nested local causes are retained for diagnosis.
An unknown non-exhaustive upstream failure remains an error. No status code is a
universal retryability bit. Outputs other than the diagnostic record are meaningful
only when the return code is zero.

The client retains one original initiation ID or journal-issued message ID across
retries. `Committed`, peer `Acknowledged`, `ResolutionPending`, `DeliveryUnknown`
and `ReservationAbandoned` remain distinct. A successful TLS exchange with a
consumption prefix that does not yet include the ID returns `PrefixPending`, not
successful application consumption. Status queries grant no sending authority.

Client invocations retain the existing finite eight-attempt, 20-second total and
one-second connect bounds. Each owner can bind one explicit listener; repeated
listen is an error and close releases it. Server calls wait up to 20 seconds for
accept, then run the shared carrier's separate 20-second/eight-exchange budget.
Accept cancellation polls every 25 milliseconds subject to OS scheduling.
Filesystem and application callbacks remain synchronous/cooperative; cancellation
does not preempt an arbitrary kernel call, foreign callback or undo a commit.
Witness dispatch checks the same owner cancellation signal before and after each
native exchange. An already running socket call uses that exchange's original
deadline. This per-exchange bound is not a global constructor or invocation bound;
the native journal can require several witness admissions. A completed witness
mutation followed by cancellation remains an unknown outcome requiring exact
reconciliation. Native witness failures retain their typed diagnostics.
AD is visible to the TLS endpoint and must not be treated as message-encrypted
private content. This boundary inherits the candidate's trusted-host and logical-
erasure limits; C in-process memory validity still depends on the caller contract.

## Application consumption

`qpc_owner_v1_serve` invokes the caller's synchronous callback only after the shared
engine authenticates and durably commits an inbox delivery. Session, message and
plaintext pointers are borrowed for that callback only; the context belongs to
the caller and remains live until serve returns. The callback must not unwind or
longjmp. Reentrant operations/close return Busy; cancellation remains available
with a separate diagnostic record.

Zero means the application effect and session/message deduplication record are
durable together. Nonzero, including an unknown external commit, returns
`QPC_APPLICATION` with the original callback status in diagnostic text. The inbox
remains unconsumed and a later retry can invoke the same callback/ID again. Hosts
must reconcile rather than repeat an external side effect blindly. A previously
consumed message instead returns `duplicate=1` without calling the application.
The native sender refuses to regenerate already acknowledged/retired ciphertext.
`qpc_owner_v1_serve_rekey` delegates the caller-selected session to the native
control endpoint; it does not mix application and control protocol identifiers.

## Cleanup after operational revocation

The seventeen `qpc_recovery_v1_*` functions share the handle registry, cancellation,
close and call budgets. Operational and recovery handles are distinct owner kinds;
using one for the other's operations returns `QPC_OWNER_KIND`. Recovery does not
create sending, receiving, rekeying or provisioning authority. Required-witness
state still requires the original native witness admission, including closed
session selection and catalogue restoration. Its explicit recovery constructor
loads the original device signer only for witness requests, without activating
SDK operational policy or TLS owners. The ordinary constructor returns
`AnchorRequired` and cannot downgrade that state.

Open the original installation, enumerate its authenticated catalogue hints, then
select one session or supply its original 362-byte QPCSCA01 archive. Selection
consumes the discovery owner. A failed native selection leaves it closed; callers
must close the handle and reopen the original installation. Malformed foreign
input rejected before selection does not consume discovery. Archive restore only
restores catalogue metadata; it never recreates keys or operational permissions.

`begin` permanently freezes the selected session and returns an immutable report
header. Read every reservation and epoch, including all unknown sends with their
original ciphertext commitments, unconsumed delivery IDs and lengths, skipped
positions, pending rekey and old-epoch resolution state. Optional counters have
explicit presence flags. No private key or delivery plaintext is exported.
The host must durably record the entire report with its exact report ID before
calling `acknowledge`; recording only the ID loses required loss accounting.
After an uncertain result, reopen the original installation and reconcile the
native status and the durable host record. A matching acknowledgement is
idempotent. Catalogue retirement requires the same closed report and does not
erase the journal or permit session-ID reuse.

Cancellation prevents further cleanup mutations. Cached report/metadata queries
remain available, but current witnessed status requires a fresh exchange and can
fail after cancellation. Close/reopen original state to reconcile the result.
Closing releases ownership, never refunds a transition
or acknowledges a report. The C fixture's `QPC-C-LOSS/1` text is only its explicit
host accounting format, not a new network or cryptographic protocol identifier.

## Qualification path

The required-witness trace provisions and explicitly enrolls both original
installations with a separately owned native witness store. Actual C client and
server processes use its real socket for bootstrap, application delivery, rekey
and cleanup. Wrong witness pins and a corrupted signed reply refuse admission.
The witness deliberately drops one already committed send advance and one already
committed cleanup advance. Reopening must retry the same command with a fresh
challenge and obtain `AlreadyAppliedExact`, without another logical advance.
SDK revocation blocks operational open; witnessed cleanup remains available.
Cancellation prevents freezing, and the reopened native journal confirms Open.
Closed archives still refuse admission without the original reachable witness.

The public transcript verifier checks every request/reply envelope length,
authority/subject, command and attempt commitment, challenge uniqueness and
monotonic head transition. It independently recomputes the unknown ciphertext
commitment and compares every loss-report row and the actual application record.
It does not independently verify signatures: the actual native witness and C
client engine perform those checks. The earlier OpenSSL vector oracle remains
a separate finite validation. This trace does not qualify witness TLS, independent
implementation, external service deployment, witness-store rollback resistance
or cancellation during a held witness socket.

Run the existing installed package collector with `--with-c-consumer`:

```sh
sh artifact/python-run.sh artifact/continuity_package.py \
  --report /absolute/SDK-cohort/RUST_SDK_PACKAGE.json \
  --report-sha256 <verified-report-sha256> \
  --toolchain-root /absolute/rust-1.98.1-host-toolchain \
  --output target/continuity-installed-rust-c \
  --with-c-consumer
```

It first executes the original archive-shipped Rust trace. The C phase then builds
both Debug/Release libraries and native C executables, checks the exact 29
exports and installed sibling-library lookup, and runs the shared archive's Rust
peer fixture. C controls the actual owner open/close, TLS bootstrap, message IDs,
delivery and rekey calls. The client trace covers:

- wrong original local-role metadata and failed-constructor capacity recovery;
- receiver exit after application fsync before ACK, followed by same-ID recovery;
- target-1 network rekey and actual post-rekey application delivery;
- cancellation before a reservation, and cancellation after actual TLS bytes reach
  a held socket, with concurrent close returning Busy;
- original-installation reopen, retained Committed status, exact resend/consumption
  and rejection after a durably signed SDK policy revocation.

The reverse trace pairs a native Rust client with a real C listener/callback. It
covers failure before application output, durable output followed by an unknown
callback result, and process exit after output fsync. Original-ID retries compare
the complete application record and create no replacement effect. A separate
duplicate case opens the original receiver through the public native recovery
consumer, checks the durable C output and calls `consume_message` before the sender
has received any ACK. The C receiver then accepts the retained original ciphertext
without invoking its callback. No journal file is edited or rewound to prepare
this case. The trace also checks reentrant Busy close, cancelled listener release,
refusal to resend acknowledged ciphertext, and a real network rekey followed by
application delivery. This qualifies that explicit native consumption transition;
cleanup accounting is exercised separately below.

The cleanup trace uses public native APIs to retain messages across two epochs,
an unknown committed send, three unconsumed deliveries, a skipped receive position,
a pending old-epoch resolution and an unconfirmed target-2 rekey. It then revokes
the SDK policy and requires operational admission to fail while the C cleanup
owner can report the original state. Real C process exits after full-report fsync
and after acknowledgement force restart reconciliation. Independent verification
checks every report row, recomputes the ciphertext commitment from retained public
wire bytes, and compares the C-exported archive with the original native archive.
Missing sessions, altered archives, wrong owner kinds, pre-freeze cancellation,
wrong acknowledgement, repeat retirement and metadata-only restoration are checked.
This trace has zero uncommitted reservations. The separate system-sync fault
matrix below prepares real positive reservations without changing journal bytes.

The fault matrix uses a separately compiled and hashed test-process probe, never
linked into the SDK library. It first checks that the probe distinguishes the
selected inode from an unrelated control file and can stop before/after both
real sync operations. It then calibrates the actual owner-open/send/close journal
syncs and interrupts a fresh process before and after every observed boundary.
Each case establishes a fresh original session through the real C/Rust bootstrap.
After restart, C status and a native public query must agree on Absent, Reserved
or Committed. A real post-sync Reserved case is mandatory, not a fabricated image.
The host signs and durably applies SDK revocation before C cleanup. Complete report
readback preserves the original ID and all reserved input lengths, or independently
checks the committed ciphertext digest. Exact report acknowledgement, retirement,
archive restoration and native closed-state readback complete every case.

Fresh retained reservations also precede every calibrated cleanup-begin and
acknowledgement cut. Recovery must expose both Open/Pending and Pending/Closed
outcomes, respectively, and preserve the same complete host report across restart.
No new report, empty default or revived operation replaces an unknown commit.
The collector rejects missing or repeated cut positions and all unexecuted phases.
The probe recognizes only typed supported Darwin fcntl calls, forwarding their
actual argument types; an unfamiliar operation stops qualification explicitly.
On Linux it wraps the real fsync/fdatasync calls. Real sync failure also stops
this process-cut profile rather than being classified as a successful injected cut.
This is process interruption with the OS/filesystem still running. It does not
qualify power loss, injected EIO, required-witness recovery, concurrent updates
or every archive-index commit through C.

The call-budget unit is also executed in each profile, including drain availability
at capacity. Each C trace selects one integration test; the other two traces and two
included native fixture tests are already executed through the original Rust
collector/C phase, and each peer selects the correct nonempty helper test name.
No test is replaced by a receipt flag. The collector separately checks command logs,
application bytes, distinct epoch IDs, Cargo origins/lock, source/executable hashes
and absence of runtime loader overrides in the normal connection traces.

The C application and library must load from their private installed directory.
On macOS the library uses an explicit `@rpath` install name and the executable uses
`@loader_path`; on Linux it uses the fixed soname with `$ORIGIN`. A successful start
that still loads the build-tree library is rejected as installation evidence.
Only selected fault children add the separately hashed probe through
`DYLD_INSERT_LIBRARIES` or `LD_PRELOAD`. The probe does not replace SDK symbols or
change the installed library; those binaries are rehashed after the fault matrix.
Uninstrumented installation and connection checks remain independently required.

Private test runtime directories contain wrapping/signing keys and journal images;
do not publish them. Retain the collector's public JSON, command logs, hashes and
dependency/loader records. Results qualify only the executed source/platform and
these finite local-profile client/server/cleanup scenarios. They are not a release, independent
implementation, cross-host connection, production C distribution or security proof.

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

The additive device-parent path uses `qpc_owner_v1_prepare_open` with kind 3 and
quality 0, followed by `finish_open`. It requires an already Active installation;
it cannot provision or finish a Creating intent. The protected local configuration
supplies `local-account`, `local-root`, `local-roster-version`,
`local-roster-digest`, `local-device`, `local-generation`, `local-certificate` and
`local-roster`, alongside the original family/policy/SDK store, wrapping/signing
owners and local TLS credentials. Local credential/roster validity and the exact
controlled signer are checked independently of any peer bundle. This constructor
requires a current local identity snapshot; it is not credential renewal.

An independent installation setup owner now exposes the native Creating/Active
boundary. `qpc_setup_v1_prepare_create` and `prepare_resume` copy the same bounded
original configuration path and device options (`kind=3`, `quality=0`), then
`qpc_owner_v1_finish_open` executes the explicitly selected action. Creation
commits a new intent before child storage; resume opens only the original intent.
Neither operation generates wrapping/signing keys, issues credentials or installs
account trust. Those original enrollment inputs must already be independently
prepared. An open error never selects creation.

`qpc_setup_v1_status` returns the durable phase and original journal identity.
`prepare_storage` admits only Creating, either creates genuinely missing initial
children or verifies their exact original genesis, and returns no service. A
local-only result has explicitly zero subject/digest fields. Required protection
returns the original public witness subject and initial image digest for separate
authorized enrollment; it supplies neither a signed witness receipt nor permission
to enroll. Repeating successful preparation retains the same identity and bytes.

`qpc_setup_v1_activate` consumes setup and converts that same handle to a device
parent only after native activation. Failure releases partial owners and may
leave Active durable; close and resume the original configuration to reconcile.
An Active setup owner can reopen existing children, but cannot prepare replacements.
The ordinary device constructor still refuses Creating. The setup owner shares
the existing owner/call quota, cancellation, exclusive invocation and deadline
machinery, with no detached task or alternate state engine.

The mandatory C setup traces cover local create/prepare/repeat/activate/reopen and
separately enrolled required-witness setup. Bad signatures and missing witnesses
are refused. A held reply checks Busy close/concurrent status, cancellation, lease
release and original Creating readback before a fresh activation. Signed TCP and
mutual TLS both reopen the original Active installation. Public replay retains
20 local or 36 witness records, 14 signed queries with one interrupted reply and
zero advances, and five TLS admissions without plaintext fallback. These finite
same-host development results do not complete key enrollment, credential lifecycle,
activation-commit interruption, power-loss or fresh full-archive qualification.
Swift/Kotlin setup owners remain to be integrated.

`qpc_peer_v1_prepare` and `qpc_peer_v1_prepare_reopen` retain that device control
owner and copy a separate trusted peer-configuration path, explicit quality and
local role. Restoration additionally copies the original session ID. The peer
directory supplies independently retained initiator/responder pins, directory
expectation, public bootstrap bundle and exact remote TLS pin/name. It supplies no
replacement local private key, policy runtime or witness. `finish_open` verifies
the context against the original service and validates TLS configuration before
publishing a child. Ordinary operations reuse the native engine through a
borrowed service/peer view. Existing pairwise constructors remain available.

Parents, prepared children and live children share the 64-owner limit. Operations
under one device serialize and conflicting calls return BUSY. Closing an idle
sibling does not require the parent's network lock. Parent cancellation fences
future child calls and signals the currently borrowed child's token; a child's
own token is independent. After an active call drains, parent close releases its
actual stores even while idle children remain. Those children return CLOSED and
must be closed to reclaim their own slots/listeners. Native journal failures can
still require original-service restart; separate cancellation signals do not
bypass uncertain-commit or closed-journal admission.

The C consumer's `--device-parent LOCAL_PATH ROLE` selector exercises these entry
points with a separate peer path. Its device workload covers both roles, wrong
local identity and a different authentic signer, shared capacity, caller-input
copies, idle-sibling disposal during an active call, parent cancellation, storage
lease release, real TLS bootstrap and exact delivery recovery after receiver exit.
A second workload covers required signed TCP and mutual TLS witnesses. These
checks use multiple child handles for one peer context at each endpoint.

The additive `qpc_device_v1_next_account`, `qpc_device_v1_account_status` and
`qpc_device_v1_send_account_member` expose the original native account transaction.
Retain the next journal ID before sending. Every call supplies the same account,
complete target set, plaintext and associated data, and selects one member for
delivery. Each target is a distinct live peer child plus its established session;
all children must belong to the exact same parent. The adapter locks their entries
nonblockingly in handle order and retains their contexts and parent until native
return. Native `FanoutInput` and `send_account_member` enforce the current signed
roster and complete input before reservation and each network attempt. There is no
loop of ordinary unary sends, and the API makes no atomic remote-delivery promise.

Any target's cancellation signals the aggregate invocation through a temporary
call token. It leaves the parent and other children's permanent tokens unchanged.
All selected peers and the parent are BUSY to close; an idle child outside the set
can close. Cancellation may follow durable local or remote commit. Retry the
original account operation after reconciling/reopening the original owners; never
replace its ID or omit a failed recipient. Aggregate status describes local
reservation/commit/accounting. Per-member outcomes distinguish confirmed or
prefix-pending consumption, resolution pending, delivery unknown, history retired
and reservation abandoned. Zero exchanges means a retained outcome, not necessarily
successful consumption.

The account workload uses three independent installations and two distinct devices
in one recipient account. It exercises incomplete/duplicate/cancelled/closed/wrong-
parent refusal, receiver exit after application commit, original message retry,
unary replay refusal, reordered retained targets and cancellation of an unselected
member during TLS. The separate required-TLS-witness delivery trace below now
covers original-message recovery and both recipients in separate own-account and
peer-account layouts. Broader delivery faults, provisioning, authority lifecycle
and Android/WASM retain separate gates.

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
not encrypt public metadata. The additive `qpc_owner_v1_open_witness_tls` and
`qpc_recovery_v1_open_witness_tls` constructors explicitly select the native
`anchor-tls` carrier, using protected `witness-tls-cert`, `witness-tls-key`,
`witness-tls-peer` and `witness-tls-name` files (see the header for exact bounds).
The CLI selects it only with `--witness-tls address`. It never falls back to TCP.
The witness's separately configured exact TLS leaf-to-enrolled-subject table
rejects cross-device credential use before durable handling. Original witness
signing pins and signatures are still mandatory. Classical TLS certificate
authentication is not PQ identity authentication. The native TLS installed-package
path has Debug/Release qualification on Rust 1.98.1 and 1.90 at source `1c1d7c80`.
Swift/Kotlin installed owners now reuse the explicit TLS carrier. Independent
service deployment, Android/WASM and product dependency/ABI admission remain unfinished.

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

For cancellation during construction, `qpc_owner_v1_prepare_open` copies the bounded
path and explicit owner/carrier selection without installation I/O, then returns a
pending handle in that same registry. `qpc_owner_v1_finish_open` runs activation on
the caller's thread; another thread can cancel through the known handle. There is
no detached constructor task. Pending handles grant no business-operation authority.
Once initialization is admitted, its request is consumed exactly once. Failure,
including late cancellation or expiration, drops partial owners and leaves only
cancel/close available. Close it and prepare the original installation again to
reconcile durable outcomes. Busy/call-capacity admission failures leave the request
pending. Successful initialization converts the same handle to the selected owner;
calling finish again returns OwnerKind without replacing it. The synchronous
constructors remain available for callers that do not need an early handle.

Existing message sessions have an explicit restoration entry:
`qpc_owner_v1_prepare_reopen(path, length, options, session, handle, error)`.
Options retain their existing layout, with `kind=1` and independently selected
quality/carrier. The nonzero 32-byte session is copied during preparation.
`finish_open` then invokes the native historical-snapshot request and Active
installation admission. It requires the exact original session/context/local role,
cleanup archive, current roster and credential/policy/runtime authority, signed
budget and required witness. Missing or unfinished state is never recreated.
Ordinary constructors retain fresh advertisement checks and never auto-fallback.
Cancellation, deadlines, owner/call quotas and failed-activation cleanup are the
same existing boundaries; no clock override or raw context/key getter is added.

The installed restore trace establishes a fixture at a historical protocol time,
then runs the foreign client at its actual current clock after advertisement expiry.
It checks fresh-open and wrong-session refusal, pre-cancelled absence, an unknown
external application commit, exact-ID retry and two application-file readbacks.
The collector independently checks identities, time markers, command logs and
application bytes, and exports only these public records. This trace covers the
local profile. A separate responder-session trace performs real foreign-to-foreign
TLS bootstrap under a required witness, refuses missing/wrong witness pins and a
corrupted reply signature, and exercises restored-owner preparation through signed
TCP and mutual TLS. Partial query replies and stalled TLS handshakes are cancelled;
the original session must reopen afterward. Independent public readback binds the
session, command results, original witness transcript and socket observations.
All three language development runs pass both traces; fresh archive qualification
remains required. Advertisement expiry and witnessed constructor cancellation are
separate workloads. This is not product provisioning or witness-store rollback
qualification.

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

Ordinary calls capture one absolute 20-second deadline before copying foreign
inputs. Constructors and operational/recovery owners pass that same deadline
through witness admissions, listener accept, application TLS and rekey TLS.
Native `RunLimits.outer_deadline` and the owner-local witness scope can only
shorten phase budgets. Native clients retain the eight-exchange and one-second
connect bounds. Each owner can bind one explicit listener; repeated listen is an
error and close releases it. Accept and serving share the invocation deadline.
Accept cancellation polls every 25 milliseconds subject to OS scheduling.
Filesystem, cryptographic work and application callbacks remain synchronous and
cooperative. Checks at their boundaries cannot preempt an arbitrary kernel call
or foreign callback, guarantee OS scheduling, or undo a commit.
Witness dispatch shares the native one-way cancellation signal with TLS dispatch.
Connected reads/writes use at most 25-ms socket timeouts, subject to OS scheduling,
and check cancellation between calls, including partial frames. A pending connect
retains one nonblocking socket and waits for readiness in at most 25-ms intervals
under the exchange's original deadline. Readiness wakes immediately; cancellation
does not spawn a replacement connection or leave a background worker behind.
Polling never refreshes that deadline.
Every witness exchange also retains the enclosing call's deadline; several
journal admissions cannot refresh it. An expired constructor publishes no handle
and drops its reservation and owners. A published owner clears only its per-call
deadline on return; a later call receives a new budget but one-way cancellation
remains set. A completed mutation followed by cancellation or expiration remains
an unknown outcome requiring exact original-ID reconciliation. Native failures
retain their typed diagnostics even when the call's deadline has also elapsed.
The internal invocation scope snapshots its cancellation token together with that
deadline. A retained witness endpoint creates each already-required fresh native
TCP/TLS exchange using this snapshot; it does not retain another call's token or
reread trust/configuration files. Existing public owners still use their original
permanent cancellation token on every call. Device parents use that same scope
with the selected child token, while parent cancellation also fences new calls.
Native unit checks exercise two different tokens through one retained endpoint,
real stalled TCP and TLS sockets, pre-cancelled refusal without a connection and
refusal outside an active scope. These byte-carrier tests supply no authenticated
reply; actual signed-witness C workloads separately exercise authentication,
restoration and revoked cleanup. Transport construction timings are not a
controlled performance comparison.
The installed C server regression waits 15 seconds before TCP admission and then
stalls TLS. It must return the invocation deadline outcome and close the socket
within the test's 23-second observation bound; this is not a latency SLA.
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

The eighteen `qpc_recovery_v1_*` functions share the handle registry, cancellation,
close and call budgets. Operational and recovery handles are distinct owner kinds;
using one for the other's operations returns `QPC_OWNER_KIND`. Recovery does not
create sending, receiving, rekeying or provisioning authority. Required-witness
state still requires the original native witness admission, including closed
session selection and catalogue restoration. Its explicit recovery constructor
loads the original device signer only for witness requests, without activating
SDK operational policy or application TLS owners. The explicit TLS variant owns
independent witness credentials for reconciliation only. The ordinary constructor returns
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

## Complete-account cleanup

The original-installation recovery constructor also supports
`qpc_recovery_v1_select_account`. It consumes discovery and selects an independently
retained batch ID. Authenticated native state supplies the complete member set;
callers cannot substitute recipients, split the reservation into single-session
cleanup, reconstruct operational permission or select a weaker witness profile.
The owner pins configuration, index and journal leases. Original installation scope
and every member archive authenticate before a pending write can be reconciled.

`account_begin` freezes every member and retains one immutable metadata-only loss
snapshot. `account_member`, `account_reserved`, `account_epoch`,
`account_unconfirmed`, `account_delivery` and `account_skipped` expose every field
and nested count. Each member has exactly one reserved input. Header/member layouts
are 72/136 bytes; epoch/item records reuse existing closure layouts. These structs
are not a portable serialization. Durably record the **complete** report and its
batch/report IDs before `account_acknowledge`. Wrong IDs conflict; exact repeated
acknowledgement is idempotent. Only then may `account_retire` remove batch metadata,
preserving all session/bootstrap tombstones and the monotonic counter. Logical
erasure does not promise secure deletion of historical pages or application copies.

`account_status` uses `QPC_ACCOUNT_*` local states. Committed batches cannot become
reserved abandonment. Account owners reject independent-session methods. Cached
report getters remain available after cancel; mutations are refused and witnessed
status still needs fresh native admission. Unknown outcomes require original-ID
close/reopen. A reopen that reconciles a pending retirement can successfully return
a selected owner whose fresh `account_status` is `QPC_ACCOUNT_RETIRED`; repeated
retirement is then a metadata-only no-op. A subsequent reopen reports
`QPC_RETIRED`. Validated absence reports `QPC_DURABLE_ABSENT`. None of these outcomes
provisions or reactivates state. The candidate
has exactly 50 exports, including 11 new functions; product ABI 2 is unchanged.

The standard collector builds a separate native fixture helper and uses the existing
bounded sync-probe runner. Three installations establish two account sessions. An
earlier committed send remains unconfirmed; incoming messages leave five unconsumed
deliveries and two skipped positions. A real process exit at a measured journal sync
leaves a complete reservation. After persistent SDK revocation, separate C processes
freeze, fsync the complete host report, acknowledge, retire and reopen the same ID.
Independent Rust readback matches every C report byte; Python also checks original
pre-fault identities and ciphertext commitments. Wrong-report/cancellation refusal,
committed/absent dispositions, bounds and independent-session separation are required.
The probe separately checks an unrelated inode.

Development Debug/Release on Rust 1.98.1 and Release on Rust 1.90 each pass this
28-command path with 139 public records and exact installed-library linkage. The
observed calibration is Committed without interruption, Absent at the first two
pre-sync cuts and Reserved at cut three. This is finite process-interruption
coverage, not all sync sites or physical power loss. The separate required-witness
trace below covers lost committed responses through all three foreign adapters.
Own-account cleanup, broader fault coverage and
final product admission remain separate. Earlier 39-export installed cohorts do
not qualify this extension; the complete `63b0e824` archive-produced cohort includes
the 50-export C cleanup path.

The `account_witness` helper shares the original native witness socket and complete
loss oracle with existing tests. Three original installations bootstrap two account
members through the selected C, Swift or Kotlin client/server. The real witness
commits an advance but withholds its response during reservation, freeze,
acknowledgement and retirement. Foreign callers retain the typed unknown outcome,
reopen under the same operation/report IDs, and reconcile each original command
with a fresh challenge. Missing/wrong witness configuration, a corrupted signature,
and witness absence even after retirement remain refusals. Host report fsync
precedes acknowledgement; all member tombstones survive retirement. Failure output
structs are never read: the recovery ABI defines them only on success.

The independent public replay validates all four phase ranges, exact original
command identities and challenges, three witness subjects, every loss field and
bootstrap receiver. It retains 67 C/Swift or 68 Kotlin files, including Kotlin's
parent-lifetime receipt. Native endpoints verify signatures; the public transcript
reader is a metadata/commitment oracle, not a second signature engine. Current
Debug/Release and minimum-Rust Release engine configurations pass this development
path. It uses explicit signed TCP, whose metadata is unencrypted; the separate
encrypted traces are described below. Own-account, physical power loss and
independent-engine qualifications remain open.

## Qualification path

The required-witness trace provisions and explicitly enrolls both original
installations with a separately owned native witness store. Actual C client and
server processes use its real socket for bootstrap, application delivery, rekey
and cleanup. Wrong witness pins and a corrupted signed reply refuse admission.
After committing the send advance, the witness sends only a signed-response prefix
and holds the socket. A concurrent C call observes Busy close, requests cancellation
and requires its sending worker to return the native unknown-outcome error within
one second. The witness observes connection closure. The trace also drops one
already committed cleanup advance. Reopening must retry the same command with a fresh
challenge and obtain `AlreadyAppliedExact`, without another logical advance.
SDK revocation blocks operational open; witnessed cleanup remains available.
Cancellation prevents freezing, and the reopened native journal confirms Open.
Closed archives still refuse admission without the original reachable witness.

The public transcript verifier checks every request/reply envelope length,
authority/subject, command and attempt commitment, challenge uniqueness and
monotonic head transition. It independently recomputes the unknown ciphertext
commitment and compares every loss-report row and the actual application record.
It binds the held partial reply to the original committed response and checks the
measured cancellation interval; the one-second test bound is not a latency SLA.
It does not independently verify signatures: the actual native witness and C
client engine perform those checks. The earlier OpenSSL vector oracle remains
a separate finite validation. This trace does not qualify witness TLS, independent
implementation, external service deployment, witness-store rollback resistance,
or cancellation of an arbitrary filesystem call. Pending-connect cancellation is
covered separately by the shared driver's actual-socket regression cases.

Run the existing installed package collector with `--with-c-consumer`:

```sh
sh artifact/python-run.sh artifact/continuity_package.py \
  --report /absolute/SDK-cohort/RUST_SDK_PACKAGE.json \
  --report-sha256 <verified-report-sha256> \
  --toolchain-root /absolute/rust-1.98.1-host-toolchain \
  --output target/continuity-installed-rust-c \
  --with-c-consumer
```

Add `--witness-openssl-prefix /absolute/openssl-installation` to require the
independent OpenSSL TLS reference peer (`bin/openssl`, `include/openssl`, `lib`).
The installed-consumer CI selects `/usr` on Ubuntu 26.04. The collector compiles
`witness_tls_peer.c` with strict warnings, matches CLI/header/runtime versions,
records the actual linked `libssl` and `libcrypto` bytes, and rechecks those inputs
after execution. Group support is established by actual TLS 1.3
`X25519MLKEM768` connections with `q-periapt-anchor/1` ALPN; unsupported libraries
fail the requested qualification. No version number alone establishes support.

The OpenSSL client sends real signed query/advance requests to the native server.
The reverse direction runs actual installed C owners through 142 witness
exchanges, application delivery, SDK revocation and crash/reopen cleanup. Four
separate OpenSSL server processes must reject wrong-subject credentials, trailing
data, missing authenticated close and wrong ALPN before any store dispatch.
Both authenticated TLS close notifications are required. The reference process
uses exact certificate/subject bindings, five-second connect/exchange deadlines,
fixed frame widths, at most 1,024 exchanges, and only explicit IPv4 loopback.
An invalid connection terminates its isolated reference process; this is not a
production listener availability or concurrency design.

The independent component is the TLS implementation. Signed witness verification
and durable transitions still run in the native `AnchorStore` host over bounded
IPC; this does not qualify an independent witness state machine, cross-host
deployment, a full TLS fault matrix, or a product provisioning API. Public exports
omit credentials and journals. The reference peer is outside the product C ABI
and does not add OpenSSL to its runtime dependencies.

It first executes the original archive-shipped Rust trace. The C phase then builds
both Debug/Release libraries and native C executables, checks the exact 50
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
The collector independently reads and exports the matrix's selected public
records to `c-sync-fault-public/<profile>` before reporting completion. Both
native CI upload lanes retain this directory alongside command and sync logs.
This makes original loss/archive and reservation readback possible without the
private temporary installation. The export includes only the verifier's named
records; missing required data fails before export and unrelated files are not
copied. The completed 7997282c native matrices independently export 342 files per
profile through this path, with a private-canary exclusion and missing-file
negative control on separate public-only copies.

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

The installation activation matrix also calibrates sync calls on the original
installation database, then interrupts the actual consumer before and after every
observed sync. It includes activation and subsequent close. A complete activation
reply already printed before a later close interruption is recorded as observed;
it is not counted as an unknown result. Unknown-result cuts must reach both
Creating and Active. An independent native observer checks the original journal
ID, unchanged next account position, absent account operation and empty archive
index. Creating must reject an ordinary device open, and explicit create must
reject the retained installation. Resume/activation must reconcile the original
state; Active must refuse storage recreation. C, Swift and Kotlin call their
actual installed interfaces. The probe is test-process-only, with a separately
checked unrelated inode; no fault switch is added to the SDK. This qualifies
process interruption of a local profile, not physical power loss, returned I/O
errors, required-witness commit cuts or initial intent/child creation failures.

Private test runtime directories contain wrapping/signing keys and journal images;
do not publish them. Retain the collector's public JSON, command logs, hashes and
dependency/loader records. Results qualify only the executed source/platform and
these finite local-profile client/server/cleanup scenarios. They are not a release, independent
implementation, cross-host connection, production C distribution or security proof.


The separate complete-account TLS workload bootstraps two original peer sessions
and freezes, acknowledges and retires the reserved account after SDK revocation.
It uses the existing native mutual TLS witness with three exact certificate/subject
bindings. Wrong witness pins, TLS names and certificate subjects refuse selection;
missing or unreachable original authority remains a failure after retirement.
Every measured foreign TLS phase must leave the plaintext witness's request count
unchanged. The complete loss report retains two reservations, two older unknown
sends, five unconsumed deliveries and two skipped positions across fresh processes.

The reserved state is deliberately prepared by losing one committed response over
signed TCP; native fixture preparation and report readback also use that original
witness. This workload therefore qualifies encrypted account bootstrap and cleanup,
not loss of TLS commit responses or a complete witnessed account-delivery/fault
matrix. The collector retains this carrier distinction and all eleven phase ranges
in its separate account-TLS public export. The original signed-TCP four-loss trace
remains mandatory. No raw owner handle, new native export or alternate TLS engine
is added. Current/native-minimum development runs remain separate from a complete
archive-produced cohort and final distribution admission.

The additional `account_tls_loss` workload withholds an encrypted reply after a
real native witness commit at reservation, freeze, acknowledgement and retirement.
A bounded socket relay retains ciphertext while the unchanged native TLS server
admits and handles the request. It observes the owned witness database before
handling and after successful serving: the native store persists only `Advanced`,
while queries and exact retries leave it unchanged. Private image copies are
bounded and zeroized; no TLS traffic secret, journal image or plaintext witness
transcript is exported. Each connection has one three-second deadline, 256 KiB
per-direction wire limits and joined worker threads.

Every lost outcome is reconciled by the actual foreign owner over the original
TLS carrier before native report readback. The separate signed-TCP witness must
observe no request during each measured foreign action. C/Swift/Kotlin current
Debug/Release and minimum-Rust Release libraries retain 178/184/183 exchanges,
36 native advances, four exact loss positions and 90/90/91 public files. The
public reader checks this census, command outcomes, original report and all loss
fields. Unlike the signed-TCP trace, it cannot independently inspect encrypted
command IDs or challenges. Native endpoints retain those checks.

Two isolated one-line controls fail when no loss is armed or a query is dropped
instead of an advance. Both originals and failures are retained. These finite
same-host traces do not qualify an independent witness engine, physical power
loss, all TLS failure sites or a completed required-witness account delivery.

## Complete-account delivery with a required TLS witness

The mandatory `account_delivery` trace runs actual C, Swift or Kotlin endpoints
under the three original enrolled certificate/subject bindings. The first receiver
fsyncs its application bytes and exits 77 inside the callback, before the native
consumption transaction. The sender retains the original committed batch and
message. A fresh receiver retries the idempotent application callback, creates no
second record, consumes the original message and returns confirmation. The other
member then receives its original reserved message. Both retained confirmations
subsequently require zero application-network exchanges; required witness admission
still occurs. No plaintext witness request is allowed during any foreign phase.

Application persistence is distinct from native consumption: this recovery returns
`duplicate=false` with one callback and zero new application records. Only a
previously consumed message skips the callback with `duplicate=true`. The collector
requires the actual receiver exit code, the application snapshot taken before
restart, original IDs, exact post-restart bytes and both consumption receipts.
Before reservation, an omitted-recipient attempt must return refusal, leave the
batch absent and preserve the next operation ID. An owned nonblocking listener
must observe no application connection. All nine phase ranges and their exact
admission counts are checked. Current Debug/Release and minimum-Rust Release
libraries pass 283 C / 289 Swift / 288 Kotlin admissions, retaining 69/69/70 public
files per configuration.

An isolated wrong-exit control fails on the actual 77 exit. A second control asks
for a new batch instead of retrying the retained one; it creates another application
record and is rejected by the consumer's complete-delivery check. It must not be
reported as successful original-operation recovery. The negative driver's initial
expectation of a later ID assertion was corrected to the earlier observed consumer
failure; the failed driver and both runtime attempts are retained.

The workload shares the existing native TLS server, bounded process lifecycle and
foreign owners. It adds no wire format, native export or alternate state engine.
This is finite delivery qualification with same-host endpoints. It does not
qualify the complete fault/concurrency matrix, independent witness deployment
or final archive/platform/product admission.

## Own-account delivery and cleanup

The additional mandatory `own_account_delivery` and `own_account_tls_loss` traces
reuse the same foreign owners and workloads with three distinct devices under one
authentic account root and signed roster. The initiator is a roster member but is
excluded from its two-device recipient set. The peer-account traces remain
mandatory and retain separate account roots. Both layouts complete original-ID
delivery and reconcile four committed TLS witness reply losses through revocation,
complete-report acknowledgement and retirement. All 36 combinations of two
layouts, two workloads, three languages and three library configurations pass in
development; fresh current archive qualification remains separate.

Public records retain all three original account/device/root/roster pins. The
reader checks root-derived account IDs, canonical roster commitments, exact
membership and generations, distinct credential digests and coherent account
layout. Native endpoints verify signatures; public parsing is not another
cryptographic implementation. Evidence schema 2 explicitly names the layout and
the collector selects its expected scope independently. Two controls execute the
peer layout successfully under the own-account test name: collection refuses the
scope, and changing only the public label still fails original-root/roster checks.
This does not qualify enrollment, credential renewal, device replacement or a
complete multi-device lifecycle.

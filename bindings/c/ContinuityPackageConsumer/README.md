# Installed Continuity C owner candidate

The current source adds same-key credential renewal on the original registration.
Resume the original enrollment intent, call `qpc_enrollment_v1_stage_credential_renewal`
with the exact grant, independent target pin and retained operation, then use the
existing consuming activation. `qpc_enrollment_v1_credential_renewal_status` reports
historical progress without loading policy/TLS. If a target expires while Pending,
`qpc_enrollment_v1_reconcile_expired_credential_renewal` distinguishes an actual commit
from proven expired NoCommit; it returns no Device. See the header's conditional
status fields and [native contract](../../../research/continuity-identity-candidate/CREDENTIAL_RENEWAL.md).

Peer grants enter through `qpc_device_v1_admit_peer_credential_renewal` on the same
parent service. Existing-session children use the service's historical-bundle path,
so current journal grants can authorize an original expired credential. Fresh
children retain ordinary current verification. Reopen a child after its grant
changes; cached views are never updated into new permission. Original registration,
policy, signer, journal and archive leases remain authoritative. For a required
witness, use the four `*_witnessed_credential_renewal` entries before activation:
prepare the exact proposal, obtain independent witness approval, then Commit,
Close or reconcile the original operation. Historical cleanup uses an independently
pinned signed policy snapshot; new Commit and activation require current authority.
Native/API source integration is not an installed archive qualification.

If a staged grant has no prepared proposal, reserve its cancellation with
`qpc_enrollment_v1_prepare_witnessed_credential_cancellation`. Keep the original
248-byte descriptor for independent witness approval. This call needs the original
pinned historical policy, including after expiry, but no SDK database or witness
connection. It reserves the original journal without preparing a target image.
Retry or reopen the same enrollment; do not replace the intent or reset its stores.
Once the independent witness has approved `Closed`, use the existing reconciliation
operation. `Unavailable` leaves the reservation pending. Local `Closed` is durable
before ACK; recovery retries the exact ACK before removing the reservation. New
Commit cannot use a cancellation descriptor, and an existing proposal conflicts.

The cancellation workload executes eight cases per language: signed TCP and
mutual TLS, live and actually expired policy, and SIGKILL at Status and ACK.
It checks the original reservation, unchanged image, exact terminal and no-SDK
cleanup. TLS cuts occur at request admission; TCP cuts withhold a processed reply.
Server completion does not prove the killed peer consumed the response. The
package collectors require the workload from the archive-derived harness for
C, Swift and Kotlin; source execution alone is not installed-package evidence.

A separate witnessed-policy workload signs the original short-lived policy before
registration and waits for actual expiry with SDK state still enabled. C, Swift
and Kotlin then recover the exact Applied/Closed proposal over signed TCP and
mutual TLS while rejecting new Commit and activation without current policy.
Applied setup uses the actual selected foreign client. After the witness durably
handles its original Commit, the fixture withholds the reply and reaps SIGKILL.
The original local state must remain Pending; an independent native observer
verifies a fresh signed Applied Status before expiry. The reopened foreign client
then performs historical recovery and ACK without another Commit. The TLS relay
retains encrypted reply bytes from the unchanged native server. A killed caller
does not establish the separate behavior of a caller returning a transport error.

The C renewal workload uses actual host-clock expiry. It checks exact pending and
terminal fields, preserves Committed after expiry, queries status in a new process
with SDK policy/TLS files unavailable, and recovers the original registration with
a separate root operation. The peer case establishes a real TLS session before
expiry, then exercises root-grant admission, independent-pin and operation refusal,
historical reopening and cached-child invalidation across two grants. A public
native readback compares the original outbox bytes after the C process exits.
Post-renewal application delivery over TLS remains a separate check.

The package collector selects all three `credential_renewal::` tests in each C
profile, using separate temporary installations, and refuses missing/ignored cases
or impossible expiry observations. Development runs of this workload do not
qualify archive installation, Swift/Kotlin renewal or an independent engine.


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

## Registering an original device

The registration and policy-continuation route has 34 `qpc_enrollment_v1_*` exports. Together with
peer-grant admission on the existing Device parent, this unpublished candidate
interface now declares 90 exports. The new renewal route still requires its own
installed-package qualification. It retains the whole native
`EnrolledDevice`, including its exclusive enrollment lease, inside the existing
device parent. It does not reopen a preconfigured installation to bypass that
owner. Product ABI 2 and the legacy constructors remain separate.

1. Create an admitted private configuration directory and explicitly call
   `provision_wrapping_key` once. Existing registration, signer or installation
   children refuse creation. Keep this wrapping file outside journal backups.
2. Supply an independently trusted account root and approved device ID,
   generation, policy family and validity in `QpcEnrollmentIntent`. Call
   `prepare_create`, then `qpc_owner_v1_finish_open`. Restart uses only
   `prepare_resume` and the same original intent; failure never selects creation.
3. Call `request` and send its exact public bytes to the account authority. Retries
   return the committed original request. The authority must independently
   authenticate the account action and verify this proof against its own approved
   intent before issuing a credential and complete roster.
4. Call `accept` with the signed response and a separately obtained
   `QpcEnrollmentPin`. Do not derive that pin from the response. Then call
   `prepare_storage`. Required-witness preparation returns the original public
   subject/genesis for independent operator authorization; it cannot enroll itself.
5. Call `activate`. Success changes the same handle into a device parent; create
   or restore peer children through `qpc_peer_v1_*`. Required-witness activation
   obtains fresh signed confirmation of the exact current authority before
   releasing the parent.

Opening, status and request need no credential, SDK policy database or TLS key.
Acceptance and later transitions require the independently provisioned SDK policy
store and verified protocol policy; activation also loads application TLS
credentials. Witness pins/carrier settings and peer trust remain independent
configuration. These application inputs and the authority transport are still
integration obligations; this route is not a complete account login service.

`status` reports durable progress, not live authority. An accepted native
transition that fails consumes the registration owner and releases its leases;
the handle then permits cancellation/disposal only. Dispose it and resume the
original record. Local Active may already be durable after denial or a lost reply.
Preflight shape errors preserve the owner; a pre-cancelled live owner remains
owned until close. Busy calls do not take it. See the header for the exact contract.
Never repair a missing active enrollment or key by creating another identity.

For same-credential continuation, resume registration and call `refresh_roster`
with the original predecessor and independently pinned target. The native durable
Refreshing transition reconciles the original journal before its roster CAS.
The witness operator must separately authorize the target. Activate the original
parent, then restore the original peer/session and operation ID. This cannot
replace a credential, policy, root or signer and is not a supported-version
storage migration.

If that exact refresh cannot resume under current authority, call
`qpc_enrollment_v1_resolve_roster_refresh` with its original predecessor and target
checkpoints after reopening the original registration. This reads the authenticated
journal and signed original policy history; it needs neither a live SDK runtime,
TLS inputs nor the private signer and returns no Device. Keep the original keys,
configuration and operation identity after every unknown result.

The separate 168-byte `qpc_roster_refresh_resolution_v1` reports the original pair,
actual observed head, original journal identity and retained observation time:

| Outcome | Evidence about the original target |
| --- | --- |
| `QPC_ROSTER_COMMITTED` | The observed checkpoint equals that target. |
| `QPC_ROSTER_EXPIRED_UNCOMMITTED` | The target itself expired and the observed version remains below it. |
| `QPC_ROSTER_SUPERSEDED_UNCOMMITTED` | The observed version equals the target version with a different digest. |
| `QPC_ROSTER_SUPERSEDED_UNKNOWN` | A higher observed version cannot reveal whether the target once committed. |

Retrying the original pair returns the retained observation, including its time.
A still-live target above the observed head remains pending (215); a mismatched
original pair fails (211). Admitted failures consume the enrollment owner but may
have persisted state: close and resume the same record. Pre-admission argument
errors preserve it; cancellation before admission keeps its lease until close.
The output record remains untouched on failure. Its reserved word must be zero.

The existing 152-byte enrollment status layout is unchanged. Phase 7,
`RosterResolved`, retains the **original** previous/next pair when the actual head
cannot yield the same credential's historical snapshot (for example, revocation
or generation replacement). The separate resolution record contains the observed
head. Phase 5 can be restored when that historical snapshot exists; neither phase
is current permission to operate. Obtain current independent authorization before
any new activity. This metadata path does not supply required-witness approval.

`roster_resolution_client.c` and `tests/roster_resolution.rs` exercise the exact
public C call and share signed fixture scenarios with the Swift/Kotlin public
consumers. Local source and wrapper-JAR results remain separate from installed
native archive, required-witness, other-platform and independent-engine evidence.

The `--enrollment-parent LOCAL_PATH ROLE` consumer selector follows this route.
Mandatory package workloads check original request/identity retention, separate
process lease exclusion, child/parent disposal, real TLS delivery with a lost
application receipt, same-session roster continuation, signed-TCP cancellation
and current-authority denial over both TCP and mutual TLS. Public readback is
structural; native endpoints verify signatures. Swift/Kotlin add typed owners over
this registration contract, with their own archive/ARC/GC gates. Current-source
devices, Android/WASM persistence and complete replacement/upgrade remain open.

## Preconfigured installation and peer owners

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
power-loss or fresh full-archive qualification. Swift/Kotlin expose the same setup
contract through typed owning wrappers.

The separate `setup_io` collector returns a real EIO before/after each calibrated
installation sync, using the test-process probe only. Consumers append phase
receipts around opening, activation and close. An opening sync failure must return
204; an activation commit sync failure must return 207 with no operational owner.
Both failure handles refuse further work and remain disposable. A 207 result can
leave either Creating or Active, so the collector resumes the original installation
and checks identity, account position and empty children. No error permits create.

Close-phase sync errors occur after the activation commit succeeded. The current
redb destructor treats shutdown metadata as recoverable housekeeping; owner close
is resource disposal, not another commit receipt for that metadata. The collector
requires the original Active state after reopen. It rejects an activation error
relabeled as a close error or successful activation. The existing exit-interruption
probe mode and all its controls remain required. Neither mode qualifies physical
power loss, arbitrary storage failures or required-witness activation commit cuts.

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

## Joint policy continuation integration

The additional candidate C entry points use the native enrollment transaction.
They retain original P0 configuration at the enrollment path and accept the
target signed protocol policy and its independently trusted root/checkpoint as
`qpc_policy_document_v1`. `select_continued_policy` opens explicitly configured
SDK policy storage and keeps the complete PolicyStore/runtime in the enrollment
owner. It is selected once per resumed owner; selection writes no G/T transaction.
The input protocol pin is never taken from an incoming approval container.

For a new joint renewal, select current P1, call `stage_policy_continuation` with
G, both approvals and independently retained previous policy/T, then explicitly
reconcile the local transaction or prepare/commit the required-witness proposal.
Native staging binds the actual original journal and exact predecessor. A later
credential-only update uses `stage_continued_credential_renewal`, retaining T.
Historical witnessed Status/Close/ACK can use the existing close/reconcile calls
with the exact transaction operation and statement. The new bounded metadata
outputs cover both G-only and G/T formats; existing fixed296/248 layouts are
unchanged. No entry point enrolls or approves work at the independent witness.

`activate_policy_continuation` transfers the original enrolled signer and storage
plus the complete current target runtime into the same Device handle. Required
protection requires completed ACK and a new witness admission; it does not
implicitly commit. The existing-session child path authenticates the original
bundle against historical P0 and opens it under current P1. Peer G verification
also remains bound to P0. The continued Device refuses fresh bootstrap. Closing
the parent closes both the native owners and the target policy runtime; children
do not retain a second operating service. Cancellation, deadlines, caller-owned
diagnostics and consume-on-admitted-failure behavior reuse the original boundary.

The current local test executes C subprocesses for registration, G1/T1 stage,
Pending readback, reconciliation, Committed readback and activation, then G2
carry of T1. It checks original signing/wrapping files, journal identity, original
P0 and independent P1 public inputs across process reopen. This does not yet
qualify required-witness C continuation, continued child traffic, failure and
runtime-lifetime controls, Swift/Kotlin exposure or current installed archives.

The separate `recover_historical_policy_continuation` entry accepts the exact
operation/statement and independently pinned historical P1. It uses original P0
metadata without selecting or loading a current target runtime. Only an exact
already-committed local journal target can finish configuration and receipt ACK;
an uncommitted Pending returns Suspended and stays Pending. It neither abandons
the original intent nor converts the Enrollment into a Device. Required-witness
transactions continue to use their independent historical recovery entry points.
The real-clock C test first observes expired-current-policy refusal, then makes
both SDK policy stores/configuration and local TLS files unavailable in its
temporary fixtures. Repeated history-only calls preserve Committed or Pending
and the original signing/wrapping/journal identity. Complete uncommitted local
policy abandonment remains separate from this completion-only recovery.


## Independent policy renewal on the original registration

The `qpc_enrollment_v1_*_policy_renewal` entries use the native independent
`qperiapt-policy-renewal/1` relation. The operation is separate from a credential
renewal or a joint G/T continuation; no credential grant is manufactured.

1. Retain one new policy operation ID. Resume the original enrollment and call
   `policy_renewal_request`. Keep its exact scope and four signed identity records.
   The returned account, original/current credentials, rosters and checkpoints
   come from the matched original enrollment/journal. This is metadata and does
   not reserve the operation or replace issuer authentication and deduplication.
2. Independently approve the exact relation under both account and policy roots.
   Retain the original request and exact approval bytes. Select the independently
   pinned current target with `select_continued_policy`, then call
   `stage_policy_renewal` with that request, independent original/current account
   pins, the independently pinned previous policy document and both approvals.
   Signed historical device records are reverified; target policy, credential,
   roster and actual journal predecessor checks still apply.
3. If the stage result is lost, close/resume the same registration and retry that
   same request and operation. Do not ask for a new request while Pending.
   `pending_policy_renewal_approval` recovers the first exact approval bytes;
   equivalent re-signatures do not replace them. `policy_renewal_status` reports
   the independent axis without implying current permission.
4. `reconcile_policy_renewal` coordinates the actual original journal commit under
   the selected current target. `activate_policy_renewal` additionally requires
   original TLS configuration and current native authority, and transfers the same
   controlled owner to Device. Use it to restore existing sessions. The reference
   client selects this path with `--independent-policy-parent`, which requires an
   existing session and refuses fresh bootstrap.
5. `resolve_policy_renewal` reads an exact original result using signed P0/target
   history without runtime, TLS or private-signer inputs. A live uncommitted target
   remains Pending; resolution does not silently commit it. Native evidence can
   report Committed or AbandonedUncommitted with its reason/head/time. Unknown
   actual policy supersession remains an error, never fabricated no-commit.

The request record is 33176 bytes with four bounded public records, each at most
8192 bytes. Unused bytes and reserved fields must be zero. These are native ABI
records, not a network message or a portable storage schema. The fixture writes
and reads them only across same-platform C processes. A real application still
needs a bounded external request format, pinned verification, account authorization,
serialized issuer decisions and durable operation/response deduplication.

A failed call never publishes success output. Admitted failure consumes the
registration owner and releases its leases, even if durable work already occurred;
close and resume original state. Preflight shape errors preserve the owner;
pre-admission cancellation retains it until close. Current activation does not
fall back to local-only operation for required-witness policies. The independent
witness control and bounded application-session paths are described below; full
product lifecycle qualification remains open.

The scoped C reference flow covers original request export, independent signatures,
Pending/restart retry, preservation of first signatures, real journal commit,
controlled owner transfer and historical readback without operational inputs.
It also restores an original TLS session and original message after receiver exit
following application-effect commit, then obtains ACK with the original effect
file unchanged. Its peer uses the same native implementation. These local source
results do not qualify Swift/Kotlin, installed native archives, an independent
engine, physical platforms, the broader failure/concurrency matrix or release.

The native source snapshot in this development candidate is the qualified original independent P/R implementation. Required-witness independent P has separate canonical QPPWNP01 C descriptors and historical progress, while runtime activation keeps the same enrollment and service owners. Embedded source and local linking are not an installed release-package qualification. The separately typed R coordination interface follows the same original owner contract; language wrappers, foreign changed-recipient roster admission and complete product admission remain open.


### Original required-witness roster refresh

`qpc_enrollment_v1_prepare_witnessed_roster_refresh` receives a retained R operation
and independently trusted current account pin, original credential and signed target
roster. The caller explicitly selects original P0 or the already selected independent
current P; neither path falls back after an error. The original enrollment/journal
derive and check the actual predecessor and exact unchanged P authorization. Retain
the full canonical 417-byte QPRWNP01 proposal before giving it to the independent
witness operator. Exact preparation retries preserve the first encrypted target.

Commit requires live current identity/P/runtime. Close and reconciliation use the
original historical scope and full caller-retained proposal. They persist and read
back Applied/Closed before witness ACK and exact pending cleanup. Progress is a
624-byte explicit record with bounded scope and zero reserved bytes; its phases
separate Absent, Staged, Reserved, Applied, Closed and AbandonedBeforePreparation.
Only Applied/Closed carry the retirement flag. None of these historical values is
an operational owner or a witness no-commit assertion.

An unknown preparation may leave only Staged, or the exact original pending target.
Recover preparation before deciding the next action. A locally absent preparation
is not witness Closed. The explicit abandonment API applies only to an intent whose
proposal was never released and whose original journal has no pending under its
service lease. A failed initial signed head query is exercised through actual C
processes to establish that this path needs neither a live runtime, signer nor any
new network request. Reserved/terminal targets must reconcile their original result.

The C tests cover original P0 and adopted independent P over signed TCP and mutually
authenticated hybrid TLS, exact encrypted target installation, full proposal/type
substitution, precancel output/owner rules, successive R after Applied/Closed and an
actual next-P issuer request using the newly adopted roster. Separate processed
commit/ACK reply losses preserve the original pending and recover after current SDK
and application TLS inputs become unavailable. Historical progress can additionally
be read without the private signer. Test hosts retain each original request/proposal
and per-operation log before starting another operation; fixtures do not overwrite
prior evidence. These are local native-library consumers, not an installed release
package or a separately implemented witness protocol. Post-dispatch cancellation,
foreign lifecycle transaction process cuts, actual foreign signed-policy expiry,
new Kotlin/Swift APIs and complete 0.2.0 qualification remain open. macOS support is
Apple Silicon only.

### Original application session across required P/R

The C application test establishes one original TLS session under P0 with a required
witness. Its receiver process persists the business result, syncs the file and its
directory, then exits with code 77 before reporting consumption. The sender retains
the original message as Committed, without inventing an ACK. C owners then adopt an
independently approved P1 and R2. The TCP witness scenario drops an actually processed
R ACK reply and reconciles that same terminal before resuming application work.

After reopening the updated owner, the original message remains Committed. A retry
using the unchanged bootstrap bundle, session ID and message ID obtains consumption
confirmation. The receiver callback finds its original durable result and creates
no new effect; the original file identity, size and modification time are unchanged.
This is a host deduplication contract, not an assertion that arbitrary business
side effects execute exactly once. Sender and receiver then complete a real TLS
control exchange to epoch 1 and deliver new application messages in both directions.
The sender's original signing and wrapping files remain unchanged throughout.

Both signed TCP and mutually authenticated hybrid TLS witness carriers are exercised.
The two application endpoints use the same C binding and native implementation.
These results establish a bounded same-host source-consumer path, including two
actual receiver process exits. They do not establish an independent protocol engine,
fresh-entropy compromise recovery, lifecycle transaction crash coverage, account
changed-recipient fanout accounting, actual policy expiry, installed package/platform
support or full release. The fixed-recipient account scenario is described next.

### Complete original account batch across required P/R

The C reference client accepts `account-next`, `account-status` and `account-send`
through an explicitly selected `--enrollment-parent` or
`--independent-policy-parent`. It transfers that same parent into the existing
account command, whose peer children all belong to the same native device service.
The path and initiator role must match, and an independent-policy parent refuses
`account-connect`: continued operations do not silently bootstrap replacement
sessions. The installed-device account path remains available unchanged.

The qualification flow creates two original recipient sessions for a complete
account, confirms the first member, and observes the second receiver process exit
after durable application commit. After independently approved P1 and local R2,
the original account batch remains Committed. The first member returns its exact
retained acknowledgement with zero application exchanges, including when the complete
input vector is reordered. The second member retries the original message ID,
confirms consumption and then also returns its retained result. Both effect files,
bootstrap bundles and the enrolled sender's signing/wrapping files remain unchanged.
The test also observes new witness admissions on retained-result calls: zero
application exchanges never means skipping the current witness checks.

Unary release, changed input, an omitted original member and a cancelled member
are rejected without journal mutation. The fixture distinguishes incomplete first
admission (PolicyDenied) from changing an already committed batch's member set
(ScopeConflict); it does not treat either failure as permission to rebuild a batch.
Signed TCP and mutual-TLS witness carriers each exercise this sequence.

This changes the reference client's owner routing and its tests, not the native
protocol or C ABI. A public peer-roster admission path with original-owner/current-P
checks is still needed to qualify foreign changed-recipient suspension and cleanup.
Direct journal mutation in a test cannot substitute for that product boundary.
Actual policy expiry, lifecycle transaction cuts, language wrappers, installed
packages, independent implementations and complete 0.2.0 release remain open.

### Current peer rosters and complete original-account recovery

`qpc_device_v1_admit_peer_roster` accepts a bounded signed roster and an independent
account pin through the selected original device parent. It admits only an already
known remote account with the same authority/family and a monotonic checkpoint.
Local roster changes still use the atomic enrollment R operation. Exact retry
returns the current target after fresh current-policy and required-witness checks;
errors publish no checkpoint and do not prove that an earlier write did not commit.
Reopen the same installation after an unknown result. No fallback policy or new
installation is selected.

After a roster update prevents resuming the original account operation, close the
traffic owner and select the original batch through the recovery owner.
`qpc_recovery_v1_account_reconciliation` returns a bounded complete frame containing
all original device, session and message IDs. Acknowledged and DeliveryUnknown are
separate; Committed and ResolutionPending prohibit retirement. This uncached call
requires the original witness head and returns no ciphertext. HistoryRetired cannot
reconstruct whether prior settlement was acknowledgement or recorded loss.

For each unresolved original session, retain every field of its closure report in
a durable host transaction before acknowledging the exact report. Reopen the same
batch and reconcile all members. `qpc_recovery_v1_account_retire` then removes only
aggregate metadata, preserving session/bootstrap records and the monotonic ID.
Persist needed results before retirement: a fresh Retired result does not recreate
the earlier member report. The C reference client serializes each member report
separately, syncs file and directory, and verifies the exact retained bytes before
acknowledgement; it keeps aggregate results separately before metadata retirement.

These are additions to the unpublished `qpc-owner/1` candidate, not product ABI 2
stability or complete 0.2.0 admission. Swift/Kotlin required-witness roster and
peer-roster update paths, installed-package qualification, physical
platform evidence and independent protocol/security review remain separate gates.

The signed-TCP peer-roster interruption workload exercises a complete request
lost before witness processing, a processed reply loss, cancellation while the
original C call is active, and termination of that process after a processed
partial reply. Recovery opens the original complete-account owner while the live
independent SDK resource is unavailable. It must install the byte-identical
sealed target and preserve each original member outcome. A processed-loss retry
uses a fresh challenge for the same complete command: the first witness result is
Advanced and the recovery result is AlreadyAppliedExact, with the same target and
last command. Two requests are not two state advances. The reference client also
checks that close is Busy during the active call, cancellation returns promptly,
and an unknown outcome publishes no checkpoint or new account ID.

The mutual-TLS peer-roster workload covers three post-commit cuts: encrypted
reply loss, cancellation during a partial encrypted reply, and termination of
the original C process at that same observed barrier. It uses the unchanged
native TLS server and an encrypted-wire relay, checks the exact signed Advance
and AlreadyAppliedExact records, and retains the original target and complete
member results through historical recovery. After selecting TLS, the original
plaintext witness request count must remain unchanged throughout both sessions,
the policy/roster transitions and recovery. The fixture's earlier registration
uses its original signed carrier.

With `--witness-openssl-prefix`, a separate pre-processing scenario uses the
pinned independent OpenSSL endpoint. It authenticates the complete mutual-TLS
request, then disconnects before calling the native witness store. It requires
an unchanged witness image, recovery of the original sealed pending target with
a fresh challenge for the same command, and complete original member accounting
before retirement. No plaintext fallback is permitted. C, Swift and Kotlin run
this same scenario through their selected clients, including registration and
local P/R adoption. The selected client also persists and acknowledges each
original member loss report. The TLS implementation is independent,
while the signed witness protocol and storage engine remain shared. Native TLS
server pre-processing interruption remains a separate gate.

The foreign account-recovery workload selects one Swift or Kotlin executable
for registration, local P/R adoption, original account traffic and peer-roster
admission/interruption, each member's loss-report persistence and acknowledgement,
complete member-result reads and final metadata retirement. The nine scenarios
require 99 completed foreign traffic calls; the optional OpenSSL scenario adds
11. The same selected language now establishes both sessions and runs their
receivers: 18 establishments and 36 completed receiver processes, including nine
observed post-commit exits, plus two establishments/four receivers/one exit in the
OpenSSL case. Every original application effect is independently read back and
must not repeat during recovery. Each scenario requires seven registration calls,
seven witnessed policy calls and five roster calls from that same foreign client.
The host independently verifies registration identity and supplies root/policy
authorities, SDK setup and witness approvals; it retains C raw-buffer controls.
The combined scenario covers normal P/R adoption, with interruption checked in
the separate policy/roster workloads. Each language run requires 36 completed
member-closure calls across the original nine scenarios;
the optional OpenSSL pre-processing scenario requires four more. The exact
session-specific report must be durably retained and read back before its ACK.
Every language must preserve the exact original batch/session/message identities,
distinguish authenticated consumption from unknown delivery, durably retain the
full host result, and refuse early retirement in the two normal carrier cases,
four signed-TCP interruption cases and three post-commit mutual-TLS cases.
This uses one shared native protocol implementation and does not qualify
physical platforms or the final release. The installed-package collectors require the same recorded C
harness and explicit foreign executable, without silently falling back to C.


The separate foreign independent-policy workload now selects Swift/Kotlin for
local and required-witness P requests, staging, exact-proposal coordination,
historical recovery and original-owner activation. It also uses the foreign
client for the original TLS session's lost-application-receipt recovery. Ten
scenarios require 117 policy calls and seven transport calls per language/profile;
C continues to perform registration and invalid raw-buffer controls. The installed
collectors bind both clients and the same previously qualified C harness.
The P request fixture calls the real API from a default pthread. Private request
results stay on the heap through owner/panic boundaries and are copied to the
unchanged caller-owned ABI record only after admission and crypto have returned.
The Swift wrapper likewise owns a bounded heap output buffer; failed native calls
never initialize, decode or publish a successful request. This addresses measured
worker-stack exhaustion without changing thread stack sizes, signature checks,
error-output guarantees or any of the 106 C exports.

## Permanently retired enrolled devices

The unpublished `qpc_retired_v1_*` family delegates whole-device cleanup to
`RetiredDeviceEnrollment`. It accepts the original approved enrollment intent,
an independently obtained witness pin, the complete original device replacement
proposal, and the signed permanent retirement proof for that old subject. These
inputs cannot be learned from an untrusted response and then treated as pins.
The scope is an existing enrolled installation with required-witness protection;
this interface does not authorize replacement, provision a new device, or add
witness protection to a local-only installation.

Close the original operational device/peer owners first. Call
`qpc_retired_v1_prepare_open` to snapshot the supplied inputs, then the existing
`qpc_owner_v1_finish_open` on that same handle. Opening may durably retain the
original inventory and enrollment retirement metadata. An unknown commit returns
no usable resource: close the handle and reopen the exact original inputs.
No operational SDK policy, TLS material, signer or service is exposed by this
restricted owner. The ordinary registry, cancellation and call limits apply.

The complete sequence is:

1. Read `inventory` and obtain the independently authorized witness inventory
   retention receipt. Preparing a request is not the witness's commitment.
2. Call `prepare_report`, retain its exact proposal, and obtain the corresponding
   independent report-retention receipt. `report_proposal` restores only the
   locally retained original expectation.
3. `load_report` authenticates both receipts and the complete original state.
   `copy_report` copies exactly the returned length of canonical `QPRDMD01/QPRDMD02`
   metadata. The record includes every original view; its keyed report ID is
   returned separately in the report info and original proposal. Protect these
   identities, account/device linkage and lengths as private host metadata.
4. Durably save the complete report and deduplicate the application's accounting
   by its report ID. Only then call `prepare_acknowledgement` with those exact
   saved bytes. The SDK does not perform or infer external host effects.
5. Obtain the independently authorized purpose-21 acknowledgement. Then
   `erase_journal` commits the original journal's logical terminal. Inspect
   `journal_state` after an unknown result; never reset or select another backup.
6. `prepare_signer_erasure` authenticates journal erasure, host acknowledgement,
   and the original encrypted signer file. Inspect `signer_state`, then call
   `erase_signer`. The latter consumes the resource even on success; close the
   registry handle and reopen the original inputs for further inspection.

The queries distinguish local absent proposals, retained originals, authenticated
terminals, and missing/corrupt files. None means local proposal absence only,
not a failed remote commit. Native errors and late cancellation consume an
admitted resource, while static pointer/length rejection precedes admission.
Outputs stay untouched on error, except that constructor handle outputs are
initialized to zero. A malformed receipt never becomes permission to erase.

Logical erasure does not erase old disk pages, backups, wrapping keys or saved
host metadata. After terminal erasure, reopening the signing file or ordinary
enrollment remains refused. The process workload first uses the existing public
registration API in ten C processes to create generation 2, reopen its original
request, accept and re-accept an independently signed grant, and prepare its exact
genesis. Activation before witness replacement is refused. The persisted
`Activating` state resumes that original genesis; it must not call `prepare`
again. After the independent account/witness controller commits replacement,
the C client activates and reopens the same journal. Eight further C processes
perform cleanup, with independent native report readback and three exits without
completion after durable work. Two more C processes then reopen the enrolled
successor: one serves the fresh TLS bootstrap, and another opens that exact session
and durably consumes its application message. Returned session/message identities,
callback counts and complete host effect bytes must match the native sender.
Three additional C processes observe the next publication ID, prepare its
complete advertisement, and recover the identical bytes after reopening the
registered owner. Both actual connection bundles must contain exactly that
manifest and its four membership proofs. Account issuance and witness replacement
authorization remain with the native Rust controller.
It also exercises snapshots, invalid receipt/length refusal, cancellation and
consumed-owner behavior. Debug/Release installed execution is required by the
package producer. Source execution alone does not qualify installed archives,
Swift/Kotlin, physical devices or the complete device-replacement lifecycle.


## Recoverable prekey publication

An activated device parent can own publication without a peer child or a signing
handle. Supply a `qpc_publication_plan_v1` with its exact `struct_size`, zero reserved
field, independently trusted directory expectation, finite validity and bounded
ordered key plan. A generated member has `reuse=0` and zero request bytes; explicit
reuse names an existing available inventory member with unchanged role/validity.

Read `qpc_device_v1_next_publication` and durably retain that ID and complete plan
before dispatch. Call `qpc_device_v1_publication_size_bound`, allocate that capacity,
and invoke `qpc_device_v1_prepare_publication`. Reopen after uncertain failure and
retry the same ID/plan. Only complete currently admitted `QPPUBA01` bytes are copied;
its inventory IDs use plan order and its proofs use canonical leaf order. The full
binary grammar and pointer/overlap requirements are documented in `qpc_owner.h`.

`publication_status` reports local history only. A prepared artifact can cease to
be releasable after expiry, revocation or inventory consumption. Acknowledge its
exact artifact digest with `retire_publication` to reclaim public history without
retiring keys. `abandon_publication` applies only to the original reserved intent
and retires fresh unshared members; it preserves reused keys and consumption
history. Retired ordinals are never allocated again. No call reports remote
publication, remote revocation or physical erasure.

## Explicit first-use configuration

The unpublished `qpc-owner/1` candidate has 132 exports, including five
`qpc_configuration_v1_*` entry points. Product SDK ABI major 2 is unchanged.
Fill the versioned input with `struct_size = sizeof(input)` and `version = 1`.
Supply original SDK trust, exact signed initial policy (and original recovery
proof for recoverable trust), independently pinned protocol policy and your own
local TLS DER identity. `prepare_create` copies those inputs synchronously;
`qpc_owner_v1_finish_open` validates and atomically publishes configuration, SDK
storage and the generated wrapping key. Caller buffers may be cleared after the
prepare call returns. No registration or traffic authority is created yet.

If first publication returned an unknown result, use `prepare_reconcile` with
those exact original inputs. A mismatch or missing key is an error, not permission
to reset state. For known committed state, `prepare_open` requires original host
SDK trust and pinned protocol metadata; mutable root files are not trusted.

`begin_enrollment` converts that same handle into original registration with an
explicit approved intent and optional independently trusted witness input. Mode 1
creates an original registration; mode 2 resumes it. Required-witness policy still
requires explicit witness enrollment and an authenticated reply before activation.
The optional TLS witness input includes independent peer/local certificates, key,
name and endpoint. Follow the existing accept, prepare-storage and activation
transaction after the application authenticates and approves the account/device.

`select_continued_policy` moves a finished target configuration's SDK lease into
an existing enrollment handle. Close the now-empty configuration handle. Selection
is not durable approval/adoption: the signed renewal transaction is still required.
An admitted failure may consume both volatile owners; close both and explicitly
reopen original inputs/intent. The header documents admission, cancellation,
ownership and unchanged-state requirements. `first_configuration_client.c` is a
standalone public C consumer; installed qualification executes it with independently
supplied inputs, never a copied private installation.

The installed first-use workload also composes policy renewal with delivery
recovery. After its original peer commits one application effect and exits before
returning the ACK, the sender obtains independent account-root and policy-root
approval for P0 -> P1. It rejects a tampered approval, replays the original renewal
request/stage, commits or reconciles the original witness proposal, and retries
the same session/message through the explicitly selected target configuration.
The receiver observes one durable effect. Local, signed-TCP and mutual-TLS
carriers run with fixed and recoverable SDK trust in C, Swift and Kotlin.

This workload starts while P0 remains valid and keeps the SDK policy unchanged.
Its mandatory public reader checks original identities and exact replay; the
shared native engine verifies signatures. Expired-policy first-use recovery,
SDK-policy replacement and independent protocol implementations need separate
qualification. The [integrated checkpoint](../../../research/sdk-alpha1/evidence/20261010-first-configuration-policy-integration/CHECKS.json)
records the actual execution and reader controls.


## Explicit peer configuration under the original device

`qpc_peer_v1_prepare_configured` and `qpc_peer_v1_prepare_configured_reopen`
accept `qpc_peer_configuration_v1`, with `struct_size = sizeof(input)` and
`version = 1`. Supply independent initiator/responder account pins and exact
expected devices/generations, a directory expectation, the untrusted signed
bootstrap bundle, and an independently pinned TLS peer certificate/name. Incoming
bundle bytes cannot define those expectations. Quality and role remain explicit.
Every bounded input is copied before preparation returns; no peer directory is
read by this route. The existing file-based entry points remain available.

Finish the returned pending child through `qpc_owner_v1_finish_open`. The same
native bundle verifier, original device, current policy/roster and TLS engine
perform admission. Reopen additionally names one original nonzero session and
never falls back to fresh bootstrap. Continued-policy restrictions are unchanged.
A prepared descriptor is not a remote TLS authentication result; name checking
and actual peer authentication occur at the connection boundary. A failed
connection may follow a durable initiation, so retain and recover the original ID.

The child retains its original parent and shares the existing owner/call quotas.
Cancel and close use the normal pending-owner contract. Explicit parent close
invalidates retained children and releases the actual stores. Product ABI 2 is
unchanged. The installed C/Swift/Kotlin gates require explicit-input traffic,
original-session recovery and public readback; foreign probes additionally
exercise public-wrapper release, explicit close and pending-child cancellation.

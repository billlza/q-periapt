# Continuity candidate state and operation contract

Status: **implemented candidate, not a frozen product contract**. This describes
the shared Rust implementation at `e00281ec`, with journal v21, message state
`QPMST011` and the fixed v6 rekey profile in [WIRE_V1.md](WIRE_V1.md).
It supplies the state semantics that language adapters must preserve. It is not
a second implementation, a stable numeric foreign ABI, a distributed transaction
or a proof of continuous recovery. Product admission still requires the remaining
[0.2.0 obligations](RELEASE_0_2_SCOPE.md).

## State, authority and observation

An operational context owns references to the original verified protocol policy,
SDK runtime, role-ordered devices and authenticated prekey selection. Received
bytes cannot select the independently pinned accounts, intended device generations,
directory expectation, allowed prekey quality or local bootstrap role. A decoded
bundle, correlation ID, stored phase or TLS connection is not operational authority.

There are distinct state owners:

| Owner | State it controls | What closing it does |
| --- | --- | --- |
| SDK runtime / verified protocol policy | Current permission for primitive and protocol operations | Denies later admission; does not erase already durable application effects |
| Signing and wrapping-key owners | Secret computation and authenticated state recovery | Releases their owned memory; does not revoke copied files or backups |
| Installation | Original device lineage, paths, key/policy/witness binding and Creating/Active phase | Releases its exclusive configuration lease after its children |
| Device journal | Bootstrap, inventory, roster, message, control and fanout aggregate | Releases the database/key owner; committed work and pending write intents remain |
| Archive index / restricted recovery owner | Original cleanup scope and existing terminal reconciliation | Releases leases; never creates operational authority |
| Transport invocation | Socket, absolute deadline, cancellation and attempt budget | Stops dispatch according to its bounded cancellation contract; cannot undo a commit |
| Host application | Application effect and its durable deduplication/accounting record | Outside the journal transaction; the host must reconcile its own unknown results |

Every journal load authenticates the current image. Required-witness admission is
checked against a fresh signed full head, including before cached output release.
Operational methods additionally check current policy/runtime, trusted time and
installed roster authority. Status methods deliberately permit some reconciliation
after expiry or policy close; that permission never extends to dispatch, plaintext
release or new work. Each status method still verifies its original owner/context,
image and protection binding. [Storage recovery](STORAGE_RECOVERY_V1.md) defines
the separate local-intent and witness transitions.

Queries describe the state read by that operation, not a lease on future state.
For example, `next_message_id` does not reserve a slot. Concurrent callers can
observe the same ID; only exact-input durable admission determines its owner.
Bindings must serialize access to mutable owners or return their defined contention
error. A cached query must not bypass the next method's admission checks.

## Installation and prekey inventory

`DeviceInstallation::provision` requires an explicit first-install decision and
independent verified inputs. It durably creates `Creating` with the original
journal ID and exact key/device/policy/path/witness binding before child creation.
`prepare` reconciles only that genesis. Required-witness preparation returns
enrollment metadata, not a service. `activate` reconciles both child owners,
commits `Active`, rechecks admission and only then returns `DeviceService`.

An activation error can occur after `Active` committed. The caller reopens the
same installation; it must not infer `Creating`, absence or permission to reprovision
from an error. An Active installation refuses missing children. Operational restart
requires the original current authority. `InstallationRecovery` instead opens only
existing Active configuration/index and authenticates a selected original archive
before constructing a cleanup-only journal. It cannot bootstrap, send or rekey.

| Prekey state | Legal progression / observation |
| --- | --- |
| `Absent` | A new retained request ID can reserve exact parameters and platform-generated key-generation randomness |
| `Reserved` | Resume the same sealed command; no public leaf is available yet |
| `Available` | Public leaf/recovery command are committed; release still checks authority; a pending bootstrap reference prevents retirement |
| `Consumed` | One-time recovery material was removed in the same aggregate commit as its response outbox |
| `Abandoned` | Explicit bootstrap cancellation burned claimed one-time recovery material |
| `Retired` | Explicit inventory retirement removed logical recovery material |

The final three states retain their request/public identity and cannot become
Available again. Reusable leaf kinds follow their separate inventory rules; a
caller cannot reinterpret a one-time leaf as reusable. Parameter changes for an
existing request conflict. Inventory includes tombstones in its 1,024-record
bound; account rosters have their separate 64-record bound. Neither retirement
nor revocation refunds the prekey identity. The [compiled budgets](BUDGETS_V1.json)
also retain the aggregate image and operation-record caps.

## Bootstrap: exact reservations before effects

The durable phase names below are observations of one exact source operation.
Their Rust discriminants are local storage schema, not a foreign ABI contract.
`Absent` is returned only by a successful authenticated lookup.

| Role / phase | Retained work and next permitted transition |
| --- | --- |
| Initiator `InitialKeyReserved` | Exact fresh hybrid key-generation command; resume under the original owners |
| Initiator `InitialKemReserved` | Exact key and encapsulation command bound to the application context |
| Initiator `InitialSignatureReserved` | Complete initial body and purpose-bound signing reservation |
| Initiator `AwaitingReply` | Initial wire and private reply state committed; exact initial wire can be dispatched |
| Initiator `ProcessingReply` | One authenticated exact reply reserved; a different reply conflicts |
| Initiator `FinalPrepared` | Accepted result/root pinned; final outbox completion can resume |
| Initiator `FinalCommitted` | Exact final outbox and private root committed; no responder receipt is implied |
| Responder `Executing` | Authenticated input reserved with exact selected keys; original keys are needed to resume |
| Responder `ResponseKemReserved` | Validated initial contribution and exact responder encapsulation reservation |
| Responder `ResponseSignatureReserved` | Complete response body and purpose-bound signing reservation |
| Responder `Prepared` | Exact response/root pinned; finish the consumption/outbox commit without fresh crypto |
| Responder `AwaitingFinal` | One-time consumption and response outbox committed together; response may be dispatched |
| Responder `Complete` | Final key confirmation and private root committed |
| Either `Rejected` | An exact definitive failure is retained; this is not an absent operation |
| Either `BootstrapCancelled` | Explicit irreversible pre-activation cancellation; retained claims and metadata prevent reuse |

No reserved or merely computed body is dispatchable. Each returned initial,
response or final wire follows its required local commit and release checks.
Retries recover the exact source operation; they do not substitute a new request,
nonce, prekey or signature reservation. A stage requiring an unavailable original
owner is `Suspended`, not a signal to begin another bootstrap.

`activate_initiator_messages` / `activate_responder_messages` transfer the admitted
bootstrap root into one paired message record and preserve the original source
relationship. The native connection path persists the original cleanup archive
before activation. Activation is a local permission transition: the initiator's
final commit does not prove that the responder has received it. The carrier sends
the final before its dependent application frames; responder activation requires
its own final-confirmation transition.

Permanent cancellation applies to pre-activation work and preserves any one-time
claims, including burned inventory. It cannot recall already dispatched bytes or
cancel an established message session. That requires the closure flow below.

## Application send, receive and consumption

`MessageId` binds logical session, sending role, epoch and sequence. Restoring its
32 bytes restores a correlation value, not authorization. Use the original ID and
input for reconciliation; never allocate another ID to conceal an unknown result.

| Outgoing status | Meaning and allowed handling |
| --- | --- |
| `Absent` | This authenticated lookup found no reservation/outbox for the named ID; new work still requires the exact next-slot and current-authority checks |
| `Reserved` | Exact plaintext/AD input is durable, but no dispatchable ciphertext is committed; resume its sealed input |
| `Committed` | Ciphertext and chain advancement committed together; exact outbox replay remains subject to authority |
| `Acknowledged` | A valid peer consumption acknowledgement retired this outgoing prefix |
| `ResolutionPending` | Frozen unresolved delivery awaits host accounting; it must not be sent or represented as successful consumption |
| `DeliveryUnknown` | Host acknowledged accounting for an unresolved committed send; no successful delivery is asserted |
| `ReservationAbandoned` | Input was never committed as an outgoing message and its whole session is terminal; the ID is not reusable |

The send path reserves exact input before chain advancement, then commits its
outbox and next chain state in one aggregate image. Same ID/different input fails.
`resume_message` accepts no replacement plaintext. A query after terminal closure
uses retained keyless reconciliation metadata. A retired traffic history can
instead return a retirement error; bindings must not convert that to Absent.

Receive derives on candidate state, authenticates the complete epoch-bound frame
and AD, then commits inbox/plaintext, receipt and chain/skipped-key changes before
returning `CommittedPlaintext`. Invalid authentication does not commit candidate
state. Exact duplicates can return the retained inbox before consumption. They
cannot replace it with different authenticated bytes. After consumption the raw
receive API returns retirement rather than releasing the plaintext again; the
carrier can recognize prior consumption and return the existing ACK.

`Consumer::commit` is the host's independent transaction. It must durably combine
the application effect with deduplication by `(session, message_id)` before
returning success. Only then does `consume_message` mark the inbox consumed and
permit its authenticated contiguous-prefix ACK. The host can commit and lose its
reply before journal consumption: a later duplicate invokes the host again and
must reconcile the same effect. The SDK cannot promise exactly-once external
effects merely from transport or journal success.

ACK acceptance authenticates the correct direction and epoch. Epoch-zero
`QPCMACK1` and positive-epoch `QPCMACK2` cannot acknowledge each other's records.
ACKs advance only an admitted contiguous prefix; a socket write, TLS receipt or
control completion does not advance it. Consumed gaps, skipped keys and outstanding
records retain their explicit bounds and backpressure.

## Rekey and sending progress

The fixed construction is a four-flight hybrid rekey for one unchanged logical
session. Original initiator proposes odd targets; responder proposes even targets.
The target is exactly the predecessor plus one and binds the completed transcript.
It is not a configurable combination of unrelated ratchets.

| Committed transition | Sending / receiving / locally confirmed epochs |
| --- | --- |
| Offer: key/signature reservation then exact signed outbox | All remain at predecessor |
| Response: exact encapsulation, pending root/signature then signed outbox | All remain at predecessor |
| Proposer Final: authenticate response/confirmation, commit final plus traffic owners | Sending advances; receiving and confirmed remain at predecessor |
| Responder Receipt: authenticate final, commit receipt and both traffic owners | Sending, receiving and locally confirmed advance |
| Proposer accepts Receipt | Receiving and confirmed advance to the already selected sending epoch |

During final/receipt signing preparation, new sends are fenced so the signed old
sending length cannot change. Existing exact sends, receives and consumption keep
their specified recovery paths. A pending input must finish before cutover
preparation. New-epoch data before local control admission is suspended without
advancing keys. Duplicate controls return retained results; a target mismatch,
altered transcript or incompatible pending input never starts a replacement epoch.

The control step API returns either committed `Output` bytes or
`LocallyConfirmed(target)`. The latter means only that exact local target completed.
A responder may still need to retransmit its committed receipt after losing all
network output. Empty carrier output is not implicitly local completion. Network
drivers retain one explicit target and fixed deadline/attempt budget across retries.

The signed `ApplicationSendBudget` is nonzero. The spend window includes committed
sends in both the locally confirmed epoch and any unconfirmed sending epoch, plus
the current reservation. A final commit alone cannot refill it. The receipt
transition advances the window without refunding new-epoch spending. Exhaustion
returns `RekeyRequired` for new input; exact already reserved/committed work remains
recoverable. ACKs, restart, epoch resolution and explicit caller IDs cannot reset
this accounting. [SEND_PROGRESS_V1.md](SEND_PROGRESS_V1.md) records its contract.

At most four traffic epochs remain. Before a fifth displaces history, both peers'
signed offer/response assertions attest to their own settled prefix. The local
implementation checks its own settlement before signing; it cannot prove the
remote host's application state merely from that signature. Missing ACKs or
unconsumed data block automatic retirement. The v6 profile's exact KDF and control
grammar are in [REKEY_OFFERS.md](../../research/continuity-identity-candidate/REKEY_OFFERS.md).

Counters report protocol progress, never that an unknown compromise has healed.
Previously disclosed pending entropy remains disclosed after deterministic replay;
[RECOVERY_CONDITIONS_V1.md](RECOVERY_CONDITIONS_V1.md) states the separate obligations.

## Resolution, closure and aggregate sends

Closed-epoch resolution is explicit: `Unrequested → Pending(report) →
Acknowledged(report)`. Freezing commits the exact report before release and stops
old-epoch operations. The host persists the whole report, including unconsumed
deliveries and unresolved outgoing IDs, before acknowledging it. Acknowledgement
removes logical epoch secrets/data while retaining old counters and unknown
outcomes. It does not turn the outgoing floor into successful delivery. Only an
acknowledged resolution can contribute to later signed prefix retirement.

Independent session closure is `Open → Pending(report) → Closed(report)`. It
freezes ordinary work and incomplete rekeys; complete host loss accounting precedes
the terminal commit. The terminal record keeps source/session identity, claims,
report correlation and required outcome metadata without private session state.
Neither close nor drop alone acknowledges a report. Expired operational authority
can use the separately authenticated original archive/recovery owner, with the
same witness requirements. Ordinary operational APIs cannot revive the session.

Account fanout derives the exact required recipient set from the installed signed
roster. `Absent → Reserved → Committed` reserves every member input and later
commits every chain/outbox in one device-journal transaction. The roster/account,
recipient devices/generations, sessions, IDs and shared input must all agree.
No member output escapes before the whole aggregate's commit and release admission.
Reserved aggregate members cannot escape through unary send/resume APIs.

Per-recipient `Committed`, `Acknowledged`, `ResolutionPending`, `DeliveryUnknown`,
`HistoryRetired` and `ReservationAbandoned` remain distinct. `HistoryRetired` does
not recover the old distinction between peer consumption and accounted unknown
delivery. Retiring aggregate metadata keeps the monotonic fanout ordinal and
source/session tombstones. This is not an atomic transaction among independent
sending-device journals or remote application databases.

Reserved fanout abandonment is `Reserved → Abandoning(report) →
Abandoned(report)`: it freezes every member session, requires one complete host
report, then installs every member's terminal state together. It cannot split the
set or cancel an already committed batch. Archive-based recovery verifies every
original member scope before mutation; no missing witness becomes local fallback.

## Errors, cancellation and adapter obligations

An error code alone does not tell whether a peer or storage transaction committed.
An adapter must preserve both the typed error and the original operation identity.
There is no universal `retryable` bit or `error means not sent` conversion.

| Result family | Required caller behavior |
| --- | --- |
| `CommitUncertain`, storage/write failure, witness error | Discard the closed owner where required, reopen the same installation/journal and reconcile its exact intent/operation; no implicit initialization |
| `Suspended` | Preserve the existing operation and required original owners; do not invent new work or report success |
| `Absent` / `MessageStatus::Absent` | Accept only from a successful authenticated lookup; distinguish an absent source operation from an absent message in an existing session |
| `Conflict`, `Rejected`, `PrekeyClaimed`, `KeyRetired`, protocol retirement | Keep the definitive distinction; do not retry under a replacement ID or treat as cache miss |
| `Capacity`, `RekeyRequired` | Respect backpressure; perform only the separately authorized reconciliation/control/cleanup that applies |
| Authentication, scope, policy/runtime, expiry or malformed state failure | Return the failure; do not weaken mode, replace trust pins, substitute time or reset state |
| Transport cancellation, deadline, exhausted attempts, I/O failure | Local and peer work may have committed; retain exact ID/bytes and query the original journal |
| Host application error or unknown external commit | Do not consume/ACK the inbox; reconcile the host's own deduplicated transaction |

Some pre-admission capacity/input errors leave the owner usable; errors during
image load/persist/release can close it. Bindings must follow the actual owner
state, not guess lifetime from the display text. `Cancellation` is one-way and
cannot be reset. It stops further dispatch at the documented network bounds; it
does not cancel an arbitrary synchronous filesystem call or roll back a commit.

Binding review must check every operation's output-buffer lifetime, ownership,
close/concurrent-call behavior, error origin and exact query/reconciliation method.
No FFI handle, callback success, queued application job or copied status snapshot
can replace an authenticated commit. A future numeric ABI must specify these
distinctions explicitly before its export/registration allowlists are frozen.

## Implementation correspondence and remaining proof

The source of the phase inventory and journal transitions is
[`durable.rs`](../../research/continuity-identity-candidate/src/durable.rs),
[`initiator.rs`](../../research/continuity-identity-candidate/src/durable/initiator.rs)
and [`responder.rs`](../../research/continuity-identity-candidate/src/durable/responder.rs).
Messages and rekeys use
[`messages.rs`](../../research/continuity-identity-candidate/src/durable/messages.rs),
[`progress.rs`](../../research/continuity-identity-candidate/src/durable/messages/progress.rs)
and [`completion.rs`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs).
Closure, fanout and their archives share that same aggregate owner.

The existing
[send-budget regressions](../../research/continuity-identity-candidate/src/durable/messages/tests/send_budget.rs),
[resolution crash tests](../../research/continuity-identity-candidate/src/durable/messages/tests/epoch_resolution.rs),
[exact-write recovery tests](../../research/continuity-identity-candidate/src/durable/write_intent/tests.rs)
and [public installed workload](../../research/continuity-identity-candidate/tests/owned_connection.rs)
exercise named parts of these transitions. Their passing finite executions do not
establish exhaustive interleaving coverage, a language-binding contract already
implemented, or a computational security proof. Full lifecycle renewal, independent
endpoints, product scheduling/budgets and construction analysis remain open.

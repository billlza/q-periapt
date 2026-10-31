# Owned request/reply session exchange candidate

Status: implemented candidate adapter, not frozen or a new PCS claim. It reuses
the existing bootstrap, session archive, message chains and acknowledgement MAC.
It is intended to connect the browser owner to native consumers without granting
the carrier signing authority or treating an HTTP response as peer confirmation.
Installed browser/native establishment and data recovery are qualified in
`../sdk-alpha1/evidence/20261013-browser-owned-sessions`. Control delivery has
separate validation and does not inherit those results automatically.

## Authority and ownership

The caller first verifies the original public bootstrap bundle against independent
account roots, exact devices/generations, roster heads, directory expectation,
quality and the existing policy/runtime. `DeviceService::admit_peer` checks that
context against the original enrolled installation. Retaining the resulting
descriptor does not extend policy, roster, witness or credential authority.

`EnrolledDevice` owns each operation. No key, raw signing handle or storage lease
is passed to the carrier. The invocation samples the trusted wall clock at each
engine/carrier release boundary and retains a finite monotonic deadline. Carrier
implementations must enforce that deadline and cancellation while awaiting I/O.
There are no implicit retries. A failed or dropped polled operation closes the
enrolled owner, including its service and signer. Reopen the same installation
and reconcile the original initiation/message ID; an error never proves rollback.

## Framing and establishment

Each frame is `QPCXCH01 || kind:u8 || body`, with a total maximum of 32,768 bytes.
The distinct tag prevents reinterpretation as the TLS-bound `QPCNET02` carrier
or its legacy `QPCNET01` version.
A pair is `first_length:u16be || first || second`, bounded by the enclosing frame.

| Kind | Body |
| --- | --- |
| 1 INITIAL | Existing signed bootstrap initial flight |
| 129 REPLY | Existing signed bootstrap response flight |
| 2 FINAL | Pair of the original initial and final flights |
| 130 READY | Pair of the 32-byte session ID and epoch-zero acknowledgement |
| 3 MESSAGE | Pair of original associated data and existing message ciphertext |
| 131 ACK | Existing authenticated consumption acknowledgement |
| 4 CONTROL | Existing signed request/offer/response/final/receipt, at most 8192 bytes |
| 132 CONTROL_REPLY | `1 || signed_control`, or exactly `0` for no further flight |

The initiator commits its original contribution, accepts the authenticated reply,
and retains the exact closure archive before sending FINAL. The responder
authenticates and commits FINAL, retains its archive and activates its original
message state. It then returns the session ID and the existing epoch-zero
acknowledgement MAC. The initiator checks the exact ID and epoch, activates its
own state, requires the archive and authenticates that acknowledgement before
returning a `Session`. A public session ID or carrier success alone is rejected.

The acknowledgement is a replayable proof concerning this original session. It
does not prove current peer availability, fresh remote authorization, physical
erasure, or any application effect. Epoch-zero acknowledgement retention also
limits how long establishment itself can be replayed: established sessions should
use the authenticated reopen path after traffic/epoch history has advanced.

## Delivery and recovery

`next_session_message_id` observes the original journal sequence. Sending checks
the original archive and reuses the existing reserve/commit/release path; retries
with changed input under an active ID conflict. `session_message_status` reports
the original ID after uncertain outcomes. Once consumed history is erased, that
status cannot authenticate replacement plaintext, and send does not pretend it can.

The receiver commits an authenticated inbox before invoking the host consumer.
The host must durably commit its effect and deduplication record together. Only
its successful return allows journal consumption and an acknowledgement. If the
effect outcome is unknown, the host returns failure and may receive the same ID
again. This is not a claim of atomicity across arbitrary host effects and the SDK.

Consumed duplicates do not invoke the consumer again. Below the erased receive
prefix the result only describes prior consumption of that ID; it does not
authenticate newly substituted bytes. The sender verifies the exact message
epoch, session and peer MAC. An authenticated prefix that does not include the
message returns `PrefixPending`, never `Confirmed`.

Reopening uses independently authenticated original bundle inputs and the same
installation/archive. Both traffic directions use the same controlled message
engine. Root/roster renewal, deployment, independent implementation interoperability and
the whole 0.2.0 goal require separate integration and evidence.

## Explicit rekey delivery

`drive_session_rekey` starts or resumes one retained target with an explicit
request allowance from 1 through 128. It reuses the original signed control
state machine, signer, archive and journal; no dummy application payload is
required. The same monotonic deadline covers all requests. Network failures
return immediately without implicit retry. Exhaustion returns `ExchangeLimit`
and closes the owner, retaining the target and original outboxes for reopen.

Both proposer and non-proposer roles work through the same API. A responder
which already committed its receipt before losing the carrier result dispatches
that exact receipt again. The receiver must remain available after local
completion to serve repeated final/receipt messages. A signed response for a
different target is refused before it can satisfy this invocation.

The carrier's `0` reply is unauthenticated metadata. It may conclude an invocation
only when the local journal already establishes completion of that exact target.
It cannot establish receipt at the other endpoint. `RekeyCompleted` reports the
local epoch and attempted exchanges only. A completed target can therefore
return without a fresh remote exchange. `session_rekey_progress` exposes local
confirmed/sending/receiving/pending epochs; none describes attacker knowledge or
proves post-compromise secrecy recovery.

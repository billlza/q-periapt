# Candidate application-send progress budget

Status: implementation contract for the 0.2.0 Continuity candidate. The current
v4 implementation does not enforce this budget. This document neither freezes
the full product profile nor establishes a recovery guarantee. It resolves the
counter/authority rule needed before implementing the governor and scheduler.

## Authenticated parameter and admission

The policy authority must sign an explicit nonzero `u16` application-send budget
`B`. There is no unsigned runtime override, disabled sentinel or default budget.
The exact value is part of the pinned session-policy body and bootstrap context;
a new policy/checkpoint cannot reinterpret a retained session's counters. A
product profile still needs a measured, selected value. Values used by fixtures
or comparison experiments do not become product defaults.

The planned canonical policy body is the current body with tag `QPSESP03` and
an appended big-endian `B:u16`: 200 bytes. Zero is rejected, including in a policy
that disables new bootstrap modes. The policy digest covers the complete body.
The signed rekey profile must advance to a distinct version binding
`application-send-budget/v1`; older profile/policy tags are refused, without
fallback or a silent counter reset. No primitive KAT, SDK KEM contract or ABI 2
entry changes its meaning.

Only a verified policy can supply this value to message admission. A proposed
`ApplicationSendBudget` constructor validates explicit issuer input, and
`SessionPolicyParameters` must require it. It cannot be reconstructed from a peer
assertion or an application-supplied remaining-count field.

## Exact counter rule

Let `c` be the locally completed rekey epoch and `s` the current sending epoch.
The existing validated control state permits `s = c` or `s = c + 1` while final
output is committed but its receipt has not been accepted. Define

`spent = sum(traffic[e].sent for e in c..=s)`.

The pending send reservation in epoch `s`, if present, occupies one additional
slot. Its exact input may resume that slot; a replacement input or new ID does
not obtain another slot. The application-visible remaining count is therefore
`B - spent - pending_slot`. Invalid stored counts or checked arithmetic failures
must fail admission, rather than saturating to a plausible progress value.

The governor denies a new reservation once `spent == B`. It checks before
persisting plaintext or reserving new work, including callers that construct a
message ID without using `next_message_id`. Exact committed outbox replay and
recovery of an already admitted pending input remain available under current
policy, roster and witness authority. There is no new-entropy retry of an
unknown commit.

ACK acceptance, plaintext consumption, explicit closed-epoch resolution, owner
reopen and witness reconciliation do not refund application-send slots. The
counter uses committed send totals, not retained outbox lengths or ACK floors.
Preparing an offer, response or final also does not reset it. In particular,
installing the proposer's new sending keys before receipt acceptance must not
grant a second budget while the exchange remains incomplete.

On actual local completion of the signed rekey, `c` advances. Messages already
committed under that new sending epoch still count against its budget. For
example, with `B = 3`, one old-epoch send plus two sends after final exhausts the
window until receipt acceptance. After that acceptance, the two new-epoch sends
remain spent, leaving one slot. If three old sends exhausted the window before
final, new application sends wait for receipt while exact control output stays
dispatchable. These examples are counter semantics, not a selected product `B`.

A receiver additionally rejects an epoch-local application index outside the
signed per-epoch bound before advancing traffic state. This does not assert
knowledge of the sender's private confirmation state. Existing cryptographic,
reordering, capacity, revocation and authority checks still apply.

## Control liveness and observability

Budget exhaustion needs a distinct `RekeyRequired` outcome, separate from storage
capacity, invalid input, revoked authority and an unknown commit. A progress
query may report the completed/sending epochs, signed limit, spent count,
reserved slot and remaining count. Like other read-only reconciliation queries,
those values do not grant permission to send after expiry, close or revocation,
and do not claim that the adversary lacks the installed keys.

Control traffic must run without dummy application messages and without consuming
this application budget. The four existing rekey flights alone do not define
the service scheduler. In particular, the non-proposing endpoint needs an
authenticated way to request control progress when the other endpoint is idle.
That trigger, its exact durable outbox/retry semantics, bounded resource usage
and interaction with pending old-history resolution remain implementation work.
Loss of control delivery can suspend application progress; it cannot authorize
reset, skipped confirmation, plaintext release or a weaker profile.

## Required implementation evidence

- Both directions enforce a small signed fixture budget through real journal
  sends, ACKs, restart and independently constructed IDs; counters change only at
  their specified transaction boundaries.
- A last-slot reservation interrupted at each measured sync barrier resumes the
  exact input once. Failed writes return no output; retry does not refund or spend
  a second slot. Owner/process loss and concurrent writers retain this invariant.
- Early final, delayed/lost receipt, duplicate control output and asymmetric
  confirmation exercise the `c..=s` window, including the two examples above.
- Old-epoch resolution, consumption and ACKs preserve spending. Revocation,
  expiry and required-witness failures cannot be converted into budget recovery.
- Real signed policy fixtures and an independent public parser cover the new
  field, zero rejection, exact checkpoint binding and earlier-profile rejection.
- A control-only scheduler trace covers one-way traffic, an idle peer, loss,
  cancellation, duplicates and budget exhaustion before product integration.
- Matched full-profile measurements retain actual durable writes, control bytes,
  latency and workload/security assumptions before choosing the product value.

The reservation-disclosure experiment still applies: a completed rekey can use
entropy exposed before computation. This governor bounds application work between
observable protocol completions; construction-specific recovery conditions must
separately account for that entropy ancestry, identity/RNG compromise and access
to later encrypted journal state.

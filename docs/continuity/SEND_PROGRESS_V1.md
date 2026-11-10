# Candidate application-send progress budget

Status: application governor implemented since the isolated v5 candidate. The
v6 candidate adds signed requests and explicit-target control steps; the product
transport scheduler and a measured product budget remain required.
This document neither freezes the full product profile nor establishes a recovery
guarantee.

## Authenticated parameter and admission

The policy authority must sign an explicit nonzero `u16` application-send budget
`B`. There is no unsigned runtime override, disabled sentinel or default budget.
The exact value is part of the pinned session-policy body and bootstrap context;
a new policy/checkpoint cannot reinterpret a retained session's counters. A
product profile still needs a measured, selected value. Values used by fixtures
or comparison experiments do not become product defaults.

The canonical policy body is the current body with tag `QPSESP03` and
an appended big-endian `B:u16`: 200 bytes. Zero is rejected, including in a policy
that disables new bootstrap modes. The policy digest covers the complete body.
The signed rekey profile binds
`application-send-budget/v1`; older profile/policy tags are refused, without
fallback or a silent counter reset. No primitive KAT, SDK KEM contract or ABI 2
entry changes its meaning.

Only a verified policy supplies this value to message admission. The
`ApplicationSendBudget` constructor validates explicit issuer input, and
`SessionPolicyParameters` requires it. It cannot be reconstructed from a peer
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

Budget exhaustion returns a distinct `RekeyRequired` outcome, separate from storage
capacity, invalid input, revoked authority and an unknown commit. The `application_send_progress`
query reports the completed/sending epochs, signed limit, spent count,
reserved slot and remaining count. Like other read-only reconciliation queries,
those values do not grant permission to send after expiry, close or revocation,
and do not claim that the adversary lacks the installed keys.

Control traffic must run without dummy application messages and without consuming
this application budget. The four existing rekey flights alone do not define
the service scheduler. In particular, the non-proposing endpoint needs an
authenticated way to request control progress when the other endpoint is idle.
The [v6 control path](../../research/continuity-identity-candidate/CONTROL_PROGRESS.md)
now implements that authenticated trigger, durable reservation/outbox and
explicit-target steps. Product transport scheduling, retry policy and matched
resource measurements remain required.
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

The current implementation also bounds every retained sent/received/peer-close
count and the close counts in cached final/receipt plans and transcripts. It
rejects an excessive signed peer count before reserving a local signature. State
records were `QPMST008`/`QPTEPO03` in the v5 qualification below. The v6 control
request extends message state to `QPMST009`; traffic remains `QPTEPO03`. The
budget comes from the exact verified
policy instead of a caller-replaceable checkpoint field. Earlier policy bodies
are rejected without resetting the existing journal.

## Local qualification

The 2026-09-29 final run passes 161 release tests in 236.98 seconds, with no
ignored tests or compiler warnings. Eight budget-focused tests cover explicit
policy issuance and legacy rejection, both sending directions and direct IDs,
ACK/restart persistence, the old/new confirmation window, pending input on both
sides of receipt acceptance, authenticated excessive frames, invalid restored
counts and validly signed excessive peer close counts. Actual last-slot storage
measurements expose nine barriers for role 1 and eight for role 2; all 34
before/after fault cases recover exactly. Two process kills retain the last-slot
reservation. The required-witness trace also loses the final send-release reply
and receipt-acceptance reply, then reconciles the correct spending after reopen.
These cases do not yet qualify a service scheduler or a full multi-writer workload.

The first full run has 160 passes and one retained failure: the crash parent saw
the stage-marker filename after creation but before its content was written.
The test helper now writes/synchronizes a private temporary marker and publishes
the completed marker by rename before the parent may kill the child. No protocol
assertion, fault case or deadline is weakened. The final full run includes both
real reservation-disclosure counterexamples again.

Strict all-target Clippy and formatting pass on Rust 1.98.1; locked all-target
compilation passes on Rust 1.90. The 45 standalone candidate-isolation and Rust
inventory checks pass for 185 tracked Rust files. Independent OpenSSL/public
parsing verifies 19 envelopes, 30 Merkle proofs, nine selections and 95 signature
negative controls, including the new policy/profile bytes; the witness oracle
verifies 12 envelopes and 60 signature negatives. Public parsing does not test
secret MAC/AEAD correctness; the journal regressions exercise those operations.

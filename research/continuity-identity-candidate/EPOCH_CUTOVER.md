# Epoch cutover and old-chain state poisoning

Status: executed counterexample and implementation requirements for the complete
0.2.0 ratchet. This is not an implemented epoch transition or a frozen profile.
The signed [offer and response](REKEY_OFFERS.md) retain a pending hybrid root;
the actual API still installs no epoch beyond zero.

## Executed trace

`disclosed_old_chain_can_poison_retention_across_restart_and_key_only_replacement`
uses the actual encrypted journals, message AEAD, consumption API and rekey
offer/response paths. Before the first honest application send, it discloses one
initial receiving-chain key. A separate attacker function receives only that key
and the public session ID. It computes all eight forged packets before either
honest journal is accessed again. It receives no identity, root, acknowledgement,
storage or later KEM secret, and no later honest entropy.

The receiver authenticates and commits those eight frames. The test application
consumes them through the real API. The journal then has receive index and
consumption floor eight, no remaining inbox or skipped entries, while the honest
sender's next index is still zero. Reopening the receiver retains floor eight.
The honest sender's first actual outbox is consequently rejected as `Retired`.

Both honest devices can still produce a valid identity-authenticated rekey offer
and response. This control evidence does not change the current traffic floor.
The test then creates **isolated in-memory candidate state** that replaces only
the traffic keys with matching fresh platform-random material. A direct AEAD
check accepts the new packet under its new key. Normal message processing rejects
it at the retired-ID guard, before consulting that key. No altered candidate
state is written to either real journal.

Observed output:

```text
OLD_CHAIN_RETENTION_POISON forged=8 honest_sent_before=0 persisted_floor=8 actual_honest_receive=retired signed_rekey_response=valid isolated_fresh_aead=valid key_only_candidate_receive=retired
```

This does not contradict the initial epoch's stated lack of compromise recovery.
It rules out a key-replacement-only extension of that implementation. It is also
distinct from the whole-KEM active-fork experiment: interference here is finite,
device identity keys remain undisclosed, and the resulting damage survives
restart without requiring the attacker to substitute a new ratchet key.

The test does not undo application effects already caused by accepted old-key
forgeries. Recovery cannot retroactively restore their authenticity. It does not
claim that a complete epoch-aware construction has been implemented or proved.

## Required epoch representation

The permanent logical session and its device/policy/roster bindings must survive
rekeying. Epoch transitions are contiguous, transcript-bound changes within that
session, not fresh bootstrap or a rollback/recovery reset. They require a distinct
traffic namespace under the new root:

- Each message ID binds logical session, direction, **key epoch and index**.
  The full tuple never repeats. An index from an old epoch cannot identify a new
  send, even after its old receipt is removed. Counters advance within an epoch;
  starting a different authenticated epoch does not recreate an old ID or key.
- Send and receive chains, skipped keys, consumption floors and receipt lookup
  are scoped to their own epoch. A receiver's poisoned old floor cannot retire,
  skip or otherwise authenticate a new-epoch packet.
- An ACK authenticates its exact epoch and can retire only that epoch's outboxes.
  Neither an old ACK key nor an old numerical floor can affect new traffic.
- Old records remain bounded and separately addressable. New-epoch admission
  cannot reinterpret their indices. Retention, explicit consumption and exact
  replay continue to apply; secret-key replacement cannot silently clear them.
- An authenticated close count describes the honest sender's old epoch. It may
  be lower than the receiver's observed old index after a disclosure. That
  difference is not permission to reject all future fresh-epoch work, invent
  peer consumption, replay old application effects or discard old records without
  a defined observable transition.

These requirements replace the idea of carrying one global consumption floor
unchanged across key epochs. They retain the stronger requirement that an old
operation ID can never become new work. Product crypto KATs, implicit rejection,
device-generation monotonicity and ABI major 2 remain unchanged.

## Control ordering to implement

The pending response alone must not switch the application to an unconfirmed
epoch. The next implementation must bind proposer and responder cutovers to the
same authenticated offer/response transcript and newly derived root. A final
proposer confirmation and exact responder completion receipt can separate the
two local switch times while ordinary old-epoch traffic continues in the interim.
Any new-epoch data arriving ahead of its required control evidence must remain
retryable without consuming keys or modifying the journal.

Each local switch must atomically commit its control outbox, new traffic/ACK
owners, retained old-epoch state and epoch identifiers before releasing bytes.
An unresolved old send reservation must be completed from its retained input;
it cannot be silently rebuilt under a new epoch. Lost control output replays exact
bytes. A later rekey must retain the previous completion receipt until the peer
can advance, rather than overwriting the only recoverable copy.

The numeric history and pending-work bounds, acknowledgement retirement rules,
authenticated progress budget and control scheduler remain part of the unfrozen
profile. Bounds may produce explicit backpressure. They must not be satisfied by
unreported old-epoch data loss or by replacing required new-epoch validation.

## Required acceptance cases

The implemented transition must accept valid new-epoch traffic after the trace
above while still rejecting old-ID reuse. It must preserve delayed old ciphertext
and plaintext handling, reject old-key ACKs against new outboxes, handle asymmetric
application traffic and control-only replies, and preserve both directions across
restart and uncertain commits. Every cutover phase needs actual process-loss and
witness-release verification. Message counters, source-bound packet hashes and
actual key agreement must remain observable in the tests without exporting live
application secrets.

The [Double Ratchet discussion of out-of-order messages](https://signal.org/docs/specifications/doubleratchet/#out-of-order-messages)
uses per-chain counters and previous-chain lengths; its
[SPQR epoch-state discussion](https://signal.org/docs/specifications/doubleratchet/#clearing-past-epoch-state)
also scopes retained chains by epoch. These are relevant design precedents, not a
security proof for this candidate's custom persistence and identity composition.

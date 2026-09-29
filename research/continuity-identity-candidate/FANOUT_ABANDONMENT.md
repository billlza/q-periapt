# Explicit abandonment of reserved account sends

Status: unpublished candidate implementation; current qualification is recorded
below. This operation closes every pairwise session in one **reserved** batch.
It does not cancel a committed batch, remotely revoke a peer, rotate an account
root, migrate an old journal or reenroll a replacement device.

## Why a reservation cannot simply be cleared

A process can die after producing one real ciphertext but before the aggregate
commit. The durable state still says Reserved. Clearing that input and accepting a
new plaintext in the same slot would reuse its chain-derived key and AEAD nonce.
The test `account_fanout_unsafe_reservation_reset_reuses_the_actual_message_keystream`
kills a real producer after its first ciphertext computation, captures those
bytes, and shows the plaintext-XOR/ciphertext-XOR equality after an isolated unsafe
reset of private test state. The shipping API refuses the replacement. This is
an unsafe-composition counterexample, not a claim of an API vulnerability in v18.

The safe operation closes the whole session permanently. It does not roll back a
sequence, advance the chain with an invented message, refund its progress budget
or treat an uncertain outcome as a successful delivery.

## Two explicit aggregate transitions

`begin_fanout_abandonment(id, original_targets)` accepts a Reserved batch. It
checks every original context, session, credential, role, owner and policy
protection binding, with no subset or replacement. The same exact targets may
be supplied in a different order. It commits all member records as
MessagesAbandoning and the batch as FanoutAbandoning together. Retrying that phase
returns the same immutable report. Committed and Abandoned batches are refused.
There is no unfreeze operation.

Freeze blocks all data, ACK and control mutations/releases, as well as cached
initial/reply/final bootstrap releases and repeat activation for each exact source.
Unrelated sessions retain their ordinary behavior. Read-only status does not grant
permission to send. Whole-batch resume cannot bypass these fences.

The metadata-only report accounts for all work in those sessions, not just this
batch: reserved IDs and lengths; rekey progress; every retained epoch's sent,
acknowledged, received and consumed counts; signed peer close counts when known;
previous closed-epoch accounting IDs; unknown ciphertext identities; unconsumed
inbox IDs and lengths; observed skipped indices. It returns no plaintext,
associated-data content, plaintext hash, chain key or control reservation.
Previously acknowledged prefixes remain acknowledged; unresolved committed sends
remain unknown. Unseen messages are not invented. Reporting a local observation
does not certify that a compromised peer's message was authentic.

The application must durably record **all** unknown/lost outcomes and deduplicate
its external transaction by the exact report ID before calling
`acknowledge_fanout_abandonment`. The library cannot make that external transaction
atomic. A crash after external commit is recovered by replaying the same report
and acknowledgement, without repeating application effects.

Acknowledgement atomically replaces every frozen private State with a keyless
terminal record and removes the private report key from the batch. Exact repeated
acknowledgement is idempotent; a different report ID conflicts. The terminal
outgoing status distinguishes ReservationAbandoned, DeliveryUnknown and the old
authenticated ACK prefix. Earlier epoch history remains Retired. Future absent IDs
never authorize work on a terminal session. Bootstrap sources remain public-only
history with their transferred root already zeroed; their source-linked fence
prevents replay or root reactivation.

`retire_fanout` can remove acknowledged terminal batch metadata. Each session's
self-contained terminal record stays, as do its bootstrap/one-time claims. The
journal's monotonic batch counter never decreases. Other retained committed fanout records keep their sealed input-intent commitments
until their separate metadata retirement; this operation does not rewrite unrelated
batches. The normal operation/image bounds still apply; this is not unlimited reclamation of terminal session slots.
Fresh, independently admitted bootstrap sessions obtain new IDs and keys.

## Authority, crashes and privacy

Peer revocation, credential expiry and policy close must not prevent local loss
accounting. Cleanup therefore checks original scope and stored protection rather
than granting fresh peer authority. It releases only metadata and destroys local
authority. Required-witness journals still require their original witness for
readback, both commits and final release; no local-only fallback exists. Witness
or storage errors close the owner and use exact sealed write-intent reconciliation.

A fresh private 32-byte HMAC key is sampled at freeze. The report ID authenticates
the journal identity and owner, canonical batch metadata and length-delimited full
private member states, including all pending bytes, counters and control work.
These private states cannot change after freeze. The ID is not a public dictionary
verifier for low-entropy plaintext. The key remains sealed only while the report
is pending and is removed upon acknowledgement.

The freeze does not add a record or enlarge the encoded image. Every new batch
already reserves a 64-byte tail before application cryptography. Terminal session
encoding must be no larger than its former State; the code checks this before
persisting. Cleanup therefore does not need an extra slot when all 16 batches,
128 operations or the aggregate image capacity are occupied. Actual tests exercise
the full batch bound and encoded-size equality; the other limits follow from the
same unchanged record count and nonincreasing payload lengths.

Erasure here means the **current logical image** and its owned values. It does not
claim secure deletion of historical redb pages, write-intent history, storage
snapshots, copied wrapping keys, backups or plaintext retained by the application.
Local-only protection still cannot resist whole-store rollback; required witnesses
retain their existing rollback and availability assumptions.

## Storage contract

Journal v19: `continuity_device_candidate_v19`, `QPVLT019`, `QPVIMG19`. Older
candidate images fail closed with no reset or implicit migration. Pairwise v6,
QPSESP03, QPMST010, QPTEPO04, KATs and published SDK/binding ABIs are unchanged.

QPFANO02 keeps canonical sorted members and uses a fixed 64-byte tail:

| Phase | Tail | Member phase |
| --- | --- | --- |
| 21 Reserved | private input intent[32], canonical zero[32] | 19 Messages |
| 22 Committed | private input intent[32], canonical zero[32] | live, frozen or terminal history |
| 25 Abandoning | report ID[32], private HMAC key[32] | 23 MessagesAbandoning |
| 26 Abandoned | report ID[32], canonical zero[32] | 24 MessagesAbandoned |

The message pending-plan reverse link must match its Reserved or Abandoning batch.
An orphan, split phase or changed frozen state is corrupt. A historical committed
batch may reference a later closed session, but cannot relabel its uncommitted
reservation as a committed message.

A terminal payload is canonical and contains no trailing bytes:

`QPABND01[8] || source[32] || session[32] || batch[32] || report[32] || pending_message[32] || role:u8 || confirmed:u64 || sending:u64 || receiving:u64 || pending_control:option<u64> || count:u8 || counts`.

The option uses 0 or 1 followed by a u64 only for 1. Each retained epoch is
`epoch:u64 || sent:u64 || acknowledged:u64`. Epochs are consecutive and bounded by
the existing four-epoch window. The pending ID is bound to the terminal session,
role, sending epoch and unchanged uncommitted slot. Shared source validation still
recomputes the session ID from the admitted final bootstrap transcript.

## Qualification boundary

The test cohort covers native journal behavior on one macOS ARM64 host. Separate
producer processes are actually killed at ciphertext computation, freeze and
terminal commit. Competing processes must return Busy within a deadline. Storage
faults are injected before and after every measured barrier, and signed witness
responses are lost before and after every measured exchange. These observations
cannot qualify installed foreign-language clients, cross-host or physical-device
behavior, a complete protocol security proof, or the remaining 0.2.0 release gates.

Current macOS ARM64 validation passes **192 tests each** in debug and release,
with zero failures or ignored tests. Runner times are 503.38 and
350.78 seconds; overlapping runs are not a controlled performance comparison.
Six added regression tests include the actual keystream counterexample, two terminal
process cuts with bounded competing writers, revocation plus unconsumed/unknown
accounting, fresh-session delivery, full batch capacity, **18** before/after storage
faults across the observed four freeze and five finalization barriers, and **16**
before/after losses across four signed witness exchanges per transition.
Rust 1.90 and 1.98.1 strict all-target/all-feature Clippy, no-default compilation,
formatting, warning-strict docs and 45 clean source/isolation checks pass. The
tracked source inventory is 201 Rust files. The initial unsafe-reset test omitted
the replacement reservation required by the primitive and failed with State; its
corrected isolated composition installs that replacement and reproduces the
keystream equality. The source gate also caught the stale documented inventory
count; the guide was corrected. Both initial failures remain in the evidence.

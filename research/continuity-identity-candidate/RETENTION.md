# Consumption acknowledgements and bounded message retention

The candidate's previous 64-receipt limit bounded total session traffic. Simply
removing old random IDs would have allowed an old request to be treated as new.
Message profile v2 instead uses session-scoped sequence IDs and monotonic
consumption floors. The 64-entry bound now applies to outstanding records.
No SDK binding or ABI export depends on this candidate. ABI major stays 2.

## Application contract

1. Read `next_message_id` and retain that ID before submitting plaintext to
   `send_message`. Reading a slot is not a reservation: concurrent readers can see
   the same ID. The first durable input reservation wins; different input conflicts.
2. Receive authenticated `CommittedPlaintext`, durably deduplicate the application's
   own external effects by session and message ID, then call `consume_message`.
   The call commits consumption and removes retained plaintext. It cannot make an
   external application transaction atomic with this separate journal.
3. `message_acknowledgement` returns the currently committed contiguous consumed
   prefix. Send it explicitly to the peer. This is not automatic telemetry; its
   cleartext counter reveals application-consumption progress and cadence.
4. The sender calls `accept_message_acknowledgement`, which verifies its MAC and
   atomically retires the corresponding ciphertext outboxes. `message_status` then
   returns `Acknowledged`. Sending or resuming a retired ID returns `Retired`;
   the old slot never becomes an absent/new request.

Out-of-order consumption erases that message's plaintext immediately and retains
only its index, commitment and consumed marker. A missing earlier delivery keeps
the cumulative floor behind the gap. The sender retains that missing message's
outbox for retransmission. There is no timeout-based skipping, silent loss,
unbounded tombstone set, probabilistic duplicate filter or automatic new-session
reset. A full outstanding window explicitly applies backpressure.

After a lost acknowledgement or restart, the receiver can recompute its current
MAC without a fresh message key or nonce. A valid old acknowledgement is harmless:
it cannot lower the sender floor or restore an outbox. All output, including
recomputed acknowledgements and cached messages, checks current policy/device
validity and any required fresh witness evidence. Read-only outgoing status does
not grant permission to release a message after policy close or expiry.

## Closed bytes and cryptography

Application messages use `QPCMSG02` and the domain
`Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/` (`D` below). The header layout remains
93 bytes and accepts only epoch zero. Profile v1 frames are rejected; there is no
implicit fallback. The initial HKDF in [MESSAGES.md](MESSAGES.md) now emits 160
bytes: rekey seed, initiator-send chain, responder-send chain, acknowledgement key
for initiator messages, acknowledgement key for responder messages (32 bytes each).
The acknowledgement keys are separate from traffic keys and from each other.

`MessageId` is exactly `index:u64 || binding[24]`, where `binding` is the first
24 bytes of the repository's length-delimited SHA3-256 digest using domain
`D || "message-id"` and body `session_id[32] || direction:u8 || index:u64`.
Indices are unsigned big endian, start at zero and never reset. The decoder and
send boundary require the exact session/direction binding, and the network header
index must equal the ID's index. Public ID bytes are not an authorization secret.
Callers recover retained IDs with `from_trusted_state`; there is no random-ID
constructor for this protocol.

An acknowledgement is exactly 81 bytes:

`"QPCMACK1"[8] || session_id[32] || acknowledged_direction:u8 || consumed_floor:u64 || tag[32]`

The tag is HMAC-SHA-256 with the direction's acknowledgement key, over
`D || "acknowledgement" || first_49_bytes`. The receiver signs the direction it
receives; the sender verifies its sending direction. Length, tag, session,
direction and the bound `floor <= sent_count` are checked. Zero is a valid floor
when a gap prevents contiguous progress. The MAC authenticates the peer's
consumption claim; it cannot prove an honest application acted outside the SDK.

## State invariants and recovery

Let `S` be the next send index, `Fs` the authenticated peer consumption floor,
`R` the next receive-chain index and `Fr` the local contiguous consumption floor.
The admission checks enforce:

- `0 <= Fs <= S`; outboxes contain exactly the indices `[Fs, S)`.
- `0 <= Fr <= R`; skipped keys and inbox records are disjoint and together cover
  `[Fr, R)`. A consumed record retains no plaintext.
- A consumed record at `Fr` cannot remain stored: consumption advances over the
  complete contiguous consumed prefix and removes those records.
- Every pending send uses the single ID for index `S`; it cannot replace a live
  outbox. Retired IDs are recognized from the floor even after all their bytes
  are removed. A future index cannot skip the current send slot.
- Floors and chain counters only advance, within `u64`. Exhaustion explicitly
  ends admission; no counter wrap or restart recreates an old ID/message key.

These are implementation invariants and reasoning obligations, not a mechanized
security proof. They close the bounded-ID replay problem independently of the
future DH/PQ update construction. They still rely on the chosen rollback profile:
restoring a whole local-only database can restore old counters, whereas required
witness journals must reconcile against the independently protected witness head.

Consumption and acknowledgement application each use one existing exact-intent
journal persist: the same crash reconciliation, atomic image installation and
post-commit release checks apply. Journal schema v9 uses
`continuity_device_candidate_v9`, `QPVLT009`, `QPVIMG09` and message state
`QPMST002`. Old v1–v8 journals are rejected without reset or implicit migration.
Logical plaintext/key removal does not erase old encrypted pages, intents,
snapshots or backups. Fresh-PQ/DH recovery, rekey-aware acknowledgement keys,
revocation/fanout integration and physical erasure remain required work.

# Durable epoch-scoped messages

This candidate now carries application plaintext through both real bootstrap
roles and their encrypted device journals. It now includes an initial epoch and bounded, identity-authenticated hybrid rekeys.
The complete continuous-PQ profile and product integration remain unfinished.
No SDK, C export or language binding depends on this unpublished workspace.
ABI major remains 2. The full 0.2.0 scope is unchanged.

## Ownership and release

`activate_initiator_messages` requires `FinalCommitted`;
`activate_responder_messages` requires `Complete`. The initiator must dispatch its
already committed final bootstrap flight before application frames. Activation
atomically replaces the stored bootstrap root with a retired-root marker and zero
placeholder, and installs the directional chains in a new linked message record.
Repeated activation returns the existing session. Initial/reply/final outbox replay
continues from the public transcript without reconstructing the retired root.

`next_message_id` supplies the session/direction/epoch-scoped send slot. Retain it before calling
`send_message` with plaintext and application
associated data. It first commits the exact input as a sealed pending command.
Only then does it derive the next message key and encrypt. The next chain seed,
exact ciphertext outbox and removal of the command commit together. No ciphertext
is returned before that commit and the required fresh witness release query.
An uncertain commit closes the journal; reopening reconciles the exact write
intent. A retained ID with different input fails. A pending command blocks
replacement sends. `resume_message` continues its sealed input using only the
retained ID; `message_status` performs read-only absent/reserved/committed
reconciliation even after policy close or expiry. Replaying an already committed message does not advance its
chain or rewrite storage.

`receive_message` works on a private candidate state. It authenticates the complete
header and application associated data, then atomically stores the new chain,
skipped-key changes and sealed plaintext inbox. Only after commit and witness
release verification does it return `CommittedPlaintext`. Authentication failure
cannot consume a persisted skipped key or advance a chain. Exact duplicates return
the same retained delivery while unconsumed; consumed deliveries return `Retired`.
This does not make external application side effects
exactly once. The application must deduplicate those effects by session and message
ID. Result plaintext is zeroized on drop; caller copies remain caller-owned.

Both directions recheck current protocol policy, runtime lifetime and device/roster
validity before operation and release, including cached output. Prekey advertisement
expiry is checked during bootstrap, not used as an established message lifetime.
The installed [roster head](ROSTER_AUTHORITY.md) controls both peers' membership
and roster lifetime. Committed revocations fence retained contexts after restart.

The [rekey control path](REKEY_OFFERS.md) now completes four signed flights through
the same journal. Offer/response preparation leaves traffic unchanged. Final and
receipt commits switch the two directions at their authenticated boundaries,
retaining old-epoch records. `rekey_progress` distinguishes sending, receiving and
locally completed epochs; none reports adversary knowledge. A packet from a future
receiving epoch returns `Suspended` without consuming keys until its control
receipt is committed. Exact control outboxes remain separately retransmittable.

## Fixed candidate cryptography and bytes

Let `D = ASCII("Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/")`.
All integers below are unsigned and big endian.

- Initial HKDF-SHA-256: salt is the 32-byte bootstrap session ID; input key material
  is its private confirmed root; info is
  `D || "initial/HKDF-SHA256/ChaCha20Poly1305" || context_digest`.
  Split 160 output bytes into a separate future-rekey seed, initiator-send chain,
  responder-send chain and separate acknowledgement keys for each direction.
  The rekey seed cannot derive these initial chain
  outputs. This initial derivation does not itself add new entropy; the later
  hybrid exchange and epoch-traffic schedule are specified in [REKEY_OFFERS.md](REKEY_OFFERS.md).
- Chain step at index `n`: HKDF-SHA-256 with zero/default salt, current 32-byte
  chain seed, info `D || "chain" || n:u64`. Split 64 bytes into next chain seed
  and a one-use ChaCha20-Poly1305 key. The nonce is twelve zero bytes; safe use
  requires the enforced one-use key/chain and exact pending-command rules.
- Header, 93 bytes:
  `"QPCMSG03"[8] || session[32] || direction:u8 || epoch:u64 || index:u64 || message_id[32] || plaintext_len:u32`.
  Direction is 1 for initiator-to-responder and 2 for the reverse. Epoch must be
  admitted by the authenticated local control state and match the message ID. The peer direction, exact session, index bound and exact total frame
  length are checked; aliases, unknown versions and trailing bytes fail.
- Frame: header, ciphertext of the stated length, 16-byte Poly1305 tag.
- AEAD associated data: `D || "aead" || header || app_ad_len:u16 || app_ad`.
  Associated data is supplied by the application and not transmitted separately.
- Send reconciliation commitment: SHA3-256 using the repository's length-delimited
  `digest` function, domain `D || "send-intent"`, body
  `plaintext_len:u64 || plaintext || app_ad`. Receipts live only inside the sealed
  journal. Pending input is compared byte-for-byte before computation.
- Receive reconciliation uses domain `D || "receive-intent"`, body
  `frame_len:u64 || frame || app_ad`. Message IDs are distinct in each direction;
  replacing an ID, or a previously consumed index, fails.

The symmetric chain and full-header authentication follow the design principles
in the [Double Ratchet specification, sections 2.2 and 3.1](https://signal.org/docs/specifications/doubleratchet/).
These candidate domains, framing, bootstrap and whole-hybrid rekeys are distinct.
This component is not an implementation of the Double/Triple Ratchet and inherits
no construction-specific recovery result from it.

## Storage, bounds and remaining work

Journal schema v16 rejects schemas v1–v15 without reset. The outer table/header and
inner image are `continuity_device_candidate_v16`, `QPVLT016`, `QPVIMG16`.
Bootstrap phase 19 means its root was transferred; message records use kind 4,
phase 19 and `QPMST008`. Image admission enforces a one-to-one link with the
matching bootstrap role, context, retained account references and session transcript, zero retired bootstrap
root, canonical sorted records, and disjoint consumed/skipped receive indices.
A restored root cannot coexist with a valid linked message state.

Candidate resource bounds are 16 KiB plaintext, 1 KiB application associated data,
128 skipped receive keys and 64 outstanding records per direction **per retained
epoch**. The current candidate retains at most four traffic epochs, retiring a
settled prefix only through the signed v4 rekey contract; the existing 2 MiB
aggregate limit remains enforced. Capacity exhaustion does not discard pending
application records or reset a session.
[Consumption acknowledgements](RETENTION.md) retire contiguous consumed ranges
without resetting counters or allowing old request IDs to become new work. The
existing aggregate journal limit is 2 MiB/128 session-operation records; each activated
pairwise session uses its bootstrap and message records. Capacity exhaustion is
explicit. Application consumption and peer acknowledgements are committed
explicitly; there is no timeout-based dropping, silent gap skipping or chain reset. Root transfer and receive each use one
journal persist (four storage sync boundaries); a new send uses two (eight).

The initial epoch alone has no new DH/PQ input. The implemented signed rekey path
now installs fresh hybrid-derived directional traffic and ACK keys, including
across restart. Tests exercise repeated alternating rekeys, bounded history and
recovery from the specific old-chain retention-poisoning trace. They are not a
completed security argument. Explicit [closed-epoch resolution](EPOCH_RESOLUTION.md)
now records application-acknowledged unknown outcomes while preserving the old
ACK floor. An authenticated progress budget/control scheduler, full device lifecycle, multi-device
fanout and product/binding integration remain required work. Logical root/key removal does not erase old encrypted database
pages, write intents, snapshots or backups. The witness profile detects local
rollback only while its separately protected authority remains current.

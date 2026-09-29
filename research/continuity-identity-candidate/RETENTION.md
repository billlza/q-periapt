# Epoch-scoped consumption and bounded retention

The candidate's message profile v3 scopes IDs, chains, receipts and ACK authority
to a key epoch within one permanent logical session. It preserves one-use message
keys and exact pending-input/outbox replay. A retired ID never becomes new work.
The [old-chain poisoning trace](EPOCH_CUTOVER.md) motivated this separation: an
old-key-authenticated consumption floor must not reject new-epoch traffic.
No SDK binding or ABI export depends on this unpublished candidate. ABI remains 2.

## Application contract

1. Read `next_message_id` and retain the complete 32-byte ID before `send_message`.
   Reading is not a reservation. Concurrent reads can see the same slot; a rekey
   can also close that epoch before input reservation. The caller must handle the
   explicit conflict/suspension rather than reinterpret an old ID as a new one.
2. Receive `CommittedPlaintext`, durably deduplicate external application effects
   by logical session and **complete message ID**, then call `consume_message`.
   An index alone is not a deduplication key. The journal does not make external
   application transactions atomic with its own storage.
3. `message_acknowledgement` reports the committed contiguous consumed prefix of
   the current receiving epoch. `message_acknowledgement_for_epoch` does the same
   for an explicitly selected retained old epoch. Each result requires current
   policy/roster/witness authority, even if its contents were already committed.
4. `accept_message_acknowledgement` verifies the exact direction and epoch key,
   then retires only that epoch's outboxes. `message_status` reports the matching
   epoch's absent/reserved/committed/acknowledged state. A stale ACK cannot regress
   a floor or affect any other epoch.
5. When a closed old epoch cannot be reconciled, the application may explicitly
   begin [closed-epoch resolution](EPOCH_RESOLUTION.md). Its durable report freezes
   that epoch and lists unresolved sends, retained plaintext and observed gaps.
   Only after the host durably accounts for the report may it acknowledge its ID.
   Such sends then report `DeliveryUnknown`, never `Acknowledged`. Resolution is
   not an automatic retry, timer, successful-delivery claim or session reset.

Out-of-order consumption erases retained plaintext immediately and leaves its
consumed marker until the contiguous prefix advances. Missing earlier deliveries
retain their skipped keys and the sender's exact outboxes. There is no automatic
application gap skipping, timeout-based loss, probabilistic duplicate filter or
new-session reset. Closed old epochs remain separately addressable for replay and
explicit consumption.

A prepared final/receipt signing plan fences that local direction's **new sends**
until its exact cutover commits. Earlier outboxes remain replayable, and reception
and consumption can continue. Cutover admission refuses an unresolved old send
reservation; `resume_message` must first finish its already retained input. No
pending plaintext is silently re-encrypted under another epoch or ID.

## Canonical IDs and ACKs

Let `D = ASCII("Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/")`. The initial key
schedule and chain-step labels remain unchanged; the authenticated frame tag is
now `QPCMSG03`. Older message tags are rejected. All integers are big endian.

`MessageId = epoch:u64 || index:u64 || binding[16]`, where `binding` is the first
16 bytes of the repository's length-delimited SHA3-256 digest using domain
`D || "epoch-message-id"` and body
`logical_session[32] || direction:u8 || epoch:u64 || index:u64`.
The full tuple never repeats. Indices start at zero inside each authenticated
fresh-key epoch. The ID's epoch/index must match the network header, and its exact
session/direction binding is checked. Public ID bytes are not secret capabilities.

Epoch zero retains the original 81-byte ACK and known-answer vector:

`"QPCMACK1"[8] || session[32] || direction:u8 || floor:u64 || tag[32]`

A later epoch uses exactly 89 bytes:

`"QPCMACK2"[8] || session[32] || direction:u8 || epoch:u64 || floor:u64 || tag[32]`

`QPCMACK2` requires a nonzero epoch. For either form, the tag is HMAC-SHA256 under
that epoch/direction's separate acknowledgement key over
`D || "acknowledgement" || complete_prefix`. The receiver authenticates the
direction it receives; the sender verifies its sending direction. The bound
`floor <= sent_count` applies to the named epoch. Zero is a valid floor.
A valid MAC authenticates the peer's consumption claim; it does not prove an
honest external application action. These cleartext fields reveal progress and
cadence and belong in the full metadata/privacy analysis.

## Epoch state and close counts

Each retained `Traffic` owns its own send/receive seeds, ACK keys, counters, floors,
skipped-key map, pending send and inbox/outbox maps. For each epoch:

- `0 <= send_floor <= sent`; outboxes cover exactly `[send_floor, sent)`.
- `0 <= receive_floor <= received`; skipped keys and inbox entries are disjoint
  and cover `[receive_floor, received)`. Consumed records hold no plaintext.
- A pending send names the exact current slot of that epoch. A closed sending
  chain has no pending send and its chain seed is zeroed. It can replay existing
  outboxes but cannot generate a replacement ciphertext.
- The signed peer cutover supplies the old receiving epoch's upper message-count
  bound. Packets at or above it cannot produce another delivery. Old receive
  seeds are erased when the observed receive index reaches that bound; until
  then, delayed in-bound traffic uses the existing bounded derivation path.
- A poisoned old receive index/floor can exceed the honest signed close count.
  That old state remains isolated; it neither advances nor retires new-epoch
  work. Existing old inbox/outbox evidence is not silently discarded.

Unknown commits retain the exact encrypted write intent, close the journal, and
require reopening/reconciliation before any output. Roster revocation and the
required witness apply to all current and old-epoch operations.

## Bounded history and authenticated retirement

The v4 rekey profile binds a mandatory settled-prefix attestation. For target
epoch `t`, both the offer and response assert that the signing peer can retire
every locally retained epoch below `max(0, t - 3)`. A peer either has the
application-acknowledged terminal resolution described above, or it must satisfy
the ordinary drained-history conditions before reserving either signed flight:

- a closed sending chain, no pending input, and every outbox acknowledged;
- an identity-signed receiving close count and consumption through that count;
- no unconsumed plaintext. Remaining skipped keys may only address indices at or
  above the signed close count, where the honest peer cannot have sent a message.

Consumed metadata and those unreachable skipped keys can be removed. A missing
in-bound message, pending send, unconsumed inbox or unacknowledged outbox produces
`Capacity` before the new reservation. It neither deletes records nor claims
application delivery. In particular, an ACK lost in transit is not a reason to
retire a sender's outbox: the receiver retains its old ACK key while preparing an
offer, so the sender can recover that ACK before signing a response.

After both signed flights and fresh-key confirmation, final/receipt commits
atomically remove that prefix, install new owners, and retain the exact signed
control output. The sender has authenticated the peer's drain assertion before
deleting its last old ACK authority. A lost final or receipt replays exact stored
bytes after restart. Receipt acceptance changes the receiving epoch without a
second history deletion. The immediate predecessor remains available to validate
the signed cutover counts and the last completed control exchange remains stored.

The retained epochs are exactly the contiguous range
`[max(0, newest_local_epoch - 3), newest_local_epoch]`: at most four at any time,
with monotonically increasing epoch IDs. Requests, packets, ACKs and status
queries for an older epoch return `Retired`; unknown old IDs are not labelled
`Acknowledged`. Current indices may restart at zero only under their distinct
epoch-bound IDs and fresh keys. Each retained epoch still allows 64 outstanding
records per direction and 128 skipped keys; the journal remains capped at 2 MiB.

The terminal resolution state retains the original counters and ACK floors,
plus its exact report ID, with no traffic/ACK/skipped keys or inbox/outbox data.
Only the explicit application acknowledgement can create it. Pending reports do
not satisfy retirement. Historical receipt coverage applies to ordinary/frozen
states; a terminal unresolved send range instead yields `DeliveryUnknown` until
the later signed rekey removes that epoch. Removed epochs return `Retired`, so
the host must retain its own durable outcome record.

These are local implementation conditions under authenticated, honest peer
signing and explicit application accounting. They do not prove continuous
recovery under arbitrary compromise or restore past authenticity. Without such
accounting, unresolved records remain and apply backpressure. The signed progress
budget/control scheduler, full lifecycle/fanout, complete construction analysis
and product binding integration remain mandatory 0.2.0 work.

Journal v16 uses `continuity_device_candidate_v16`, `QPVLT016`, `QPVIMG16` and
message state `QPMST008`. Earlier candidate journals are rejected unchanged,
without migration or reset. Logical erasure does not erase old encrypted pages,
write intents, snapshots or backups. Local-only journals do not detect whole-file
rollback; required-witness journals depend on the independently retained head.

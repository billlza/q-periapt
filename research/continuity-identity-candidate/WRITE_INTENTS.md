# Exact local journal writes

Each logical journal transition now persists its complete sealed target before
attempting to install that target as current state. This covers reservations,
result pins, bootstrap outboxes/confirmations, prekey generation/retirement and
authenticated roster updates.
It preserves the same ciphertext, nonce, revision and complete aggregate across
an interrupted state write. The unpublished local journal schema is v10; earlier
schemas are rejected without migration or reset. Network bytes and ABI 2 are
unchanged.

## Two durable transactions

The journal owns one exclusive database lease. An operation loads the authenticated
current image, constructs its next state, increments its checked revision and
seals that complete image once. It then:

1. Creates an authenticated write intent containing the exact prior revision/digest
   and complete sealed next image. Inside the first write transaction, compare the
   stored image digest against the expected prior and require no other pending
   intent. Commit the `pending` row with immediate durability and two-phase commit.
2. After that acknowledgement, begin a second write transaction. Compare both the
   current image digest and exact saved intent again, then atomically replace
   `image` with the saved bytes and remove `pending`. Commit with the same durability.
3. Only after the state commit returns may the operation continue computation or
   release its public result, subject to its existing policy/time checks.

No transition can replace a pending intent. Same-version/different-digest is a
conflict. The expected digest and intent comparison happen inside each write
transaction; a cache read before acquiring the writer lease supplies no authority.
All prekey consumption and outbox effects reside in the one sealed target and are
installed together.

Write failure closes the active database/wrapping-key owner and reports the existing
explicit error, including `CommitUncertain`. If intent reservation is absent on
authoritative readback, no target-state attempt crossed its acknowledgement barrier.
The prior operation can then continue from its retained cryptographic reservation.
If the intent exists, subsequent recovery uses its exact target bytes and does not
draw a new sealing nonce or rerun the cryptographic operation for that write.

## Reopening and reconciliation

`DeviceJournal::open` authenticates the current image and optional pending intent
and verifies the caller's independently retained `JournalIdentity` **before any
recovery write**. It settles at most one saved intent:

| Observed state | Action |
| --- | --- |
| No pending intent | Return the authenticated current image |
| Exact expected prior revision and digest | Apply the saved target and remove its intent atomically |
| Target already installed but a pending intent remains | Reject this inconsistent pair; state installation and intent removal are one atomic transaction |
| Conflict, changed intent, wrong identity, malformed or unauthenticated data | Return an error; do not replace state or generate a new proposal |
| Recovery commit outcome unknown | Return `CommitUncertain`; reopen/reconcile the same retained intent |

Reopening may complete a previously admitted storage transaction. This does not
grant permission for new cryptographic work or dispatch: the public operation APIs
still recheck policy, runtime and time. Queries on an open journal do not apply new
intents; an unexpected pending row fails and closes that instance. An already
applied exact target with no pending row is idempotent and performs no second state
advance.

## Encoding and bounds

The single table `continuity_device_candidate_v10` accepts exactly the `image` row
and, while a write is pending, one `pending` row. The current image uses the
[v10 encrypted aggregate](DURABILITY.md). Unknown tables, multimap tables and extra
rows are rejected.

The intent is:

`QPWINT01[8] || store_id[32] || owner[32] || expected_revision:u64 || expected_digest[32] || next_revision:u64 || next_digest[32] || target_length:u32 || sealed_target || tag[32]`

Integers are big-endian. The fixed prefix is 156 bytes. `next_revision` must be
exactly `expected_revision + 1`, with both nonzero and below `u64::MAX`. Both
digests use the existing complete encrypted-image hash, including nonce and tag.
The decoded target must authenticate under the journal key and match the same
store, owner, next revision and next digest. Its ordinary record/claim/inventory
validation also applies before an intent can be admitted. The target must retain
the current image's protection metadata and local account identity.

HMAC-SHA256 authenticates the entire prefix and sealed target. Its 32-byte key is
derived from the protected journal wrapping key by HKDF-SHA256 with default zero
salt and info `Q-PERIAPT-CONTINUITY-WRITE-INTENT-KEY/v1`. Verification uses the MAC
provider's verification API. It is separate from signing-owner, image and SDK token
encryption. Intent fields commit encrypted images, not plaintext secret values.
The intent itself has no public import/construction API.

The existing image plaintext limit remains 2 MiB. A sealed target is at most
2 MiB + 120 bytes and an intent at most 2 MiB + 308 bytes. There is at most one
pending target. The database limit remains 64 MiB. Each normal logical state write
now uses two redb transactions and four synchronization calls: the measured fault
harness sees 20 sync points for five response transitions, previously 10. Actual
latency and energy still require the complete release performance measurements.

## Verification and remaining contract

Tests kill a real inventory-backed responder after intent reservation but before
state application at initial admission and response-outbox commit. They inspect
the authenticated old state and saved intent, reopen the store, compare exact target
ciphertext and complete confirmation against a surviving initiator. Four additional
before/after-sync failures interrupt recovery itself. The existing fault matrices
cover every sync in both transactions, retaining real confirmation and atomic
consumption assertions. Byte mutations, valid-MAC malformed records, stale/forked
prior digests, wrong expected identity and exact duplicate application are checked.

This implements local write-intent ordering and recovery. The
[required-anchor profile](REQUIRED_ANCHOR.md) also derives the same full-head
advance from the saved intent, verifies the witness before local application, and
requires fresh queries before usable output. [Account roster fences](ROSTER_AUTHORITY.md)
use this same path. Complete policy and witness-authority renewal,
suspension records, release acknowledgements, cancellation and multi-device atomicity
remain part of the full 0.2.0 contract. Local-only mode can still restore an older
valid image; store identity alone is not a monotonic anchor.

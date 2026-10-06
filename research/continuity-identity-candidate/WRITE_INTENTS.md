# Exact local journal writes

Each logical journal transition now persists its complete sealed target before
attempting to install that target as current state. This covers reservations,
result pins, bootstrap outboxes/confirmations, prekey generation/retirement and
authenticated roster updates.
It preserves the same ciphertext, nonce, revision and complete aggregate across
an interrupted state write. The unpublished local journal schema is v21; earlier
schemas are rejected without migration or reset. Network bytes and ABI 2 are
unchanged.

Genesis creation uses the independently retained, caller-supplied identity and one
immediate two-phase transaction. [Creation recovery](DURABILITY.md#creation-with-an-unknown-result)
never generates a replacement image: local-only reopening authenticates the saved
genesis, while required-witness recovery can only recover its public enrollment
metadata. The metadata reader refuses any pending intent; ordinary anchored recovery
still requires the original witness before applying that intent.

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

The single table `continuity_device_candidate_v21` accepts exactly the `image` row
and, while a write is pending, one `pending` row. The current image uses the
[v21 encrypted aggregate](DURABILITY.md). Unknown tables, multimap tables and extra
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

## Independent policy-only witnessed target

`DeviceJournal::prepare_policy_renewal` re-verifies the original two-root approval
and live target/current identity, compares the original journal's actual policy
predecessor and roster, and queries the original witness head. It then seals one
aggregate and reserves it in the same exclusive `pending` row. The journal closes
on success or error. This method neither prepares nor commits the witness and
returns no operational owner. An uncertain reservation must be inspected before
another target is attempted.

The separately typed `QPWINT06` format adds `PolicyRenewalId[32]` and policy
statement digest `[32]` immediately after the 8-byte tag, then uses the existing
store/owner/expected/next/length/target/MAC fields. Its fixed prefix is 220 bytes;
the sealed target has the same existing bound. The decoder authenticates the
whole intent and sealed target, verifies the exact independently typed P record,
and preserves journal protection, local account and original identity. Ordinary,
G/T and independent-P bindings are distinct enum variants. A G/T intent cannot be
read as a P proposal, and no ordinary recovery path may apply either bound type.

`inspect_policy_renewal_preparation` reads the exact retained proposal before or
after local installation, with original trusted identity and historical P0. It
sends nothing and never reseals. `None` describes local absence only.
`recover_policy_renewal` sends only a fresh signed status query to the original
pinned witness. Applied installs the exact saved ciphertext using the existing
atomic target-write transaction. Prepared and Closed require the original head
and perform no local write; Unavailable retains uncertainty. Missing, stale or
substituted evidence is an error. Matching local target bytes alone do not create
witness Applied evidence. The intent remains even after successful installation.

These public journal preparation/recovery APIs do not acknowledge the witness,
erase pending state, mark the P journal receipt acknowledged, or release a
service/session. The [original enrollment coordinator](ENROLLMENT.md#required-witness-independent-policy-coordination)
now persists and reads back its exact Applied/Closed terminal before passing a
private typed capability to the journal cleanup boundary. That boundary checks
the original head, approval, actual P predecessor/target and pending descriptor
before ACK. Applied requires the exact target receipt still AwaitingEnrollment;
Closed requires the actual unchanged predecessor. Cleanup removes only that
pending row atomically and preserves the authenticated image byte for byte.

A lost ACK reply or uncertain cleanup write requires the same durable terminal.
Fresh Unavailable may finish that already-authorized cleanup under the monotonic
witness assumption; it cannot establish a new terminal. An exact no-pending retry
is idempotent. Configuration marks retirement only after cleanup readback. This
does not itself authorize operational use. The original enrollment owner now
retains a private completion capability bound to that exact P and original
proposal. The journal's serialized AwaitingEnrollment phase stays unchanged;
operational reads explicitly require the separately durable completion. A direct
journal open has no completion capability. This avoids an ordinary Advance solely
to acknowledge history after expiry, while every usable release still requires
current policy/runtime, actual roster and fresh independent-P witness admission.
A later P must use the original enrollment coordinator, which retains the exact
previous completion when it opens the journal; a public journal open cannot
acknowledge that history implicitly. The last completion survives the next P
stage/close. Carrying actual G/T remains
separate work. Local-only owner APIs still refuse required-witness P.

The focused journal checks use a real anchored journal with an existing prekey,
actual signatures, a real witness store, a lost commit reply, expired/closed
runtime inputs, and exact sealed-byte comparisons. They cover four intent-commit
sync faults, eight later database-close sync faults, and six target-installation
sync faults. Calibration captures the intent boundary before database Drop:
reservation uses two syncs, while successful owner teardown adds four in the
observed redb build. Installation also has a pre-commit I/O boundary, whose
original injected `Storage(Io)` is distinct from `CommitUncertain`.

A Drop housekeeping fault after an already acknowledged immediate commit does
not undo that commit; every such case must return a proposal that is still exact
and durable on a real reopen. This check does not claim an error-returning close
API. Separate enrollment checks cover terminal persistence before ACK, 16
configuration sync faults and 10 cleanup sync faults with the original typed
terminal. Calibration and injected cases use the same database open/close history,
and every injection must actually fire. Eight new process kills cover Applied and
Closed at four cross-store boundaries. Separate original-session checks cover
operational release, actual traffic and rekey under independent P. Deployment
storage guarantees, network/TLS, installed languages, G/T composition and the
complete 0.2.0 release remain open.


## Atomic roster target in the original journal

`DeviceJournal::prepare_roster_refresh` takes one retained `RosterRefreshId` and
`RosterRefreshMaterials`: original immutable credential/P0, the exact current
policy/runtime and the independently root-approved same-credential target device
and roster. The original required journal supplies the actual previous roster and
current policy authorization. Completed independent P requires its private
original-enrollment completion capability; ordinary metadata opening alone cannot
invent that completion. Real local G/T composition is still refused.

The previous roster may be expired: its signed historical membership identifies
the actual predecessor but grants no current permission. Preparation admits the
fresh target roster, unchanged credential and current policy/runtime at the given
trusted time. It reads the fresh original witness head, advances the roster using
the existing monotonic roster implementation, and seals one aggregate. Existing
identity, policy approval and all non-roster records remain unchanged. It retains
the exact target before returning its proposal and closes the journal on success
or error. It neither prepares nor commits the witness. The surrounding original
enrollment/service owner must retain its lease through this operation.

The separately typed `QPWINT07` pending format adds the canonical 185-byte R scope
before the existing store/owner/expected/next/length/target/MAC fields. Its fixed
prefix is 341 bytes and the encrypted target retains its existing size limit.
The same scope codec is shared with the unchanged 417-byte `QPRWNP01` descriptor.
The original single pending slot arbitrates ordinary, G, P and R intents. Those
bindings are explicit enum alternatives; another transaction kind cannot serve as
R evidence, and ordinary recovery cannot apply any bound target.

After an uncertain preparation return, `inspect_roster_refresh_preparation` reads
the exact original proposal before or after target installation, without signing
or resealing. `None` means local absence only. `recover_roster_refresh` checks that
complete retained proposal and original witness/key separation before dispatch.
It sends only a fresh RosterStatus (17). Exact Applied installs the original sealed
bytes through the shared atomic apply kernel and retains pending. Prepared or
Closed require the original old head; authentic local target bytes paired with
these outcomes are a conflict. Unavailable never becomes Applied or NoCommit.
Lost/stale/substituted replies are errors, not authorization.

The native component checks use a real original enrollment, actual journal,
existing generated prekey and real signed witness/roster approvals, under both P0
and an adopted independent P. They cover lost commit and status replies, exact
recovery after credential/policy expiry and runtime closure, changed-target/type
refusal, current-input refusal, and preparation from an actual expired roster to
a fresh root-approved target. Authenticated before/after comparison checks all
non-roster records and the retained independent-P approval. A test-only replay of
the authentic sealed target verifies that local ciphertext alone cannot invent a
witness Applied outcome; it is not a production repair path.

The fault matrix covers four reservation sync failures, eight later database-Drop
sync failures and four target-installation failures. Every injection must fire,
preserve its original typed I/O error where returned, and recover the same intent
and ciphertext. A later destructor housekeeping failure cannot retract an already
acknowledged immediate reservation; those cases require a successful real reopen
of the exact returned proposal. This does not claim an error-returning close API.
Calibration and fault cases use matching database open/close history.

These methods do not retain an original-enrollment R terminal, ACK the witness,
delete pending or release an operational roster owner/session. That coordinator
remains the next integration step. New R process-cut, live network/TLS, foreign
and installed-platform qualification remain open; prior P process cuts are
separate evidence. The supported target roster retains the unchanged original
credential; this is not an external lost-device revocation control plane.

The original enrollment now constructs a private `PersistedRosterTerminal` only
from authenticated durable readback. R retirement checks the complete proposal,
original subject/protection, expected Applied/Closed head, actual roster and
unchanged current P binding (including the retained original P completion). Only
then can a fresh exact ACK (19) authorize removal of the original pending bytes.
The final compare-and-remove transaction is shared with independent P retirement;
G cancellation and its historical audits are not changed by this extraction.
Unavailable supports cleanup only under this private already-persisted terminal,
never target installation or a fabricated disposition. Unknown cleanup retains
either the original exact pending or its atomic absence and retries the same R.
The new R tests consume 16 enrollment-save sync failures and eight journal-cleanup
sync failures, checking the original typed I/O source. Eight actual process kills
reopen original enrollment, journal and witness databases after expiry without
constructing a live runtime. These counts are distinct from the reservation and
installation matrix above.

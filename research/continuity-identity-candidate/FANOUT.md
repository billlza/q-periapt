# Atomic complete-roster account sends

Status: unpublished candidate with local qualification. This is one
sending device's account fanout transaction, above the existing v6 pairwise wire
protocol. It is not group encryption, atomic remote application execution, a
distributed transaction across independently owned device journals, or installed
language-service integration.

## Admission and authority

`send_account_message` takes a retained journal-issued `FanoutId`, recipient
account, existing authenticated pairwise contexts/sessions, one plaintext and
associated data. The journal derives each peer identity from its existing session;
the host cannot relabel an arbitrary session as another device.

The installed signed roster defines every mandatory recipient. Exactly one session
for each current device is required. Sending to the local account excludes only
the sending device itself. Empty, omitted, extra, duplicate, replaced or wrong-account
recipients fail before reservation. There is no optional-recipient fallback.
Every context must pass the existing runtime, policy, device, generation, time and
roster checks. A selected context cannot implicitly update a stored roster head.

The reservation records the exact installed recipient roster checkpoint. A later
roster update does not rewrite that batch's membership. Release/resume requires
the same checkpoint and complete retained routes; a changed head suspends the
batch rather than silently sending to a reduced or enlarged set. Independent
roster installation and fresh session admission remain separate operations.

## Atomicity and recovery

The journal performs two aggregate transitions:

1. Validate every target's send fence, progress allowance, outstanding capacity
   and current slot; commit all exact plaintext/AD reservations, the batch record
   and monotonic batch counter together.
2. Derive/encrypt each member on private candidate state; commit all chain advances,
   immutable outboxes and the batch's committed state together, then recheck release
   authority before returning any member.

No per-member write or release occurs between these transitions. Failure after
computing a prefix leaves the original all-member reservation. Retry recomputes
only those identical inputs under their original message IDs and keys. An unknown
storage result closes the owner and uses the existing exact sealed write-intent
reconciliation before any further work.

Every reserved member has a persisted batch reference. Image admission validates
both directions of the relationship, exact plaintext/AD intents, unique member
slots and context/session bindings. Missing, swapped or conflicting batch records
cannot turn a member into an ordinary send. `next_message_id`, `send_message` and
`resume_message` refuse independently releasing a reserved batch member. The
normal signed send budget counts each reservation once and each committed member
once; restart and retries do not refund or double-charge it.

The existing required witness covers this device's entire encrypted journal image,
including all affected sessions and the batch metadata. Its exact reservation and
final aggregate digests must be reconciled before release. There is no per-recipient
anchor loop whose successful prefix could independently release ciphertext. This
does not provide an account-global transaction across other sender devices' stores.

Cancellation stops dispatch and retains exact work; it does not cancel the durable
reservation, restore the spent allowance or permit replacement plaintext. Authority
loss can leave a batch suspended. The separate [explicit abandonment](FANOUT_ABANDONMENT.md)
flow freezes and accounts for every member session before terminal closure. It
never resets a session, refunds a slot or substitutes a recipient. Re-enrollment,
device replacement and account-wide coordination remain separate lifecycle work.

## IDs, replay, retention and privacy

The journal reserves monotonically increasing batch ordinals. A public ID contains
the ordinal and a domain-separated binding to this journal's independent identity;
it contains no plaintext hash. The plaintext/AD intent stays in encrypted records.
Concurrent readers can receive the same next ID; only an identical reserved input
may reuse it. Once an older batch record is retired, its ordinal remains consumed.

`FanoutStatus::Committed` means that all members committed locally. A replay returns
one explicitly identified outcome for each original member: exact committed wire,
authenticated acknowledgement, pending closed-epoch accounting, recorded unknown
delivery, or already-retired epoch history. The last outcome does not invent whether
the old message was acknowledged or recorded as unknown. The existing external
closed-epoch reports preserve that application accounting.

`retire_fanout` removes metadata only when every member is acknowledged, explicitly
accounted unknown, or belongs to already-retired epoch history. A reserved batch,
live outbox or unacknowledged resolution report prevents retirement. The batch
counter is not reset, so a retired ID never becomes a new operation. Delivery to
one peer neither acknowledges another peer nor permits reporting aggregate remote
success. Existing per-session delivery ACKs remain distinct from local commit.

At most 16 batch records and 32 recipients per batch are admitted. Existing
16-KiB plaintext, 1-KiB AD, per-session receipt/progress limits, 128-operation bound
and 2-MiB aggregate image limit also apply. These are concurrent bounds; reaching
the image or session limit may reject work before the batch-count limit. Nothing
is silently truncated or dropped.

## Storage identity and qualification boundary

The candidate journal advances to **v19** (`continuity_device_candidate_v19`,
`QPVLT019`, `QPVIMG19`). The image adds its monotonic batch counter. Record kind 6
uses `QPFANO02`, explicit reserved/committed/abandoning/abandoned phases and canonical sorted members.
Message state is **QPMST010**, traffic state **QPTEPO04**; a pending send stores an
optional exact batch ID. Older research images are rejected without reset or an
implicit migration. v6 signed controls, QPSESP03 policy and application wire bytes
are unchanged.

The kind-6 payload is canonical, big-endian and has no trailing bytes:

`QPFANO02[8] || id[32] || account[32] || roster_version:u64 || roster_digest[32] || count:u8 || members || private_tail[64]`.

Each of the `count` members is exactly 153 bytes:

`device[16] || generation:u64 || credential[32] || context[32] || session[32] || role:u8 || message_id[32]`.

The payload is `177 + 153 * count` bytes. Members are strictly ordered by device
ID; sessions and reserved slots cannot repeat. The record context uses the existing
length-prefixed digest helper with message-domain label `account-fanout-metadata/v1`
over all payload bytes before `private_tail`. In live phases the tail contains
`intent[32] || reserved_zero[32]`; other phases are defined in the abandonment
contract. The intent is the existing private
`send-intent` digest and never enters a public batch ID. Reserved/committed phase
21/22 resides in the enclosing authenticated record, not a caller-provided flag.
In QPTEPO04, immediately after a pending message ID, a one-byte 0/1 discriminant
is followed by the exact 32-byte batch ID only when it is 1. The plaintext and AD
length/value fields then follow the existing pending-input grammar.

At commit `1210788c`, the v18 local macOS ARM64 runs pass **186 tests each**, with zero failures or
ignored tests: debug 518.46 seconds and release 443.62 seconds in their runners.
The runs overlapped and are not a controlled performance comparison. Rust 1.90
and 1.98.1 strict all-target/all-feature Clippy, no-default-feature compilation,
formatting and warning-strict docs pass. A separate clean source snapshot passes
45 candidate-isolation and Rust-inventory checks for its 198 Rust files. Those
public-byte/OpenSSL oracles verify 20 envelopes/100 signature negatives, and the
separate witness oracle verifies 12/60; private message protection is established
by the actual journal tests, not inferred from those public signatures.

The checkpoint's eleven fanout tests include the subprocess entry point and exercise complete peer
and own-account rosters, both bootstrap roles in one batch, omission/duplication,
expiry, changed/revoked roster heads, capacity, exact replay and ID retirement.
Two independently enrolled recipient journals decrypt the actual frames. A unary
loop first reproduces partial plaintext release when a later required peer has
exhausted its budget; the batch preflight leaves all member states unchanged.
Partial ACK, an fsynced application accounting record, unknown delivery and later
epoch retirement retain their distinct per-member outcomes.

Nine observed storage barriers yield **18 before/after sync faults**; every result
reconciles to all-absent, all-reserved or all-committed. Three actual process kills
cover reservation, first ciphertext computation and aggregate commit. At each cut
a bounded competing process observes `Busy`; recovery returns the same pre-commit
ciphertext and exact complete batch. All **18 before/after losses** across nine
actual witness calls also recover the full set without a local-only fallback or
refunded/doubled spending. Missing batch metadata and relabelled/split phases are
rejected as corrupt.

Initial fixture failures are retained: proof indices were incorrectly assumed to
follow leaf kinds, and noncanonical temporary paths failed protected-file admission.
The fixture now selects authenticated proof roles and canonicalizes its private
directories. Initial compiler/Clippy diagnostics were corrected without suppressing
checks. The first 184-test full runs are distinct from the final source, which
avoids duplicate validation work and adds mixed-role/accounting tests.

These are native Rust journal/process tests on one host. Application frames move
through the harness; this does not qualify installed cross-language consumers,
cross-host application transport or physical devices. Full device lifecycle,
independent sender-store coordination, release security analysis and final platform
qualification remain required.

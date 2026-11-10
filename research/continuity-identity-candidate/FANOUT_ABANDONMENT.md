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

Current journal v21: `continuity_device_candidate_v21`, `QPVLT021`, `QPVIMG21`. Older
candidate images fail closed with no reset or implicit migration. Pairwise v6,
QPSESP03, QPTEPO04, KATs and published SDK/binding ABIs are unchanged. QPMST011
reserves the independent-closure tail described in [session closure](SESSION_CLOSURE.md).

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

`QPABND02[8] || source[32] || session[32] || batch[32] || report[32] || pending_message[32] || role:u8 || confirmed:u64 || sending:u64 || receiving:u64 || pending_control:option<u64> || count:u8 || counts`.

The option uses 0 or 1 followed by a u64 only for 1. Each retained epoch is
`epoch:u64 || sent:u64 || acknowledged:u64 || reserved:u8`, with reserved exactly 0 or 1. Epochs are consecutive and bounded by
the existing four-epoch window. The pending ID is bound to the terminal session,
role, sending epoch and unchanged uncommitted slot. Shared source validation still
recomputes the session ID from the admitted final bootstrap transcript.

## Archived whole-batch cleanup

`FanoutAbandonmentJournal::open` / `open_anchored` take an existing private
journal, original wrapping key, independently retained JournalIdentity and FanoutId,
and its existing SessionArchiveStore. Complete membership comes from the
AEAD-authenticated batch record; every original QPCSCA01 session archive must
match the journal, owner, account, session, context, role and peer device/generation.
The admitted context digest retains its credential binding. All member archives
also name the same original local signer. There is no caller-supplied recipient
subset or a fabricated BootstrapContext. The index owns no private key, and its
mere presence grants no cleanup permission.

The owner exposes only `status`, `begin`, `acknowledge`, `retire_metadata` and
`close`. Freeze/acknowledgement reuse the original transaction engine and complete
report: the application must durably account for all losses and unknown outcomes
before acknowledgement. `retire_metadata` accepts only an acknowledged abandoned
batch; it cannot retire ordinary committed fanout history. It removes the batch
record, leaves every terminal session, bootstrap and one-time claim in place, and
never resets the monotonic counter or frees a terminal session slot. Same-owner
repeat retirement is idempotent; a later authenticated opener returns Retired.
The owner releases its database, key and witness client on close. The caller keeps
ownership of the index and may close it independently after successful admission;
the restricted owner retains only authenticated public scope bytes for rechecking.

The header selects only a bounded decryption candidate. The complete sealed image
and independent ID authenticate before any write. An operation missing from the
current image can be recovered only from its **already sealed exact reservation**.
Every member archive and the complete target membership authenticate before any
saved transaction is reconciled. The same checks apply to pending freeze, terminal
and metadata-retirement intents. Missing archives return `ArchiveRequired`; they
cannot be mislabeled as an absent batch or trigger replacement provisioning. An
invalid MAC or a valid-MAC archive for a different context fails without applying
the original intent. Restoring the exact original public metadata can recover it.

Required-witness open preserves its pinned witness, subject and original enrolled
signer. Returning Absent or Retired also requires a fresh authenticated head query;
a stale local counter cannot certify that disposition. With an unresolved unrelated
intent, the opener reports suspension instead of guessing. An expired enrollment
can confirm an already applied freeze but cannot perform an unperformed freeze,
terminal acknowledgement or metadata-retirement advance. There is no fallback.
All uncertain commits close the owner and require exact reopen/reconciliation.

No new wire or archive format is introduced: QPCSCA01/QPCSIX01, QPFANO02, QPMST011,
QPABND02 and journal v21 remain unchanged. The shared loader is also used by the
bootstrap cancellation owner; it does not broaden either owner's public methods.
Logical erasure and witness trust/availability/rollback limits above still apply.

Focused tests cover three observed process kills (freeze, terminal commit, metadata
retirement), three contenders checking both database leases, and fresh cleanup
processes that construct no verified policy/device/context objects. Mixed local
handshake roles and installed peer revocation retain all prior unknown sends and
unconsumed inbox losses. The single-session archive owner still refuses to split
the same reserved batch; the aggregate owner returns the exact shared-engine report.
Each shared transition has four observed sync barriers, for 24 before/after faults
reopened through the indexed owner. Open plus each archived transition has five
signed witness exchanges, for 30 before/after response losses. Exact pending birth,
missing/tampered/substituted archives before pending writes, wrong wrapping key/ID,
committed-batch refusal, expired enrollment and fresh Retired disposition are checked.
The corrected full Debug/Release suites pass 246 tests each, zero failures or
ignored tests; runner times are 716.265/710.917 seconds under overlapping load,
not comparative performance. Strict all-feature, individual-carrier and no-default
Clippy pass on Rust 1.90/1.98.1, along with warning-strict docs, fmt and 95 clean
source/isolation/release-contract checks. The initial feature check identified the
archive-mutation test helper's unnecessary connection-tls gate; the helper now serves
these unconditional tests. An extra-multimap schema counterexample fails on the old
index validator and passes after the common read boundary rejects unsupported
namespaces. Both corrected full suites were rerun; initial diagnostics are retained.
These tests do not qualify installed foreign SDK consumers or independent hosts/devices.

## Qualification boundary

The test cohort covers native journal behavior on one macOS ARM64 host. Separate
producer processes are actually killed at ciphertext computation, freeze and
terminal commit. Competing processes must return Busy within a deadline. Storage
faults are injected before and after every measured barrier, and signed witness
responses are lost before and after every measured exchange. These observations
cannot qualify installed foreign-language clients, cross-host or physical-device
behavior, a complete protocol security proof, or the remaining 0.2.0 release gates.

The original v19 macOS ARM64 qualification passed **192 tests each** in debug and release,
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

## Restricted reconciliation of an already committed batch

`InstallationRecovery::open_account` selects the complete authenticated original
batch and all of its retained session archives. Its restricted journal can now
call `reconcile_members()` for a committed batch or an acknowledged reserved
abandonment. The result contains the original batch, device, session and message
IDs and one metadata-only disposition for every original member: Committed,
Acknowledged, ResolutionPending, DeliveryUnknown, HistoryRetired or
ReservationAbandoned. No ciphertext is released. HistoryRetired does not recover
the distinction between earlier acknowledgement and recorded unknown delivery.
Reserved and unacknowledged abandonment still require the complete loss-report
path and return Suspended from this metadata query; retired metadata returns
Retired explicitly. An original required witness must still admit the current
head before a result is released. This grants no traffic authority.

A changed current recipient roster can suspend the original committed operation.
The caller can then use each original `InstalledSessionRecovery` to retain and
sync its complete closure report, acknowledge that exact report only after host
accounting, and reopen the original account recovery owner to reconcile every
member. `retire_metadata()` accepts a committed batch only after the existing
shared retirement kernel verifies every original member has a settled outcome.
A remaining Committed or ResolutionPending member prevents retirement. This
preserves authenticated consumption separately from host-recorded unknown
delivery; it never reclassifies committed work as reserved abandonment.

Retirement removes only aggregate metadata. The original session records,
bootstrap claims and monotonic batch counter remain. Settled live sessions need
not be closed just to retire aggregate metadata. A duplicate on the same owner
rechecks each retained original archive and settled message fact; reserved
abandonment still requires one matching whole-batch terminal report. An unknown
commit outcome requires reopening the original installation and reconciling its
exact pending target. A fresh Retired result does not reconstruct a lost member
report, so the host must retain results it needs before retiring metadata.

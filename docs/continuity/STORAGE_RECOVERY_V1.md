# Continuity candidate storage and recovery contract

Status: **implemented candidate, not a frozen product contract**. Source baseline:
`e00281ec`. The current journal is v21; incompatible candidate images are refused
without implicit migration or reset. [STATE_MACHINE_V1.md](STATE_MACHINE_V1.md)
defines the operation dispositions; [WIRE_V1.md](WIRE_V1.md) separates network,
public import and local formats. This document does not claim hardware power-loss
qualification, a hardware key store or protection against a hostile same-UID host.

## Assets and independently retained inputs

| Asset | Contents and original binding | Recovery requirement |
| --- | --- | --- |
| Wrapping-key file `QPVKEY01` | Exact 40-byte tag/key file; non-exporting `JournalKey` owner | Retain the original protected file outside database backups; a missing/wrong key is not first use |
| Signing-owner files | Purpose/identity-bound encrypted signing material and original public identity | Reopen the original owner under its wrapping key; never generate a substitute to resume reserved work |
| SDK signed-policy store | Verified SDK policy lineage and durable current selection | Use its existing prepare/persist/activate and revocation contract; a Continuity journal cannot recreate an expired/closed runtime |
| Installation configuration `QPCINS01` | Original journal ID, device owner, key/policy/path/witness bindings, Creating/Active | Keep independently trusted; no ordinary open error permits provisioning or path replacement |
| Device journal | Authenticated encrypted aggregate, optional exact-target write intent | Reopen with original key/identity/device/protection; reconcile only the saved intent |
| Session archive index `QPCSIX01` | Bounded public session IDs and immutable MACed cleanup archives | Discovery is a hint; actual use authenticates the original archive and protected journal |
| Separate QPCSCA01 archive | Original context/session/device/storage protection for cleanup | Restores cleanup scope only, never operational policy or a missing session |
| Witness database and signing owner | Independently maintained full heads, enrollment and signed observations | Must be outside the client rollback domain; restoring client and witness together defeats this boundary |
| Host application/accounting store | Application effects, deduplication, complete loss reports and their IDs | Commit effect and deduplication together; reconcile unknown host commits independently |

The installation's `JournalIdentity` is generated and committed before child
creation. The device-owner digest includes the credential-bound device generation;
changing a credential or generation does not reopen the old installation as a new
device. One authoritative lineage per configured device is a host responsibility.
The independently retained ID/configuration is not itself a rollback witness.

All native stores use the shared private-file/database admission boundary:
private ownership/mode/ACL checks, descriptor-relative traversal with pinned parent,
no symlink traversal, exclusive creation and nonblocking lifetime database locks.
The database file cap is 64 MiB with a 2 MiB cache. Lock acquisition is followed by
fresh inode/extent admission; a previously cached file/image cannot replace the
authoritative state under the acquired lease. These checks do not isolate mutually
hostile code running as the same user.

An initializer failure preserves the newly created file: its data may already have
been committed or admitted by another opener. A partial file is subsequently refused.
A complete wrapping-key file is admitted only after exact shape/link checks and
file/parent synchronization. No `open_or_create` recovery path exists. The retained
[creation regression](../../research/continuity-identity-candidate/DURABILITY.md)
includes an opener using a complete key before its original creator reports failure.

## Aggregate image and local write intent

The only journal table is `continuity_device_candidate_v21`. It contains one
`image` row and at most one authenticated `pending` intent. The sealed image is:

`QPVLT021 || journal_id[32] || owner[32] || revision:u64 || nonce[24] || ciphertext || tag[16]`.

Its 104-byte header is associated data for XChaCha20-Poly1305. The nonce is fresh
platform randomness generated when constructing the sealed target; retry of an
existing intent uses the saved nonce and ciphertext, not a resealed replacement.
Revision is nonzero and strictly below `u64::MAX`.

The plaintext starts with `QPVIMG21`, protection metadata, local account, monotonic
fanout ordinal and the bounded ordered record set. Record kinds distinguish
responder, initiator, prekey, message, roster and fanout. Owner/context/source,
one-time claims, authority references, payloads and their phase relationships are
validated as a whole. Separate record quotas and the 2 MiB plaintext cap all apply.
Terminal records/tombstones continue to count; removing them to reclaim capacity
would change replay and one-time semantics.

Each ordinary state advance follows this order:

1. Load/authenticate the exact current image and its required witness head.
2. Validate the proposed aggregate, increment the checked revision, and seal its
   complete target once. No public effect is released at this point.
3. In a write transaction, compare the authoritative current digest with the
   expected prior, require no pending intent and commit `QPWINT01` containing the
   exact prior/target. Durability is Immediate with redb two-phase commit.
4. If required, obtain the original witness's exact Advance acknowledgement for
   that prior and saved target. A lost reply is an unknown outcome.
5. In another write transaction, compare current digest and the exact intent again;
   install the saved target and remove the intent atomically, with the same durability.
6. Recheck the current witness head and the operation's current authority before
   continuing computation or releasing output.

The [intent codec](../../research/continuity-identity-candidate/WRITE_INTENTS.md)
uses a distinct HKDF-derived HMAC key. Intent authentication covers the complete
sealed target and prior, not a caller-supplied description of the intended effect.
Image, intent, signing-owner and witness-state keys have separate derivation domains.
No public API imports a pending-root or constructs an admitted intent from network
bytes. A same revision with a different digest is a conflict.

## Reopen algorithm and unknown commits

Open admits the private existing file, takes the lifetime lease, authenticates the
current image and protection, and checks the independently expected identity before
any recovery write. A required image is refused by the local-only opener before
applying even a structurally valid intent.

| Authoritative observation | Allowed recovery |
| --- | --- |
| Valid current image, no pending row | Admit that exact current state, with the required fresh witness check |
| Valid pending intent and exact prior image | Reconcile its original witness command if required, then apply the saved target exactly once |
| Target installed and no pending row | Treat it as current; do not increment again |
| Target installed but pending row still present | Refuse the inconsistent pair; state install and intent removal should be atomic |
| Wrong identity/key/protection, malformed image, changed target or prior digest | Return the specific failure; no repair, replacement or resealing |
| Recovery commit acknowledgement lost | Return `CommitUncertain`; close and reopen the same retained inputs |

Image/persist failures close the journal's active owner. An error can occur after
the state or witness committed, so its display text is never evidence of absence.
After reopening, query the exact request/session/message/control identity and resume
the retained result. Reopening may complete a previously admitted storage write;
it does not grant fresh operational policy or dispatch permission. Status queries
can remain available after operational expiry under their narrower contracts.

If no intent is present after authenticated readback, no target installation passed
the acknowledged intent barrier. Resume the prior stage using any already retained
crypto reservation. A sealed entropy reservation is intentional exact computation
replay. Do not replace it with fresh randomness merely because the previous process
or reply disappeared, and do not classify replayed exposed entropy as fresh recovery.

## Required-witness profile

The signed protocol policy selects either local storage or one exact witness
binding. Required mode seals the policy digest, witness binding and writer fence
in every image and intent. Ordinary recovery cannot downgrade or replace them.

Enrollment is explicit against independently verified device/policy pins and the
actual empty revision-1, fence-1 genesis. Unknown creation can recover only the
original public genesis metadata; a pending intent or advanced image is refused by
that restricted reader. Enrollment cannot be inferred from ordinary request bytes.

The witness head is `(fence, revision, encrypted_image_digest)`. Advance compares
the whole expected tuple, increments revision once and preserves fence. Fence
increments fence and preserves revision/digest. Each request attempt has a new
random challenge and signature, but an exact retry retains the immutable command
and command ID. Signed replies bind the complete attempt and command. Neither a
captured reply nor another command reaching the same next tuple counts as success.

After lost Advance reply, the saved intent reconstructs the exact command. The
client requires `Advanced` or `AlreadyAppliedExact` for its next head before local
application. An intervening head/fence or different command conflicts; it is never
silently rebased. Exact last-command reconciliation can succeed after enrollment
expiry, while an unperformed mutation still requires current authority.

The witness independently persists its head before reply signing. A signing failure
after that commit is `ReplyUnavailable`, not rejection. A query is a fresh observation,
not a lease preventing later writers. The client does not automatically adopt a
higher fence. The native trusted control-plane
[`update_roster_authority`](../../research/continuity-identity-candidate/ANCHOR_WITNESS.md#explicit-refresh-under-a-newer-roster)
can refresh the same credential/policy subject against an independently admitted
newer roster, preserving its genesis/head/fence/last command. The saved predecessor
checkpoint is only a compare-and-set expectation; current authorization comes from
the verified target. Its result confirms current enrollment metadata, not an exact
administrative-command receipt. Credential/policy or witness-key replacement,
independent deployment and authenticated lineage migration remain lifecycle work.

## Installation, archives and application transactions

Creating configuration, journal genesis, archive-index genesis and Active are
ordered transactions, not one atomic multi-database commit. The retained original
configuration makes exact reconciliation possible. Active with a missing child is
an error; startup never guesses that an earlier install was unused.

The connection carrier commits/authenticates a session cleanup archive in the
index before message activation, and checks it again before application send or
delivery. A crash between archive commit and activation can leave unused public
metadata; it does not authorize deletion or a new session identity. A lost index
commit acknowledgement closes the index owner. Reopening and retrying the exact
archive is idempotent even at capacity; changed bytes conflict. The index cap is
128 archives, independently of aggregate journal capacity.

The index is not an anti-rollback witness. Missing/rolled-back rows can remove
discovery or stop delivery. Explicit restoration must authenticate the original
archive against an existing original protected journal. It cannot restore private
session state, bypass its current witness, recreate an operational context or make
an unknown ID valid. Terminal index retirement requires the original `Closed(report)`
state and the host's retained exact report ID. Journal claims/tombstones remain.

Application effects are another transaction boundary. The receiver journal first
commits plaintext/inbox; the host then commits its application effect and deduplication;
only afterward does the journal commit consumption and release an ACK. A host failure
after its own commit can repeat the callback. The host must retain the same ID and
recover that effect rather than performing a new one. The public consumer's
post-fsync process exit exercises this unknown interval; it is not a distributed
transaction protocol for arbitrary host databases.

Loss accounting has the analogous order: freeze and commit an exact report, durably
record the entire report at the host, then acknowledge that exact report to install
terminal/retired state. Neither a successful write of just the report ID nor dropping
the returned owner substitutes for complete durable accounting.

## Backup, erasure and migration boundary

Local-only images provide integrity/confidentiality under the wrapping-key and
trusted-host assumptions; they do not detect a completely restored older valid
image. Required mode adds an independently current witness head, so a stale client
snapshot cannot simply replace it. Joint client/witness rollback, lost trusted
configuration or hostile access to their keys falls outside that claim.

`Zeroizing`/secret owners and terminal encodings address owned memory and current
logical records. They do not erase old redb pages, filesystem snapshots, backups,
host copies, swap or previously disclosed reservations. A compromised wrapping key
plus access to later encrypted images exposes those later images; fresh protocol
randomness does not repair storage protection. Host-key replacement and an explicit
backup/erasure design are required before any stronger claim.

There is no automatic candidate schema migration. An unsupported old table/tag,
changed policy family/device generation, missing file or bad MAC never triggers
empty-state initialization. Product upgrade/rollback support needs a separately
specified, crash-safe migration and compatibility policy; the current v21 refusal
is not a complete long-term maintenance strategy.

## Source correspondence and qualification limits

The implementation is in
[`durable.rs`](../../research/continuity-identity-candidate/src/durable.rs),
[`write_intent.rs`](../../research/continuity-identity-candidate/src/durable/write_intent.rs),
[`anchoring.rs`](../../research/continuity-identity-candidate/src/durable/anchoring.rs),
[`installation.rs`](../../research/continuity-identity-candidate/src/installation.rs)
and [`session_archives.rs`](../../research/continuity-identity-candidate/src/session_archives.rs),
using the shared
[filesystem boundary](../../crates/q-periapt-host-store/src/filesystem.rs).
The existing exact-intent, creation, installation-recovery, witness-loss and
public installed-connection tests exercise real stores and bounded process/I/O
faults. Their source-bound results do not qualify sudden hardware power loss,
all operating systems, every schema upgrade, foreign adapters or an independently
operated witness. Those remain separate completion evidence.

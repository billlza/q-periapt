# Independent storage, witnessed recovery and session ownership

This is an unpublished single-session implementation for interoperability work.
It is independent of the Rust protocol state machine and redb image format.
It implements bounded four-flight rekey, four retained traffic epochs and separate
local-only/required-witness storage profiles, plus remote same-key credential
renewal and peer revocation. It does not yet implement local credential/policy/roster
coordination, same-account peer authority changes, account fanout, network control scheduling,
installed consumers or a complete installation owner.
Its original verified authority snapshot and trusted time remain explicit inputs.
It is not a replacement product package or a completed security proof.

## Assets and authority

The caller retains the original 32-byte wrapping key and `Scope` before creation.
Scope contains a fresh 32-byte journal identity, a public signing-owner binding
and the original bootstrap context digest. The owner binding is the existing
length-delimited SHA3-256 construction over domain
`Q-PERIAPT-INDEPENDENT-OWNER/v1` and the initiator public pair. The wrapping key is
not saved in the session directory. Test workers use a separate private config
file; no key or private journal image enters the public artifacts.

The identity signing owner remains separate. A session snapshot contains no
ML-DSA or P-256 signing private key. Waiting bootstrap snapshots retain the actual
ML-KEM/X25519 reply key seed and first hybrid secret, plus the exact signed initial.
Restoration checks that the seed reproduces the signed public reply key and that
the saved secret verifies the signed initial confirmation. It never generates a
replacement key to reopen an operation. Restored entropy is not fresh recovery.

Completed bootstrap snapshots retain both exact signed flights, final confirmation,
session identity and the confirmed root. Activation transfers it into one current
rekey root and four traffic/ACK seeds for epoch zero. Each later epoch has its own
directional chains, ACK keys, counters and records; old rekey roots are not copied
into those traffic records. Public transcript bytes remain available for exact
reconciliation. Restoring private local state
does not grant output permission: bootstrap replay retains advertisement expiry;
established traffic checks the separate credential, roster and policy windows.
Status exposes dispositions without ciphertext or plaintext and can survive expiry.
The external signing owner is required for unsigned rekey work. In local-only
mode, once a control
flight is committed, its exact outbox can be recovered without that private owner,
while current policy/identity/roster validity is still required for release.
Required-witness reopening also needs the original device signer to authenticate
fresh witness requests; cached protocol output does not remove that requirement.

## Required witness ownership

`authenticate(..., witness_pin=pin)` verifies that the signed policy requires
exactly that independently retained instance/key binding, including separation
from both account roots, device keys and policy keys. Omitting the pin still
rejects a required policy; supplying one to a local policy also fails.
The supported witness commands are Query, Advance, Fence and AdmitAuthority with
the unchanged [signed wire contract](../../docs/continuity/WIRE_V1.md#witness-commands-and-receipts).
Fence is an explicit command; the journal always retains its original fence and
never adopts a higher one from a response.

`WitnessSession.provision` persists an inactive first snapshot and returns only
its public `Genesis`. This independent format's first snapshot contains the
prepared, undispatched initial bootstrap operation. It is not the native empty
redb genesis format. The operator authenticates and explicitly approves the
remote initial image through `AnchorGenesis::from_trusted_state` and enrollment;
public metadata alone supplies no enrollment or session authority.
`recover_genesis` reconciles only that original revision-zero creation intent or
revision-one image. It cannot open an operational owner, advance a lineage or
reset missing/advanced state. `WitnessSession.open` requires the configured
client and a fresh witness response before returning a session owner.

The separate image is
`QPREFW01[8] || scope[96] || witness_binding[32] || subject[96] || fence:u64 || revision:u64 || AES-SIV ciphertext/tag`.
The 248-byte prefix is associated data. Subject is the original journal ID,
canonical native credential storage-owner commitment and protocol-policy digest.
The outer scope still binds the independent signing-owner ID and full bootstrap
context. Key derivation uses the distinct
`Q-PERIAPT-INDEPENDENT-WITNESSED-JOURNAL/v1/` image/intent labels over the full
232-byte scope/witness/subject/fence binding. The intent retains the existing
shape, with this distinct authentication key and complete exact target image.
Payload limits and the underlying bootstrap/epoch semantics remain unchanged;
`QPREFS05` adds separately retained peer authority below. Local readers
reject witnessed images; no in-place local-to-witness migration is inferred.

An update authenticates the original local head and freshly queries its exact
`(fence, revision, digest)`. It then durably publishes its exact write intent,
requests the corresponding Advance, requires Advanced or AlreadyAppliedExact,
publishes that exact saved ciphertext, removes the intent and queries again.
Each attempt has a fresh challenge; the original command ID excludes the challenge
and remains stable across retries. A lost response may follow remote commitment.
Recovery retries the saved command rather than sealing another target. A stale
head, conflicting last command or changed fence closes the owner without release.

Ordinary session calls check both head and independently adopted current authority
before work and before returning their result. Status queries use fresh head
checks without gaining ordinary traffic permission. Historical exact-commit
reconciliation can therefore finish after expiry, while ciphertext/plaintext
release remains denied. Authenticated authority denial cannot become a local-only
fallback. Queries and authority responses are admission points, not future leases.

The client serializes calls and verifies both signatures, exact subject/command,
attempt digest and outcome consistency. A failed or reentrantly closed client
cannot release a reply; recovery needs a new client over the same saved command.
The TCP carrier uses one explicit numeric address, exact 3674/3659-byte frames,
a total finite attempt budget of at most 60 seconds and no implicit retries.
All partial I/O uses the remaining deadline. This signed carrier exposes public
metadata; it does not claim TLS confidentiality. Custom host carriers must honor
the deadline themselves; synchronous Python cannot forcibly preempt callbacks.

`witness_checks.py` verifies actual bootstrap, bidirectional consumption and three
PQ rekeys with both durable implementations. It retains three real SIGKILL cuts,
before-dispatch and lost-response faults, stale/corrupt receipts, expired exact
reconciliation, actual witness-store reopen, restored-client-image rejection and
writer fencing after a send commits but before output. Separate controls cover
signature/framing input, total-deadline trickle and close during a valid exchange.
These tests do not restart the whole witness service process, qualify a separate
host or cover the full renewal/revocation/migration lifecycle. Whole-witness
rollback remains outside the guarantee, as do physical erasure and power-loss proof.

## Private file boundary

The session directory is independently supplied, owned by the current UID and
mode 0700. Every path component opens without symlink traversal. A nonblocking
lifetime directory lock excludes other owners; in-process locks serialize the
same owner's methods. Reads and writes recheck the selected directory identity.
Formal files must be private mode-0600 regular files with one link, with bounded
reads and descriptor/path identity checks. Hostile code running as the same user
is not isolated by these permissions.

Plain state is capped at 2 MiB, each file at 2 MiB + 4096 bytes, and new writes
respect 128 directory entries and 64 MiB of retained files. Multi-epoch message
records reserve 64 KiB of the image for bootstrap/control/history completion.
Both the pending plaintext record and its eventual ciphertext row must fit before
the input is committed. Capacity for both
staged publications is checked before admitting a write intent. Failed staging
files remain private and are not chosen as recovery inputs or swept automatically.
An I/O failure can be an unknown commit; it closes the active owner and requires
reopening the same key, identity and context. It never authorizes a new directory.

## Envelopes and transitions

All integers are big endian. The independent image format is:

`QPREFJ01[8] || scope[96] || revision:u64 || AES-SIV ciphertext/tag`.

The complete 112-byte prefix is AEAD associated data. Revision is positive and
below `2^64-1`. AES-SIV uses a 64-byte HKDF-SHA256 key, with salt=journal identity
and info=`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/image-key/ || scope`. The input key is
the external 32-byte wrapping key. The separate intent key is 32 bytes with info
`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/intent-key/ || scope`.

[AES-SIV](https://cryptography.io/en/48.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESSIV)
supports deterministic authenticated encryption. This local format uses that
mode instead of deriving a nonce from a revision that an uncommitted retry might
reuse for different data. It changes no Continuity network cipher or key schedule.
Unsupported provider algorithms fail explicitly.

The intent is `QPREFI01[8] || prior_revision:u64 || SHA256(prior_image)[32] ||
target_length:u32 || complete_target_image || HMAC-SHA256[32]`. The MAC covers
`Q-PERIAPT-INDEPENDENT-JOURNAL/v1/intent/ || scope || all preceding intent bytes`.
Genesis uses prior revision zero and the all-zero prior digest. Every other target
must name the exact current image and have revision exactly prior+1. Both the
target encryption and its protocol payload are verified before any recovery write.

1. Compare the current authenticated image with the caller's expected digest.
2. Seal the complete target and publish its authenticated intent durably.
3. Publish those exact target bytes as `head`.
4. Remove the intent durably, then acknowledge the transition.

Intent publication writes a private exclusive staging file, syncs it, renames it
under the held directory lease and syncs the parent. Head publication uses one
reserved `.stage-head` output slot. An interrupted slot is completed only when its
existing bytes are an exact prefix of the authenticated intent target. Its bytes
never choose a target or supply authority. A conflicting prefix fails unchanged;
other staging files are neither selected nor swept. Repeated interruption of the
same head publication therefore does not allocate new files or exhaust the slots
reserved by the original commit. macOS additionally requests
`F_FULLFSYNC`; an unsupported barrier is an error, not a weaker fallback.
These are OS durability requests, not hardware power-loss qualification.

Unlike redb's atomic row update, this file protocol can legitimately retain both
the exact installed target and its intent after interruption. Recovery removes
that intent without a second increment. If the prior remains, recovery publishes
the saved target. Any other prior/target pair is a conflict; no intent is rebased.

Ordinary open refuses a missing active head. The explicit creation reader can
recover only revision-one genesis, and refuses advanced state. A crash before
formal intent publication can leave only a private staging orphan; creation
recovery then reports missing original intent without guessing or recreating.
The caller's original creation/configuration lifecycle is a precondition; this
primitive does not supply a complete installation manager. Snapshot migration
below is narrower than a product installation or backup-restore workflow.

## Protocol records and release

`QPREFS05` retains the original context and exactly one waiting, confirmed or
traffic phase, including optional control requests and closed-epoch resolution.
`QPREFS01` remains readable
as an epoch-zero format; `QPREFS02` retains its multi-epoch operations without
control requests. `QPREFS03` retains its explicit-target control operations without
resolution. `QPREFS04` retains outcome resolution without peer authority.
Opening these formats does not migrate them: `upgrade_format(now)`
explicitly commits the same session, secrets, reservations and outboxes into
version five. Repeated upgrade is
idempotent; `storage_format()` reports its disposition even after authority expiry.
Older readers reject version five. Migration that cannot retain all state and the
control headroom fails without replacing the old image. Unknown tags/phases,
extra bytes, malformed transcripts and wrong
KEM ownership fail. Traffic records validate exact outbox coverage, disjoint
inbox/skipped-key coverage, contiguous consumption, counters, send budget and
the bounded record counts. There is no unbounded allocation from a stored count.

A new send first commits its exact ID, plaintext and AD as a reservation. Only
then does it derive a message key and encrypt. The next chain and immutable
ciphertext outbox commit before release. A retry cannot change the reservation;
resume uses its stored input. Completed outboxes retain the original send-intent
digest and frame, not another plaintext copy. Receive and consumption similarly
commit before plaintext or an ACK is returned. Rejected packets leave the previous
chain/skipped keys intact. While a send is reserved, receive, consumption and ACK
mutations wait for that original operation. Cutover preparation also waits.
Control preparation and receipt reconciliation use separately reserved headroom
and cannot replace the original send input. Closing an owner from a commit
observer prevents result release even when the target is already committed;
reopening the original store can reconcile that result. Closed-directory and
observer-close checks prevent a `None` handle from selecting the working directory.

## Rekey ownership and retained epochs

Multi-epoch versions store separate confirmed, sending and receiving epochs, the exact
predecessor, the latest completed four-flight transcript and one pending exchange.
The original initiator proposes odd targets; its peer proposes even targets.
Targets advance exactly one step and use the existing signed v6 profile.

| Phase | Retained private/public state |
| --- | --- |
| 1 | Original 96-byte hybrid key seed; no releasable offer |
| 2 | That seed and the exact committed offer |
| 3 | Authenticated peer offer, computed unsigned response body and pending root |
| 4 | Offer, exact committed response and pending root |
| 5 | Offer/response, confirmed pending root and frozen unsigned final body |
| 6 | Exact final and installed new sending epoch; receiving/completion still prior |
| 7 | Offer/response/final, pending root and frozen unsigned receipt body |

Receipt commit installs both responder directions and the completed transcript.
Receipt acceptance commits the proposer's receiving cutover and completion.
Phases 5 and 7 fence new sends, fixing the identity-signed old sending count.
Cached sends remain available. Future-epoch receives are refused until admitted;
old epochs retain their own delayed frames, outboxes, consumption and ACKs.
No rekey root is used directly as a traffic key.

This implementation persists a generated key seed before signing an offer, and
persists computed response body/root before signing a response. It does not use
the Rust engine's pre-computation sealed-randomness tokens. An unsigned fixed body
may be signed again if its first signature was never committed or released; once
an exact signed outbox or authenticated write intent exists, recovery uses those
original bytes. Signing private keys remain external. These different internal
reservation cuts need their own disclosure/refinement analysis; restoring retained
material is not fresh entropy.

At most four traffic epochs are retained. Before each first flight, all epochs
below `max(0, target-3)` must be settled. Unacknowledged sends and unconsumed
plaintext block retirement. Identity-signed close counts bound the old receiving
chain; only already-consumed metadata and skipped keys beyond that count may
expire. The signed send budget covers committed sends across confirmed through
current sending epoch plus an outstanding reservation. Consumption and outbox
deletion do not refund that budget. Receipt confirmation advances the window.
An acknowledged local resolution can also settle an epoch, as specified below;
a pending report alone cannot grant retirement.

## Independent progress requests

Versions three through five separately retain an optional exact request body or committed
signed request. The body uses purpose 13 and the unchanged `QPRKRQ01` wire grammar.
Only the non-proposer can request the next target. A request asserts no settled
history, allocates no KEM key and grants no application credit. Its current
identity/policy/roster authority is checked before release. `BodyPrepared` status
means a durable public body, not Rust's reserved signature randomness; an
uncommitted signature may be computed again. Once committed, only exact wire bytes
are returned. Completion clears that target's request in the same transaction.

`advance_rekey_control(target, signer, now)` performs one preparation/resumption
and returns `(target, wire)` or `(target, None)` for local confirmation. It never
implicitly begins the following target. `receive_rekey_control` dispatches one
bounded input through the original authenticated handlers. A replayed request for
the retained completed target returns the old offer; older or future targets fail.
Invalid authentication or scope cannot allocate replacement work.

`start_rekey_control` additionally resends the last receipt when the responder has
completed locally but may never have dispatched it. `replay_rekey_control` checks
the original output against its committed outbox and current authority; it cannot
create a new request after the old target has completed. Status remains readable
after expiry. The host must bound transport attempts/deadlines and continue
servicing incoming controls after local completion. Dropping output stops host
dispatch; it does not undo a commit. The control-pipe tests are not an implemented
network carrier, timer scheduler or energy optimization.

These rules provide SDK consumption accounting, not atomic external application
effects. The host must deduplicate and commit its own effects before consumption.
Same-key backups and old filesystem pages can retain prior secrets. Logical
removal is not cryptographic erasure; consistent whole-store rollback is not
detected by this local-only profile. Python bytes/provider temporaries do not
provide a zeroization guarantee. Observed rekey completion is a protocol counter,
not evidence that an adversary has lost keys. No post-compromise security proof
is claimed by these runtime checks.

## Retained peer renewal and revocation

`admit_peer_credential_renewal(wire, operation, target, now)` adopts a root-signed
`QPRNB001` grant for the existing remote device. `target` is a separately obtained
40-byte account checkpoint; it is not selected from incoming grant bytes. The
original account root, device ID/generation, credential commitment, full signing
key and exact protocol policy remain fixed. Verification authenticates all three
credentials, both complete rosters and the purpose-15 statement. Predecessor
membership is historical evidence; the successor must be valid at the actual
supplied current time. Validity retains the original start and strictly extends
the predecessor end. No grant restores missing session state or authorizes a new
bootstrap from a historical advertisement.

Adoption requires the exact currently retained predecessor checkpoint and
credential. The same operation/statement at the same current target is read-only,
even if the root re-signs that statement with different signature randomness;
the first committed wire remains unchanged. Another operation, an older/forked
head, changed original lineage or an already observed revocation fails. Both
local-only and required-witness modes commit through their existing exact-target
transactions; a lost result is reconciled using the original owner and input.

`admit_peer_roster(wire, target, now)` adopts a separately pinned, monotonic signed
remote account head. An empty roster is valid revocation. Changing a credential
within the same generation requires the renewal grant rather than a bare roster.
A removed or replaced original generation cannot reappear in this session.
The terminal revoked head remains retained; later generation adoption needs a
separate device/session lifecycle. No global newest-roster discovery is claimed.
These entries reject same-account peers because their roster can also revoke
the local member and needs the local joint authority coordinator.

`peer_authority_status` reports the exact checkpoint, credential commitment,
retained renewal operation and active-membership flag. Historical status survives
expiry without returning plaintext or dispatch permission. Maintenance checks
current local credential/roster and policy, while an expired remote credential
does not prevent admission of its valid successor grant.

New snapshots use `QPREFS05`. Immediately after the unchanged tag/context/phase
prefix, a zero presence byte means original peer authority. A one byte adds
`grant_target[40] || grant_length:u32 || grant || roster_length:u16 || signed_roster`.
An absent grant requires length zero and a zero target. A present grant is at
most 65,536 bytes; a roster is at most 8,192 bytes and still has the canonical
32-member bound. Every open reauthenticates the grant and roster against original
roots and policy, checks the retained target ordering and binds the derived
current peer only to traffic in this actual established snapshot. The bootstrap
context, prekey selections and original signed flights do not change.

Formats one through four remain readable without implicit mutation. Explicit
`upgrade_format` preserves all original operations and returns only the version.
An established owner's upgrade requires live local authority and policy, and its
normal witness admission; the remote credential may have expired. This metadata
transition grants no output permission. New peer authority cannot be encoded into
an older format, and a derived session view cannot be used as a fresh create/open
input. Retained public metadata reduces business-record capacity by its encoded
size, preserving the existing 64-KiB control-completion reserve. Insufficient
capacity refuses adoption without dropping traffic or changing the original target.

Before a result returns, the owner checks the currently committed peer authority,
including changes made by a reentrant host observer after the operation's write.
A local authority-generation counter also detects changes inside the final
witness transport callback, after the last state read. Such a change withholds
the result and leaves the committed state for original-owner reconciliation.
The counter is an in-process observation guard, not a persistent anti-rollback
mechanism or freshness lease. Runtime tests preserve both demonstrated pre-fix
counterexamples; ordinary operation-entry checks alone were insufficient.

## Closed-epoch application accounting

`begin_closed_epoch_resolution(epoch, now)` explicitly and irreversibly freezes
an already closed old epoch. Both directional cutovers must be committed.
Creating a new report is refused while a request or rekey is pending. An existing
frozen report remains retrievable during later control work, with current
authority. Status can be queried after expiry without releasing its plaintext.

The immutable report contains the original unconfirmed IDs and ciphertext digests,
retained unconsumed plaintext, skipped indices, counters/floors and signed peer
close count. A hole does not assert an honest message existed. Old-key disclosure
may have invalidated the authenticity of retained plaintext. The host must retain
and account for this data without silently treating it as a new business effect.
Old send/resume/receive/consume/ACK operations are fenced as soon as the freeze
commits; current-epoch operations, including an already reserved send, remain valid.

Each report gets a separate platform-random 32-byte HMAC-SHA256 key. Its immutable
ID uses the exact body/domain in the native [resolution contract](../continuity-identity-candidate/EPOCH_RESOLUTION.md#identity-and-stored-state).
Private intent fingerprints and plaintext digests stream into the MAC; they are
not exposed as public report fields. The report key is sealed with the frozen
traffic, never returned, and is unrelated to old traffic/ACK keys. A saved intent
or report restores the same key and ID. A pre-intent interruption releases no
report and does not turn an orphan staging file into authority.

The host durably records its own deduplication/quarantine/unknown-outcome decisions
before `acknowledge_closed_epoch_resolution(epoch, id, now)`. That second commit
removes the old ciphertext rows, plaintext, intent fingerprints, skipped keys,
four traffic/ACK keys and report key. The exact ID and original counters/floors
remain. Unconfirmed sends become `DeliveryUnknown`, never `Acknowledged`; a
different report ID conflicts and repeating the original acknowledgement is
idempotent until collection. No cancellation reactivates old keys. The host's
application file/database is a separate transaction; SDK acknowledgement neither
undoes earlier effects nor prevents already released packets reaching a peer.

Version four stores a bounded sorted resolution metadata map in the reserved
control headroom: count:u8, then epoch:u64, phase:u8 and ID[32], with key[32] only
for frozen phase one. Phase two is acknowledged; ordinary epochs have no entry.
There are at most four entries. The report body is reconstructed from the frozen
traffic, avoiding a second serialized plaintext copy. Decoding verifies its MAC.
Acknowledged traffic has a distinct invariant: empty maps and zeroed four keys,
no report key, but its original unacknowledged range. Only that acknowledged state
can satisfy retirement in place of ordinary draining. A later signed cutover
collects the epoch and its resolution metadata together.

Removal is logical: Python bytes, old images, intents, filesystem pages and backups
do not provide physical erasure. The direct host report can contain up to 64
retained 16-KiB plaintexts. Test orchestration's bounded native pipe is not a
network serialization or a general application report API.

## Validation entrypoints

The [local-only credential contract](LOCAL_CREDENTIAL.md) specifies conditional
version seven. Pending grants, current local identity, the last abandonment and
its time floor share the original authenticated journal transaction. It requires
an established session under the original local-only policy. Both Pending and
final metadata must fit before staging; combined metadata is charged to business
capacity without shrinking control headroom. Initialization refuses any existing
head, intent or authority record before publishing a new head.

The [joint local renewal contract](LOCAL_RENEWAL.md) specifies conditional
version six, its separate authenticated control record, typed exact-target intent,
terminal-before-ACK ordering and historical cleanup. It keeps the original
witness subject and does not turn an unsubmitted ordinary write into renewal.

`control_checks.py` uses an archived version-two writer and its complete peer
source closure, preserves a pending send and original offer through explicit
upgrade, and exercises the request/body/signature boundaries in fresh workers.
Its fixed schedules drop and duplicate each distinct control flight once, bound
attempts/queue size and exercise both initiating roles without dummy traffic.
This checks the one-step driver and host retry contract; it is not a measurement
of a real network scheduler or a fully restarted Rust endpoint.

`resolution_checks.py` begins with the complete archived version-three writer,
retains a pending current-epoch send while freezing old traffic, and loses both
pre-intent and committed results in real worker processes. It checks exact
reports, explicit application decisions, all old-operation fences, unchanged
floors and later collection. `resolution_capacity_checks.py` returns all 64
retained 16-KiB plaintexts through the direct Python API. The existing capacity
lane freezes 64 old outboxes when the business-record allowance is full and
checks observers closing the owner after freeze/acknowledgement commit.

`resolution_disclosure_checks.py` is an isolated counterexample, not a production
forge API. Only the epoch-zero send chain after the first honest message is given
to its forge function; it receives no identity, root, KEM, journal or ACK key.
Two forged old packets are consumed by the real Rust peer. Its resulting ACK
floor is three while the honest sender sent only one message, so the sender must
refuse the ACK and retain the original outbox. The earlier valid ACK is deliberately
not delivered to the sender; if a host retained that ACK, ordinary recovery would
remain available. After three actual rekeys the original epoch blocks target
four. Explicit unknown-outcome accounting then admits the same original offer
and permits further traffic. This establishes that specific accounting/progress
behavior, not recovery of confidentiality or authenticity after compromise.

`storage_checks.py` kills real worker process groups at eight write boundaries
for both genesis and update, and checks exact-target/idempotent recovery, lost
acknowledgements, wrong keys/scopes, malformed files, leases, CAS races, conflicting
authenticated predecessors and capacity before intent publication.
It also repeats interrupted head recovery at the 128-file limit, retains unrelated
staging files, checks constructed partial output prefixes and rejects conflicting
output-slot bytes without overwriting them.
Workers run directly under the already admitted isolated Python bootstrap and
the parent's private empty cache prefix. Each cut records the actual worker PID,
which must equal the PID being killed and waited for. Waiting only for a launcher
shell does not establish that a child journal owner's lease has been released.

`durability_checks.py` uses fresh processes for operations against a live Rust
journal. It kills the independent peer after final commit, send reservation, send
commit, ACK publication, receive commit and consumption commit. It recovers the
original ciphertext, plaintext and ACK, verifies retired IDs and expiry, and runs
malformed snapshot controls. The identity signing key is not passed to any worker.
The test clock is explicit: bootstrap at 150, advertisement expiry at 160,
established traffic at 170, authority expiry at 200. Rust process restart,
network/TLS carriers, hardware power loss and the broader lifecycle remain separate.

`durable_rekey_checks.py` uses the archived old writer to create a genuine version-one
snapshot, interrupts its explicit upgrade, then runs eight alternating exchanges
with fresh worker processes. Nine protocol-stage kills, one publication kill and
the upgrade kill exercise exact control recovery, directional switches, external
signer availability, current validity, a real signed budget of four and blocked
retirement until the original old ACK arrives. `capacity_checks.py` builds a real
two-epoch journal with 122 maximum-size outboxes, rejects a reservation whose
ciphertext cannot fit, and commits/reopens/decrypts an exact-fit message. Private
signing fixtures remain outside the session and public artifact trees.

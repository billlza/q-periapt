# Encrypted device journal candidate

`DeviceJournal` connects the actual [bootstrap](BOOTSTRAP.md) to redb. It can
recover a pinned response after its original signing/prekey owners have closed.
This remains an unpublished candidate; it does not complete the 0.2.0 session
store, ratchet or recovery contract.

## Ownership and storage identity

`JournalKey::provision` generates a fresh OS-random 256-bit wrapping key and writes
`QPVKEY01[8] || key[32]` to a new private file without replacing an existing path.
`open` requires that exact existing file and never creates a replacement on error.
The owner has no raw-key export and erases its memory on drop. Keep its file outside
database backups. This provider assumes a trusted same-UID host and supplies
neither a hardware keystore nor per-record cryptographic erasure.

After successful provisioning, retain `JournalIdentity` independently of the
database. Opening requires this expected identity and an independently verified
local device. An incoming database cannot choose its expected identity. The owner
binding hashes account, device ID, generation and credential digest using the
bootstrap `storage-owner` domain. Roster updates can retain this owner; a different
credential/generation cannot silently reuse it. One authoritative journal per
device lineage is a host configuration requirement; a new empty journal is not
recovery.

The candidate reuses `q-periapt-host-store::filesystem` private path admission,
exclusive provisioning and lifetime database locking. Path traversal is descriptor
relative with private mode/owner/ACL checks and no symlink traversal. The shared
backend rechecks the inode/extent **after** acquiring the lock and rejects an
unclean redb file lacking the two-phase recovery flag. Its file limit is 64 MiB and
cache is 2 MiB. The policy store uses this same backend and retains its policy and
commit-uncertainty behavior.

The same journal supports both local roles and its local prekey inventory. Kind 1
is responder, kind 2 initiator, kind 3 prekey, kind 4 message state and kind 5 account
roster; initiator records cannot claim remote prekey consumption. This unreleased
local v16 schema rejects v1–v15 tables/headers without implicit migration or reset.
The network bootstrap bytes and SDK ABI major **2** are unchanged.

## Sealed encoding

Exactly one table, `continuity_device_candidate_v16`, holds one `image` row and an
optional authenticated `pending` write-intent row. The [write-intent contract](WRITE_INTENTS.md)
defines exact-target recovery and the two transactions used for each state advance.
The image is:

`QPVLT016[8] || store_id[32] || owner[32] || revision:u64 || nonce[24] || ciphertext || tag[16]`

The 104-byte header is associated data for XChaCha20-Poly1305. The wrapping key and
fresh OS-random 192-bit nonce are not network inputs. Revision is in `1..u64::MAX`,
with the upper bound excluded. The encrypted plaintext is:

`QPVIMG16[8] || protection[73] || local_account[32] || count:u16 || records`

`protection = mode:u8 || policy_digest[32] || witness_binding[32] || fence:u64`.
Local mode is exactly 73 zero bytes. Required mode is 1, with nonzero policy and
witness digests and a fence in `1..u64::MAX`. Provisioning starts at fence 1;
ordinary recovery cannot replace it. The [required-anchor contract](REQUIRED_ANCHOR.md)
checks this metadata before applying any pending intent. Old tables/images are
rejected; this candidate provides no implicit migration.

Each record is `operation_id[32] || context[32] || kind:u8 || phase:u8 ||
authority_count:u8 || accounts[authority_count*32] || key_count:u8 ||
fingerprints[key_count*32] || reference_count:u8 || prekeys[reference_count*32] ||
payload_length:u32 || payload`.
The [roster contract](ROSTER_AUTHORITY.md) requires retained account heads for each
record and keeps the local account immutable across pending writes. There are at
most 64 roster records, 128 session-operation records, 1024 prekey records, two one-time
claims per responder record and 2 MiB of total plaintext. The byte limit applies
even before either count limit is reached. Inventory-backed responders reference
exactly two prekey record IDs, PQ first then classical; other records have none.
Records and fingerprint lists are strictly sorted; duplicate claims fail. No
automatic eviction or counter wrap can reactivate an old one-time key.

Responder operation ID uses the identity candidate's length-prefixed digest function with
domain `Q-PERIAPT-CONTINUITY-VAULT-OP-CANDIDATE/v1` over context plus complete signed
initial wire. Callers cannot supply an unrelated ID. Each API also checks exact
initial bytes, context and derived claims. Claims use authenticated public-key
fingerprints, so a new signed manifest/epoch cannot relabel a consumed public key.

Executing/rejected responder records retain the initial wire. Responder plans use
the encoding below. Prepared/awaiting-final/complete records hold a private
checkpoint: `QPRCHK01[8] || context[32] || initial[5817] || reply[4633] || root[32] ||
state:u8 || tail`. State 1 has a 32-byte initiator-confirmation key; state 2 has the
exact accepted final[136] and no confirmation key. State 3 has that same final
with a zero root placeholder after the atomic transfer to linked message chains.
The [message contract](MESSAGES.md) defines phase 19 and its one-to-one image
checks. The crate-private restore path
is used only after image authentication and rechecks both signature components,
lengths, context and transcript relationships. Network input cannot mint this
checkpoint. The public journal returns response bytes or a **public session ID**,
never a raw root or application key.

Encrypted extent, stable store/owner headers and revision remain visible; there is
no padding/unlinkability claim. Zeroizing buffers do not erase encrypted old pages,
backups or all compiler/provider temporary copies.

## Local prekey inventory

`PrekeyId` is an independently retained nonzero public provisioning-request ID.
`generate_prekey` binds that ID to the local device owner, complete 68-byte SDK
policy, leaf role and validity. It validates the policy/device/roster interval,
commits `PrekeyReserved` (15) with a sealed SDK key-generation command, generates
the actual key internally, and commits `PrekeyAvailable` (16) before returning
the public `PrekeyLeaf`. Resuming the same ID cannot change its role, policy or
validity. Each entry uses a complete SDK hybrid key but exposes only its selected
component. Neither private bytes nor the recovery token cross this public API.
Known public fingerprints must be distinct across inventory roles and states.

Inventory operation IDs use `D("Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-ID/v1", request)`.
Here `D` is the same length-prefixed digest function used for the journal operation
ID above, with the complete literal domain supplied. The entry intent uses domain
`Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-INTENT/v1` over `sdk[68] || kind:u8 || validity[16]`.
The SDK generation operation uses domain
`Q-PERIAPT-CONTINUITY-PREKEY-INVENTORY-GENERATION/v1` over
`journal_id[32] || owner[32] || inventory_id[32] || intent[32]`.

The payload is `QPPKEY01[8] || request[32] || sdk[68] || kind:u8 || validity[16] ||
public[32 or 1184] || data`. Reserved entries have a fixed-width all-zero
unpublished public placeholder, so publishing the real key needs no extra space.
Reserved/available `data` is the exact 277-byte SDK token. Consumed entries
replace it with the consuming responder operation ID[32]; retired entries remove
it. Available/consumed public bytes must form a valid leaf. A retired reserved
entry can retain its zero placeholder. IDs and public fingerprints are not evicted.

`respond_from_inventory` resolves the authenticated selection against available
entries with matching policy, role, fingerprint and validity. It commits the
response reservation and both inventory references before restoring the keys.
Restoration verifies each token's full scope and reconstructed public component.
An invalid/substituted token closes the journal without selecting new randomness.
This allows `Executing` recovery after process loss without an external prekey
owner. Subsequent stages share the same responder state machine as `respond`.

The response outbox transaction also changes selected one-time entries to
`PrekeyConsumed` (17), replacing their logical tokens with the consuming ID.
Reusable entries remain available. Image admission checks both directions of the
reference/consumption relationship; an outbox cannot coexist with an unconsumed
one-time reference. `retire_prekey` removes an available/reserved entry's logical
token and commits `PrekeyRetired` (18). A pending response reference blocks
retirement, including for reusable keys. Consumed entries keep their tombstone.
Reusing a retired or consumed request never generates a replacement key.

`prekey_status` reconciles an exact request after policy close/expiry; `prekey_leaf`
only returns currently usable available public keys. Unknown generation or
retirement commits require reopening/querying the retained request, just like
response commits. Logical consumption/retirement does not erase old encrypted
pages or backups and does not supply rollback detection.

## Responder transitions

`respond` performs bounded public signature/scope admission, then:

1. Commit `Executing`, the exact initial and one-time reservations.
2. After acknowledgement, authenticate the initial with the exact selected prekeys.
   This decapsulation and MAC check are deterministic and may resume from `Executing`
   when those owners are available. No fresh responder contribution executes yet.
3. Commit `ResponseKemReserved` (13): the admitted S0, fresh nonce and exact sealed
   encapsulation command. The original prekeys are no longer needed for this operation.
4. Compute the response body; commit `ResponseSignatureReserved` (14) with that
   complete body and its purpose/body/owner-bound signing randomness before signing.
5. Commit `Prepared` with the exact private result and signed response.
6. Commit `AwaitingFinal`, consuming the claims together with the immutable outbox.
7. Recheck policy/lifetime before returning response bytes.

`respond` resumes an `Executing` record with the original selected prekeys;
`respond_from_inventory` restores those owners from its committed local inventory.
`resume_response` resumes a contribution or signing plan using only the original
device signer. That signer can be restored from a separately protected
[signing-owner file](SIGNING_OWNERS.md); the journal checks its exact enrolled public
identity. Signing files are provisioned before enrollment, outside this journal.
Signer-free `resume` can replay a pinned result
but cannot perform unfinished signing. Missing owners are explicit failures, never
requests to generate replacement keys or coins. A wrong prekey/signer is refused;
local/transient failure retains the selected work. A definitive MAC or invalid-share
failure commits rejection before clearing one-time reservations.

Response scope is `D("Q-PERIAPT-CONTINUITY-RESPONSE-PLAN/v1",
journal_id[32] || context[32] || record_operation_id[32])`. Bootstrap `H` labels
`durable-reply-kem` and `durable-reply-sign` derive distinct command IDs. Plan bytes:
`QPRPLN01[8] || phase:u8 || context[32] || scope[32] || initial[5817] || S0[32] ||
nonce[32] || kem_token[245]`. Phase 14 appends `reply_body[1256] ||
signing_binding[32] || signing_randomness[32]`. Exact sizes are 6199 and 7519 bytes.
S0 is admitted only by actual initial authentication or by the authenticated encrypted
local image, never by a public secret constructor. The context and exact initial
still bind the prekey claims. Normal execution retains the derived schedule across
acknowledged writes; restart recomputes the same KEM result, verifies the saved body
and signs it with the same reservation. Result pin retires this plan's S0 and coins
from the logical record, without claiming erasure of old encrypted database pages.

Every logical write first persists the exact sealed target, then applies it and
removes the intent in a second transaction. Both use immediate durability and redb
two-phase commit. The expected encrypted aggregate digest is compared again inside
each write transaction. Reopening checks the expected store identity before settling
a pending write, and never reseals its saved target.
Invalid signatures fail before reservation; a definitive cryptographic failure
writes `Rejected` and clears reservations. A different initial claiming a reserved
or consumed one-time public key fails. A pinned response replays its exact bytes
without signing, decapsulation or new KEM randomness.

`finish` validates the real final MAC and commits completion before returning its
public session ID. Invalid final input does not advance storage. Exact duplicates
are idempotent; changed final bytes conflict. Returning bytes is local dispatch
permission, not transport delivery or an application-delivery acknowledgement.

Write failure closes the database lease and wrapping-key owner. `CommitUncertain`
is not absence or success. Reopen under the retained identity and query the same
authenticated input:

| Phase | Recovery |
| --- | --- |
| Absent | Reservation did not survive; no crypto crossed its acknowledgement barrier |
| Executing | Repeat initial authentication with the exact selected prekeys, restored internally for an inventory-backed operation |
| ResponseKemReserved | Resume the sealed contribution and signing with the original signer; prekeys are no longer needed |
| ResponseSignatureReserved | Recompute/check the same body and sign with the saved randomness |
| Prepared | Commit the pinned result without rerunning crypto |
| AwaitingFinal | Replay the exact response |
| Complete | Exact final replay returns the same session ID |
| Rejected | Retain the failure; do not reinterpret it as a new operation |

Read-only reconciliation remains available after policy close/expiry. Execution,
dispatch and final acceptance retain their policy/time/runtime checks. A missing,
corrupt or wrong-key database is an error, never the `Absent` result.

## Initiator persistence and reply selection

The host retains a public `InitiationId` before calling `initiate`. Its index is
the length-prefixed digest of that ID under
`Q-PERIAPT-CONTINUITY-VAULT-INITIATION-CANDIDATE/v1`. Context is checked separately,
so reusing an ID with another context conflicts instead of creating a second
operation. The ID is correlation data, never KEM entropy or an authorization.

`initiate` now persists three closed computation plans before executing them:

1. `InitialKeyReserved` (10): platform-generated nonce and SDK sealed key-generation coins.
2. `InitialKemReserved` (11): the exact reply public key/context is known; SDK
   sealed encapsulation coins bind that complete command.
3. `InitialSignatureReserved` (12): the complete initial body and purpose/body-bound
   signing randomness are committed before either signature is computed.

It then pins `Prepared` with private state and commits `AwaitingReply` with the
immutable initial outbox before returning bytes. Retrying `initiate` with the same
request/context and original signing owner continues the exact saved plan. Key quota,
temporary entropy/provider failure and unavailable signer retain the pending stage.
The signer or its protected recovery handle must still be available before the
signed result is pinned. It is not stored in this journal. Wrong signer/context
cannot replace the command; invalid stored KEM material closes the journal.

The operation scope is `D("Q-PERIAPT-CONTINUITY-INITIATION-PLAN/v1",
journal_id[32] || context[32] || record_operation_id[32])`. Bootstrap `H` labels
`durable-initial-key`, `durable-initial-kem` and `durable-initial-sign` derive distinct
stage IDs from this scope. Thus a plan cannot move to another journal or context.
The SDK recovery owner derives its separate sealing key from the protected journal
key using the [sealed-operation contract](../../docs/SDK_SEALED_OPERATIONS.md).

Plan bytes, after the request ID prefix, are:
`QPIPLN01[8] || phase:u8 || context[32] || scope[32] || nonce[32] || key_token[277]`.
Phase 11 appends `kem_token[245]`; phase 12 additionally appends
`initial_body[2440] || signing_binding[32] || signing_randomness[32]`.
Plan lengths are 382, 627 and 3131 bytes. The signing binding is the candidate `D`
under `Q-PERIAPT-CONTINUITY-SIGNING-RESERVATION/v1` over the full signing public key,
sign-stage ID and exact purpose-prefixed signed message. These private fields stay
inside the authenticated encrypted image. There is no public raw-signing-coin API.

Normal execution retains owned keys/contributions across acknowledged transitions.
These volatile caches are never needed for correctness. Restart recomputes from the
sealed KEM commands; a saved signing body must exactly match this recomputation.
Both signatures replay byte-for-byte, including the deterministic P-256 component.
No new crypto entropy is chosen for a command whose reservation already committed.
The signer-free `resume_initial` cannot execute a plan; after result pin,
it verifies the saved signature and needs no signer or private-key import slot.

The private checkpoint is `QPICHK01[8] || context[32] || initial[5817] || state:u8 || tail`.
State 1 contains first KEM contribution[32] and the SDK expanded reply key[2440].
State 2 instead contains reply[4633], root[32] and final[136]. Every initiator record
payload prefixes its request ID[32]. The first contribution stays in an internal
zeroizing owner; no public SDK raw-secret constructor is added. Restoration uses
the checked expert key import and requires its reconstructed public bytes to equal
the key in the signed initial. Invalid material/pairing closes the journal;
temporary quota/entropy failure retains the exact selected work.

`accept_reply` verifies the responder signature/context, then commits
`ProcessingReply`: the waiting checkpoint plus the exact signed reply. Only then
does deterministic confirmation processing run. Different reply bytes conflict
while selection is pending. A definitive MAC/noncontributory-share rejection
commits a return to `AwaitingReply`; local/transient errors retain the selection.
An uncertain rejection write must also be reconciled before selecting another reply.

Successful processing pins `FinalPrepared` with the exact reply/root/final wire,
then commits `FinalCommitted` before returning `CommittedInitiation`. The completed
checkpoint contains neither S0 nor the private reply key. Final replay needs no
private-key import or fresh KEM randomness. `FinalCommitted` is distinct from the
responder's `Complete`: local outbox commit does not prove remote final receipt.
Phases are 1=Executing, 2=Prepared, 3=AwaitingFinal, 4=Complete, 5=Rejected,
6=AwaitingReply, 7=FinalCommitted, 8=FinalPrepared, 9=ProcessingReply, with the three
initial computation plans at 10–12, responder plans at 13–14 and prekey states at 15–18. Absent=0
remains query-only. The responder uses exact initial bytes for reconciliation;
the initiator uses its retained request ID and context.

Both journals reopen and preserve equal roots for all four modes. An additional
64 before/after-sync faults cover twenty initial and twelve reply-processing sync points.
Eleven initiator processes are killed at eight durable boundaries and after each
of the three reserved computations but before its result is pinned. Public outputs
from those interrupted computations are compared byte-for-byte after restart, and
an independent live responder verifies the final MAC. Other tests exercise held
key quota, unavailable/wrong signing owners, reply/context substitution, old schema/
role rejection, and invalid stored keys/tokens. Recovered signing reservations also
reject a different key, purpose, operation ID or body.

## Verification and required follow-through

Real-peer tests cover all four modes, private checkpoint preservation, owner close,
database reopen, exact replay, bad signatures/MACs, wrong key/store identity,
header/ciphertext corruption and cross-manifest public-key reuse. A sampled disk
scan detects plaintext root bytes; it is not a general forensic-erasure proof.
The fault matrix covers twenty synchronization points across five response transitions
both before and after sync (40 cases), eight final-confirmation sync failures and
a first-write failure that reconciles to exact absence.

Eight responder process cuts cover six committed boundaries and the two
post-computation/pre-result-pin windows. An independent initiator stays alive and
verifies response/final MACs after recovery. The original prekeys die with the child;
saved contributions recover without them. Pinned results replay after the signing
owner closes too. The external-owner API remains suspended when `Executing` lacks its prekeys. This
stronger live-peer harness replaces the earlier four-cut self-contained harness and
retains its owner-loss/no-early-output assertions. Production builds contain no
test-only parking or public-output capture hooks.

Inventory tests cover all four selections, sixteen generation sync faults, forty
response sync faults and eight retirement sync faults. Three generation process
cuts cover the reservation, computed-key/pre-publication window and available
commit; three response process cuts cover initial authentication admission, pinned
result and committed outbox. The original prekeys exist only in the killed child;
a surviving actual initiator verifies recovery, including from `Executing`.
Token corruption/substitution fails closed, and authenticated images with
inconsistent consumption/outbox state are rejected.

Both roles now replay reserved cryptographic commands, and local inventory
restores the selected prekeys before first responder authentication. A completed
bootstrap is not a full session lifecycle. Protected signing files now restore
matching owners for unfinished operations. Installed account rosters now fence
revoked devices and retained contexts, and the message layer supplies durable
per-message state and consumption acknowledgements. Cryptographic erasure, full
identity rotation, cancellation, supersession, ratchet/rekey and multi-device
transactions remain implementation work. Local write intents now retain
the exact outer encrypted aggregate across state-write retries. Required-anchor
journals derive their immutable witness command from that intent and verify fresh
evidence at open, state application and result release. The rest of G1's complete
effect lifecycle remains required.

Store identity alone does not detect an older snapshot of the same journal. The
required-anchor profile rejects it while the independent witness retains its newer
head. Old encrypted pages remain decryptable with the wrapping key. Witness
deployment, backup/erasure model and complete wire/state/budget lock remain required
in **0.2.0** before product promotion.

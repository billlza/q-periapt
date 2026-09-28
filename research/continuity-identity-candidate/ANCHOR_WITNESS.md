# Authenticated monotonic witness candidate

`AnchorStore` is a real persistent compare-and-advance provider with authenticated
device requests and ML-DSA-65 **and** P-256 witness replies. It provides the witness
side of the rollback-anchor contract. The [required-anchor journal](REQUIRED_ANCHOR.md)
now connects signed witness requirements, exact durable commands and bounded TCP
exchanges to state-application and release gates. Deployment and the complete
rollback recovery workflow remain required in 0.2.0. The SDK ABI stays **2**.

## Authority and enrollment

The operator retains an independently generated `AnchorIdentity` and pins the
witness public key. `AnchorPin` binds both through the length-prefixed SHA3-256
digest with domain `Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1` over
`instance_id[32] || public_pair[1985]`. An incoming response cannot choose this pin.
The separate `AnchorSigningKey` uses protected signing-file role **4**. It has no
private-key export or arbitrary-message signing API.

`DeviceJournal::anchor_genesis` derives an `AnchorGenesis` only from its authenticated
empty revision-1 image, matching verified device owner and policy family. The object
contains public metadata; it does not anchor the journal or grant release permission.
The witness's explicit control-plane `enroll` accepts that object with independently
verified device/policy inputs and trusted time. It checks current mode/runtime/time,
exact owner/policy, and the intersection of credential, roster and policy validity.
The witness key must share no component with the device, account root or protocol
authority, and its ML-DSA component must differ from the SDK policy root.

Each entry binds `subject = journal_id[32] || owner[32] || policy_digest[32]`.
Owner uses the existing bootstrap storage-owner derivation. The index is the same
length-prefixed digest under `Q-PERIAPT-CONTINUITY-ANCHOR-SUBJECT/v1` over
`authority_binding || subject`. Only one subject may be registered per credential
owner. Exact enrollment retries retain an advanced head; a changed genesis,
journal, policy or enrollment checkpoint cannot reset it. Ordinary request bytes
cannot create registrations. Authorization refresh, revocation and migration need
separate authenticated control-plane transitions; enrollment does not track later
roster changes automatically.

## Heads, commands and attempts

An `AnchorHead` is `fence:u64 || revision:u64 || encrypted_image_digest[32]`.
Integers are big-endian, nonzero and below `u64::MAX`; digests are nonzero. A
constructed head is an expectation, not an authenticated receipt. Enrollment starts
at fence/revision **1/1** with the actual genesis image digest.

| Command | Exact transition |
| --- | --- |
| Query (1) | Read one already enrolled subject; no mutation or implicit genesis |
| Advance (2) | Require the full expected head, preserve fence, increment revision by one and require a different next image digest |
| Fence (3) | Require the full expected head, increment fence by one and preserve revision/digest |

Command encoding is `kind:u8 || expected_head[48] || next_head[48]`, exactly
97 bytes. Query's 96 head bytes must be zero; they are an explicit query encoding,
not a default state. Mutations cannot alter unrelated fields or overflow counters.
The immutable command ID uses domain `Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1` over
`authority_binding[32] || subject[96] || command[97]`.

The subject and command provide strict `to_bytes`/`from_trusted_state` codecs for
authenticated local retention. Restoring them grants no current-head authority;
it lets a restarted client create a new attempt for the exact original command,
including status reconciliation after enrollment expiry. Retained bytes must not
be replaced by untrusted incoming metadata.

Every attempt obtains a new platform-generated nonzero 32-byte challenge and a
fresh device signature. The immutable command excludes challenge/signature bytes;
retrying it never selects another expected/next state. A reply also binds the digest
of the complete attempt body under `Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1`.
Old replies cannot answer another attempt. This challenge binding is not a network
deadline or a promise that no other writer can advance after a signed observation.

`AnchorRequest::close` stops receipt admission without undoing an already dispatched
mutation. Verification atomically admits at most one valid result for an attempt,
including concurrent verifiers. Invalid replies do not consume it. A cancelled,
timed-out or missing acknowledgement must be reconciled using the same immutable
operation and a new attempt; durable operation cancellation is separate work.

## Exact signed wire

Both use the identity candidate's existing signature prefix/context and canonical
dual signature. Request purpose is **7**, reply purpose **8**; other purposes fail.
The envelope is `body_length:u32 || body || ML-DSA_signature[3309] || ECDSA[64]`.

Request body (297 bytes; envelope 3674):

`QPANRQ01[8] || authority_binding[32] || subject[96] || command_id[32] || challenge[32] || command[97]`

Reply body (282 bytes; envelope 3659):

`QPANRS01[8] || authority_binding[32] || subject[96] || request_digest[32] || command_id[32] || outcome:u8 || observed_head[48] || has_last:u8 || last_command[32]`

Outcomes are Current=1, Advanced=2, AlreadyAppliedExact=3 and Conflict=4. Query
accepts only Current. Applied outcomes must match the exact next head and command
ID. The same next tuple reached through another command is a conflict. Conflict
does not yield `applied_head`; an internally contradictory signed outcome fails.
`has_last=0` requires zero last-command bytes and fence/revision 1/1. Later states
require `has_last=1`. No trailing bytes or unknown discriminants are accepted.

## Persistent witness state

The private, bounded host-store backend provides an exclusive database lease. The
single `continuity_anchor_candidate_v1` table contains exactly one `image` row:

`QPANC001[8] || authority_binding[32] || store_revision:u64 || count:u16 || entries || HMAC[32]`

Entries are strictly sorted by subject index and contain:

`index[32] || subject[96] || device_public[1985] || enrollment_authority[32] || validity[16] || genesis_digest[32] || head[48] || has_last:u8 || last_command[32]`

Each is 2274 bytes. There are at most 256 entries, a 1 MiB authenticated-image cap
and the shared 64 MiB database cap. No eviction resets a head. The image contains
public commitments/verification metadata, not journal roots or signing secrets;
its contents are authenticated rather than encrypted. HKDF-SHA256 with default zero
salt and info `Q-PERIAPT-CONTINUITY-ANCHOR-STATE-KEY/v1` derives a distinct 32-byte
HMAC-SHA256 key from the witness's protected wrapping key.

The provider checks the stored device signature before admitting a request. State
or fence advancement requires the complete expected tuple. It compares the current
aggregate digest again inside the write transaction, commits with immediate
durability/two-phase commit, and only then signs the reply. Exact retries match both
the current next head and last command ID without advancing again. Older commands
whose state has been superseded conflict; the provider never silently rebases them.

Storage failures close the database and key owners. `CommitUncertain` is not rejection
or absence. Reopening and retrying the same command reports either its first exact
application or AlreadyAppliedExact. If reply signing fails after state was observed
or committed, `ReplyUnavailable` explicitly requires reconciliation; it cannot be
treated as an unperformed mutation. Expired enrollment permits authenticated status
queries for reconciliation, but rejects new state/fence changes.

## Evidence and trust boundary

Tests use real signed enrollment, a real authenticated journal genesis, real redb
commits, four before/after-sync failures and an independently killed/reopened witness
process. They cover fresh challenges, stale fences, same-target/different-command
conflicts, role-component reuse, malformed and contradictory signed messages,
cancelled/duplicate/concurrent receipt admission, storage corruption and bounds.
An OpenSSL/Python oracle independently checks 12 witness envelopes, 60 signature
negative controls, canonical scope/command/attempt hashes and six transitions. The
existing bootstrap oracle separately authenticates the same enrollment fixtures;
the hosted macOS lane runs both and archives both results.

The witness must retain its own state independently of client journal snapshots.
A retained counterexample restores the witness database itself and obtains an old
valid head: this software provider does not supply hardware anti-rollback or protect
its own authority from whole-store restoration. The process test does not establish
separate-host deployment or Byzantine consistency. Those deployment assumptions,
transport cancellation, account-level coordination and the wider 0.2.0 lifecycle
remain required. Required-anchor journals retain their original writer fence;
they reject externally changed fences rather than adopting a new writer authority.

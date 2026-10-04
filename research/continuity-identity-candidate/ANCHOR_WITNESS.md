# Authenticated monotonic witness candidate

`AnchorTransport::constrain_deadline` lets a host narrow each exchange to an
explicit enclosing invocation deadline. `AnchorClient` clamps the returned value
to its own attempt budget, checks it before signing/dispatch and retains it
through reply verification. An untrusted carrier cannot extend the attempt by
returning a later value. The C owner shares one scope across every witness call
in a constructor or ordinary invocation; ending the call removes only that
scope, not its one-way cancellation or original durable operation identity.

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
cannot create registrations. Enrollment does not track later roster changes
automatically. Revocation, credential/policy replacement and migration need their
own authenticated control-plane transitions.

### Explicit refresh under a newer roster

The native trusted operator uses
`AnchorStore::update_roster_authority(subject, previous, next, policy, now)` for an
existing subject whose **credential, device key, account root and policy remain
unchanged**. Restore `subject` with `AnchorSubject::from_trusted_state` from the
original protected configuration. Retain the original `RosterCheckpoint` before
the call; it is a compare-and-set expectation, not historical authorization. The
host does not need to revive an expired `VerifiedDevice` using an old clock.
Only `next`, verified against independently admitted current account/roster pins,
supplies current membership and time authority. An incoming roster cannot select
its own trusted checkpoint. This method is not a data-plane network command.

The next version must exceed the expected predecessor. Its exact credential owner,
public key, policy digest, witness binding and current SDK policy/runtime must pass
the existing enrollment checks. The stored authority must equal the canonical
account/checkpoint/family binding of the expected predecessor. A different current
head or a same-version fork is refused. Current verification always precedes any
idempotent readback, so an expired/future target or closed policy is not a success.

The transaction changes only the enrollment-authority digest and the intersection
of credential, next-roster and policy validity. A newer authorized roster can
shorten or extend that interval within those limits. Subject, original genesis,
journal head, writer fence, last data-plane command and witness key remain
unchanged. The stored-image upgrade is described below. No entry is created by this method. A storage error
closes the witness owner; reopen its original database/key and retry the original
subject, predecessor and target. If the exact target is already current, the
returned checkpoint confirms that state without another write. It does not prove
which invocation committed it and is not `AlreadyAppliedExact` for an administrative
command. A newer, different target cannot be overwritten by this retry.

After a witness admission expires, a client roster write may already have a durable
local intent but lack its witness advance. Explicit witness refresh preserves the
old head, allowing `DeviceJournal::open_anchored` to reconcile that same intent.
The client still has to install the current roster; witness refresh alone grants
no application-send permission and cannot undo an observed client revocation.
The native regression exercises this path with a retained encrypted bootstrap
outbox, original journal identity, one roster commit and refused revoked replay.
Separate tests retain exact data-command confirmation across a witness process
kill after refresh commit and returned errors before/after each measured sync.

The archive-shipped `owned_connection` consumer now requires the same recovery
through public APIs and signed TCP. Three separate device processes reopen the
original installation for expiry refusal, exact recovery, and durable revocation;
the witness runs in the parent process. The package collector checks the public
request/response commitments, two refused attempts of one immutable command, one
subsequent advance, unchanged journal identity/fence/bootstrap outbox, signed
roster checkpoints, bootstrap envelope/context, signed phase query readbacks,
and child completion. Only that checked public closure is
exported and re-read; private keys and databases are excluded. Protocol time is
injected. This path does not establish application-message restoration after
credential replacement or an independent witness implementation.

This is a native control-plane operation, not a deployed administrative service or
complete credential-renewal protocol. Independent current-roster admission,
authenticated operator transport, deployment/device qualification and credential,
policy or witness-key replacement remain separate product work. No global discovery
of unseen revocations or physical power-loss guarantee is claimed.

### Explicit same-key credential renewal

`AnchorStore::renew_credential_authority(subject, grant, operation, policy, now)`
adopts an independently verified root grant for the original subject. It checks
the expected operation, original credential owner and exact policy, then compares
the stored current credential owner, roster authority and validity with the
grant's exact predecessor. The successor must pass live device, mode, policy and
witness-signer separation checks. Ordinary signed data-plane requests cannot
invoke this control-plane method. The operator remains responsible for verifying
the grant against independent current account/roster pins and retaining the
original request before dispatch.

Only the current credential owner, enrollment authority and validity change.
Original subject, genesis, journal head, writer fence and last command survive.
An exact current target can be read back without another write; the returned
checkpoint describes current state, not which invocation committed it. Expired
targets fail even on retry. Another renewal or intervening roster update prevents
an old grant from overwriting newer authority. The same-credential roster method
continues to work under the new credential, while credential replacement still
requires this separately verified root grant.

Native tests exercise two renewals around expiry, intervening roster refresh,
fork/scope/operation refusal, actual old-format reopen and upgrade, both sides of
each measured sync barrier, and process termination after commit before any
result returned. The process test retains and re-verifies the original grant,
target pin and operation rather than creating a new request. These tests qualify
the witness control plane only. Original enrollment activation, expired-intent
recovery and installed foreign consumers under required-witness credential
renewal remain gated until their complete cross-store flow is integrated.

### Joint credential renewal and bounded terminal retention

`prepare_credential_renewal(proposal, grant, policy, now)` independently admits the
exact `QPCRNP01` journal proposal and verified root grant. It requires the original
subject/policy/operation/statement, exact current predecessor credential and roster,
and original expected head. One retained slot binds that proposal to target owner,
roster authority, effective validity and signed successor roster version. Preparation
changes neither the head nor the credential. An exact existing slot is historical
readback; it does not grant current operational authority.

Only device-signed `CredentialCommit` applies a prepared slot. In one witness
transaction it changes head, credential owner, authority and validity, recording
the complete commit command ID. A root-approved target may replace an expired
predecessor, but the target must still be live. An already-applied exact slot can
be recovered after expiry; it does not revive an expired owner. `CredentialClose`
closes the exact preparation or reports its prior Applied outcome. The independent
control-plane `close_credential_renewal` can also close an original verified target
before preparation, including after expiry or local policy-instance closure.
Neither close path can turn an Applied outcome into Closed.

Every terminal consumes its root-signed successor roster version as a permanent
per-subject floor. After durably retaining the terminal locally, the client may
acknowledge the exact proposal. The provider removes the full slot and retains
only the last acknowledgement binding plus the floor. Retrying that acknowledgement
cannot erase a newer slot. A different or older unavailable proposal is reported
Unavailable; a lower/equal version cannot be prepared or closed as new work. Same
version never means same operation, statement or proposal. The next independently
approved target must use a higher successor roster version. Absence, a floor, a
normal head Query or AuthorityDenied never proves that an original renewal did
not commit.

While a slot is retained, ordinary Advance, Fence and roster refresh are refused.
Once a subject has used this protocol, the legacy authority-only credential renewal
method stays disabled even after terminal acknowledgement. Later roster refreshes
preserve the floor and must advance beyond it. Exact genesis enrollment retries
never reset the slot or floor. The witness still commits opaque encrypted-image
expectations: it does not verify arbitrary encrypted application state or authorize
an operational owner merely because a hash was observed.

The native store tests cover all five mutating transition types with every measured
before/after-sync cut (22 fault injections), five process kills after commit before
reply, same-version conflicts, delayed acknowledgement, legacy control-plane bypass,
expiry, fresh reply scope and explicit storage upgrade. A real required journal
supplies the original sealed target in an additional lost-reply test; its pending
bytes remain unchanged and generic reopen remains suspended. Dedicated local apply,
close/ack coordination and original enrollment recovery are not yet integrated.
The public enrollment `AnchorRequired` guards remain; these tests do not qualify
an installed end-to-end required-witness renewal or an independent implementation.

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
| AdmitAuthority (4) | Read-only confirmation that the exact independently expected device authority is current and the witness enrollment is valid at this check; never enroll or update it |

Every command is exactly 97 bytes. Commands 2/3 encode
`kind:u8 || expected_head[48] || next_head[48]`; Query is `1 || zero[96]`.
AdmitAuthority is `4 || expected_device_authority[32] || zero[64]`, with a nonzero
expectation and strictly zero reserved bytes. Its expectation is the verified
account/checkpoint-version/checkpoint-digest/family binding, separate from the
witness-instance binding. Query's padding is an explicit encoding, not a default
state. Mutations cannot alter unrelated fields or overflow counters.
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

Outcomes are Current=1, Advanced=2, AlreadyAppliedExact=3, Conflict=4,
AuthorityCurrent=5 and AuthorityDenied=6. Query accepts only Current.
AdmitAuthority accepts only 5/6, bound to its exact command and fresh request digest.
The witness signs 5 only when the enrolled device authority equals the requested
binding and its validity contains current witness time; otherwise it signs 6.
Neither changes the head, last applied command or stored enrollment, and neither
is accepted by `applied_head`. A correct head alone cannot substitute for 5.
An ordinary Query remains available after expiry for original-intent reconciliation
and cleanup. Applied outcomes must match the exact next head and command
ID. The same next tuple reached through another command is a conflict. Conflict
does not yield `applied_head`; an internally contradictory signed outcome fails.
`has_last=0` requires zero last-command bytes and fence/revision 1/1. Later states
require `has_last=1`. No trailing bytes or unknown discriminants are accepted.

Joint commands 5/6/7/8 are CredentialCommit, CredentialStatus, CredentialClose
and CredentialAcknowledge. Each encodes `kind:u8 || proposal_binding[32] || zero[64]`.
The binding is the domain-separated hash of the complete canonical `QPCRNP01`
proposal. Outcomes 7/8/9/10/11 are Prepared, Applied, Closed, Unavailable and
Acknowledged. Status accepts 7/8/9/10; Commit and Close accept 8/9/10; Acknowledge
accepts 10/11. They retain the same request/reply sizes and fresh dual signatures.
`credential_renewal_state` additionally checks the caller's exact proposal scope:
Prepared/Closed require its expected head, Applied requires its target head and
complete CredentialCommit command ID. Generic `applied_head` rejects every joint
outcome. Older endpoints reject these new commands; there is no ordinary-Advance
fallback. Acknowledged retires already-retained history; it is not an owner-release
or NoCommit observation.

## Persistent witness state

The private, bounded host-store backend provides an exclusive database lease. The
single `continuity_anchor_candidate_v1` table contains exactly one `image` row:

`QPANC002[8] || authority_binding[32] || store_revision:u64 || count:u16 || entries || HMAC[32]`

Entries are strictly sorted by subject index and contain:

`index[32] || subject[96] || device_public[1985] || current_credential_owner[32] || enrollment_authority[32] || validity[16] || genesis_digest[32] || head[48] || has_last:u8 || last_command[32]`

Each is 2306 bytes. The reader also accepts the authenticated `QPANC001` layout,
whose 2274-byte entry omits `current_credential_owner`: before credential renewal
it equals the original subject owner. Opening does not write or reset state. The
next ordinary transaction writes the complete `QPANC002` image under the existing
durable commit and unknown-outcome recovery contract. An old reader rejects the
new tag; rolling back software must not silently recreate or reinterpret that
store. This is witness-image compatibility, not a redb file-format migration.

A subject with a joint slot or terminal floor selects `QPANC003`. After each
2306-byte base entry it adds `floor:u64 || has_ack:u8 || last_ack_binding[32] || phase:u8`.
Phase 0 has no slot; phases 1/2/3 (Prepared/Applied/Closed) add the 296-byte proposal,
target owner[32], target authority[32], validity[16], and successor version:u64.
The complete extension is at most 426 bytes per entry. Opening older 001/002 state
uses an empty slot and zero floor without writing. A joint transition upgrades it
atomically; terminal retirement preserves 003 and its nonzero floor. Older readers
reject 003. Encoders and decoders reject inconsistent floor, slot, head, credential
or last-command relationships. The redb file-format contract is unchanged.

There are at most 256 entries, a 1 MiB authenticated-image cap
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

`AnchorTcpTransport::with_cancellation` shares the same one-way signal as the
native TLS carriers without requiring operational SDK activation. Connected
reads/writes use socket timeouts of at most 25 milliseconds and check cancellation
between calls, including partially received length and reply fields. Scheduling
can delay observation. Pending connects retain one socket and use readiness
waits of at most 25 ms under the original exchange deadline; a readiness event
wakes the driver immediately. Neither polling nor partial progress refreshes that deadline. Cancelling
closes the connection and returns an unavailable outcome, never evidence that the
witness failed to commit. Recovery must reconcile the original durable command.

Tests use real signed enrollment, a real authenticated journal genesis, real redb
commits, four before/after-sync failures and an independently killed/reopened witness
process. They cover fresh challenges, stale fences, same-target/different-command
conflicts, role-component reuse, malformed and contradictory signed messages,
cancelled/duplicate/concurrent receipt admission, storage corruption and bounds.
An OpenSSL/Python oracle independently checks 12 witness envelopes, 60 signature
negative controls, canonical scope/command/attempt hashes and six transitions. The
existing bootstrap oracle separately authenticates the same enrollment fixtures.
These oracle vectors cover the earlier command set; independent public-vector
verification of the joint-renewal commands remains an open qualification gate. The
hosted macOS lane runs both and archives both results.

The witness must retain its own state independently of client journal snapshots.
A retained counterexample restores the witness database itself and obtains an old
valid head: this software provider does not supply hardware anti-rollback or protect
its own authority from whole-store restoration. The process test does not establish
separate-host deployment or Byzantine consistency. Those deployment assumptions,
global invocation bounds, account-level coordination and the wider 0.2.0 lifecycle
remain required. Required-anchor journals retain their original writer fence;
they reject externally changed fences rather than adopting a new writer authority.

## Authority-admission compatibility

This unpublished grammar extension retains the exact request/reply lengths
3674/3659, signature purposes, command-ID domains and existing command 1–3 and
outcome 1–4 encodings. New endpoints still support those existing operations.
Older endpoints do not support command 4. Every anchored `DeviceEnrollment::activate`
now requires command 4, including initial activation, ordinary restart and roster
refresh; an unsupported or unavailable endpoint prevents owner release. There is
no fallback to Query or local-only storage. Lower-level historical recovery and
cleanup keep their existing Query semantics.

AuthorityCurrent is a fresh signed observation, not proof that a particular update
invocation committed and not a future authorization lease. Every later mutation
still checks the witness's live grant and original head/fence. Independent operator
admission, credential/policy/key replacement and protocol finalization remain
separate obligations.

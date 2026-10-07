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

### Immutable original identity and legacy witness migration

New `enroll` entries retain the original account, device ID, generation, credential
validity and policy family. The entry's full device key and the existing canonical
credential encoder reconstruct the original credential digest; the resulting
storage-owner commitment must equal `subject.owner`. This invariant is checked
before encoding and after authenticated decoding. It binds every identity field,
including family and validity, without adding another credential parser.

`AnchorStore::retain_original_identity(subject, original)` explicitly fills this
record for a legacy subject. The operator authenticates the original certificate
and roster against independently retained original pins; expired inputs use the
existing `AccountPin::verify_historical_device`. The complete original public key
and reconstructed owner must match. A renewed current credential is not a substitute
for the original credential. Historical identity grants no current time, roster,
policy or runtime permission.

The operation changes only this immutable metadata and the outer witness image
revision. It preserves the original subject/genesis, current credential and roster
authority, validity, journal head/fence, last data command, and G/P/R state. An exact
retry is read-only, including after witness reopen or a lost result. An I/O failure
closes the owner and may follow commit; reopen the same witness and retry the same
proof. Ordinary network requests and exact legacy enrollment retries cannot fill
missing identity records.

`QPANC010` retains the complete v9 entry layout, with all optional lifecycle fields
explicitly present, followed by `identity_present:u8`. Value 0 represents an
unclassified legacy entry; value 1 adds
`account[32] || device[16] || generation:u64be || validity[16] || family[32]`.
Other tags fail. Every present record is checked against the original owner and
full key. A v10 image must contain at least one classified entry. Existing supported
v1-v9 formats still decode with absent identity metadata, and remain unclassified
until explicit proof admission. Mixed images preserve those absences. Limits remain
256 entries and 1 MiB; identity metadata does not evict existing history.

Native tests cover genuine credential renewal before migration, retained old data
command receipts, expired identity without current permission, partial migration,
wrong proofs, authenticated field substitution, every measured before/after-sync
failure and a real child-process kill after commit before return. Existing legacy
format tests construct explicit legacy inputs and retain their format assertions.

This metadata is a prerequisite for the native replacement transaction below.
Unclassified legacy entries cannot silently be treated as unrelated devices.

### Atomic device generation replacement at the witness

The trusted native controller calls `device_replacement_proposal` with a fresh
anchored journal's actual genesis, an independently admitted root-signed higher
device generation and roster, its current policy, and every active predecessor's
original subject, current roster checkpoint and authenticated historical policy.
The proposal is a read-only compare-and-set snapshot; retain its complete bytes
before calling `replace_device`. Neither parsing nor possession of these bytes
supplies account authorization. This is a local trusted-controller API, not a new
unauthenticated enrollment or network management endpoint.

Every known entry must have original identity metadata. For the selected account
and device ID, the target generation must exceed all retained generations, its
signing key components must be fresh, and its roster must exceed the supplied
current checkpoints and retained G/R floors. The supplied predecessor set must be
exactly the active set for that device. The target roster must also retain the
exact current credentials of all other known live devices in that account; this
single-device operation cannot silently include their revocation or replacement.
This check does not claim global roster adoption or discovery of unknown devices.
Ordinary `enroll` admits a previously unknown device ID; an already known ID needs
this explicit transaction. New enrollment is suspended while any legacy entry
remains unclassified. Exact active enrollment retries retain their prior behavior.

The previous policy proofs must match each entry's actual adopted policy and
validity, including independent policy renewal. The target policy cannot roll back
an adopted version or fork its digest at the same version. A merely prepared policy
target does not become adopted by replacement. Both target and historical proofs
must bind the same policy family and required witness. Creation and a new commit
require current target authorization. Exact retries of an already committed
proposal still require the original public inputs and authenticated historical
policy proofs, and return a historical `Committed` even after expiry, successor
advancement or subsequent replacement. They grant no current operating owner.

One existing durable witness transaction inserts the new genesis and the complete
replacement decision. All predecessor entries remain byte-for-byte intact. Their
normal queries, exact write retries, new writes, fences, authority admissions and
G/P/R operations are rejected with `Scope`; trusted renewal/refresh entry points
also refuse them. An old cached certificate or valid mutual TLS connection does
not bypass this decision. Other live subjects continue normally. There is no new
positive network outcome or receipt that could be mistaken for release authority.

Any I/O error can hide a committed result: reopen the same witness and retry the
original proposal. `device_replacement_status` observes that exact retained local
decision. `retired_subject_observation` provides the frozen head, last command ID,
complete G/P/R state commitment and original successor binding. This metadata is
**not** an ACK, a loss-accounting report, a historical journal mutation permit, or a
freshness receipt. The complete retired state is retained without eviction.

`QPDRPL01` proposals encode witness[32], original target identity[104], subject[96],
genesis[32], key commitment[32], authority[32], admitted validity[16], roster[40],
policy[40], policy validity[16], and a u16be predecessor count. Each sorted unique
predecessor contains subject[96], roster[40], policy[40], policy validity[16] and
frozen entry commitment[32]. The size is `450 + 224 * count` (674 bytes for one).
The proposal binding and frozen-state commitment use distinct domain separators;
the latter includes the witness binding and the existing complete entry encoder.
Truncation, trailing bytes, unsorted/duplicate subjects and inconsistent fields fail.

`QPANC011` keeps complete v10 entries, then a nonempty u16be decision count and
sorted `(binding[32], proposal_size:u32be, proposal_bytes)` records before the
existing image authenticator. Every decision is cross-checked against its target
and frozen predecessor entries. Each affected device has exactly one live highest
generation; a subject is retired at most once. Limits remain 256 entries and 1 MiB,
with no eviction or reset to admit an additional generation. Previously supported
schemas decode with no replacement decisions. Older binaries cannot read v11;
rolling a witness binary back after replacement is unsupported.

Native component tests exercise competing targets, state changes between proposal
and commit, policy forks/rollback, preserved G/P/R state, other-device membership,
measured before/after-sync failures, and a real child kill after commit before
return. A mutual TLS test rejects the original inactive journal and activates the
exact new journal. This does not yet qualify a complete device-service replacement
coordinator, retired-session loss accounting, foreign replacement APIs, cross-host
installed flows, independent protocol implementations or physical devices.

### Portable permanent-retirement proof

`AnchorStore::retired_subject_receipt(proposal, subject)` signs the exact immutable
observation under a separate signature purpose **18**. The independently provisioned
`AnchorPin::verify_retired_subject(proposal, subject, wire)` authenticates both
signatures and the complete expected replacement, old subject and successor. It
returns the opaque `AnchorRetiredSubject`, with its original witness binding. There
is no conversion to `AnchorReply`, ordinary `Current`, a new operating owner or a
host loss-accounting acknowledgement.

The body is 377 bytes: `QPDRTR01[8] || witness[32] || replacement[32] || subject[96]
|| head[48] || last_present[1] || last_command[32] || frozen_state[32] || successor[96]`.
The existing two-signature envelope makes the exact wire length 3754 bytes. All
truncations, trailing data, invalid signature components and noncanonical absent
last-command fields fail. Existing signature purposes and ordinary network request
and reply layouts are unchanged. This new proof uses neither their tag nor purpose.

The fact is permanent, so it has no freshness nonce or current-policy time grant.
Issuance is read-only and can be repeated after policy close, witness reopen, later
successor progress or another replacement. Randomized signatures can differ while
the body remains identical. The original witness key and independent storage
continuity remain trust assumptions; a compromised witness is not repaired by this
proof. Distribute it through the application's independently authorized control
plane, rather than adding an unauthenticated management endpoint.

A valid proof identifies the frozen authoritative image, **not every retained local
write intent**. A real `install_roster` test interrupts Advance before processing:
the journal preserves its sealed pending target while the witness and current image
remain unchanged. A prior backup has that same image and no pending target. Both
therefore match the same retirement proof. Receipt-only local cleanup would fail to
distinguish those snapshots. The separate inventory binding below preserves that
distinction; a complete cleanup coordinator must retain the original request outside
old-journal backups before dispatch and before releasing a report.

### Independent retired-journal inventory binding

`DeviceJournal::retired_cleanup_proposal(path, key, identity, retired)` reads the real
encrypted journal under its original exclusive lease and authenticates the current
image and complete pending record. The verified retirement must match the journal,
owner, original policy and independently pinned witness. The current image must
match the frozen witness head, or its authenticated, already sealed pending target
must match that head exactly. This covers an advance committed at the witness whose
reply was lost before local installation. A bound G/P/R target already installed
locally retains its pending record in the inventory. Reading does not apply a target,
change G/P/R, dispatch a network request or return an operational journal owner.

The canonical `AnchorRetiredCleanupProposal` is 313 bytes:
`QPRCLP01[8] || witness[32] || replacement[32] || subject[96] || frozen_state[32]
|| frozen_head[48] || stored_image_digest[32] || pending_present[1] || pending_digest[32]`.
The pending digest covers the complete authenticated local pending wire, including
cancellation intents; absence has canonical zero padding. The proposal binding uses
`Q-PERIAPT-CONTINUITY-RETIRED-CLEANUP-INVENTORY/v1`, and the pending digest uses
`Q-PERIAPT-CONTINUITY-RETIRED-LOCAL-INTENT/v1`. No secret material is exported.

An independently authenticated controller calls `AnchorStore::retain_retired_cleanup`
with the original retained proposal. Public proposal bytes are not caller authority.
The first inventory is committed permanently; exact retries are read-only and any
different inventory for the same retired subject conflicts. An I/O failure may hide
commit, so the coordinator must reopen and reconcile the same independently retained
proposal, never generate a new one from whichever backup is now available. An
`Unavailable` observation does not resolve an outstanding invocation. The store
preserves the old entry and its G/P/R history byte for byte.

Store format `QPANC012` retains the complete `QPANC011` image and appends a nonempty
u16 count followed by sorted `subject_id[32] || proposal[313]` records. Every record
must match its retained replacement decision and frozen subject. The existing
256-entry and 1-MiB bounds remain; records are never evicted. Earlier supported store
formats open with no retained cleanup inventories; an older reader rejects v12.

After retention, `retired_cleanup_receipt` signs the canonical proposal under the
distinct purpose **19**. Its envelope is 3690 bytes. `AnchorPin::verify_retired_cleanup`
requires the exact original proposal, verified retirement and pinned witness, and
returns an opaque `AnchorRetiredCleanup`. This permanent historical fact needs no
current policy grant and cannot convert to an ordinary witness reply. Ordinary
network layouts and the C ABI are unchanged.

Regression coverage includes actual interrupted ordinary writes and real credential,
independent-policy and roster targets at Prepared / witness-Applied /
locally-installed-with-pending stages. These use sealed journal targets and real
witness transactions, preserve the complete pending wire across local installation,
and check historical capture after policy closure without applying or erasing either
row. Target-free credential cancellation is exercised both before witness closure
and after it: a backup with the same frozen image but no cancellation intent conflicts
with the independently retained inventory. Ordinary G/P/R operations stay refused
after replacement, and the complete frozen witness observation stays unchanged.
Other coverage includes exclusive-lease and identity rejection, authenticated store
corruption, each measured before/after retention sync fault, and process loss after
commit before return. Credential-with-policy-continuation inventory variants and
installed foreign consumers still require dedicated coverage. The high-level
coordinator below retains the original request and binds complete historical metadata;
host acknowledgement and logical erasure remain open. Neither proof nor inventory
retention authorizes report acceptance, erasure or new runtime work.

### Original request retained by the installation

`RetiredInstallationRecovery::open(paths, key, retired)` now owns the first local
request-retention step. It admits only the existing Active installation, its original
key, independently configured paths and verified permanent retirement. On first use,
it reads the actual authenticated journal inventory and commits the complete proposal
to the independent installation database **before** returning a request to dispatch.
The `retired-cleanup` row is `QPCICL01[8] || QPRCLP01[313]`; the existing installation
row is unchanged. Only this named additional row is admitted, with exact journal,
owner, original policy and witness matching. Older readers reject the added row.

Every later open reads that saved proposal and never recaptures a newly selected
backup. The original request remains available after journal loss and policy expiry
so an independently authorized controller can reconcile an unknown witness commit.
`verify_retained(pin, wire)` authenticates permanent witness retention of that exact
saved request. Neither operation claims the old data is present or complete for a
loss report. The report reader below authenticates the exact independently bound image and
pending inventory, and rejects missing or substituted state.

Once the row exists, ordinary `DeviceInstallation` and `InstallationRecovery` open
paths return `Suspended`; they do not release an operational or per-session cleanup
owner through this configuration. The restricted object cannot convert to a service.
An I/O error may hide the request commit and returns no owner: reopen the original
configuration and retirement proof. Exact retries do not rewrite the saved request.
The configuration remains trusted host state outside journal backups, not a new
anti-rollback mechanism. Report binding is a separate step below; host ACK and
logical erasure remain unimplemented.

Actual installed-service tests cover interrupted roster writes with retained pending
inventory, prior backups with the same frozen image and no pending row, missing
journals, wrong key/retirement, every measured request-commit sync cut, and owned-child
process loss before and after commit before any request returns to the caller.

### Complete historical report and independent report retention

`prepare_report(verified_inventory)` authenticates the exact original image and full
pending wire under the exclusive journal lease. The authenticated records choose the
complete inventory; the archive index cannot select a subset. Every message session
and every fanout member requires its original MAC-authenticated closure archive with
matching journal, protection, context, role and peer identity. Missing state or archives
fails the whole preparation. It never applies a pending target or changes G/P/R.

The `retired_device::Report` contains explicit views: the witness-committed authoritative
image, and a superseded source or an uncommitted target where still retained. A locally
installed bound target with a retained intent has one authoritative view plus the exact
original transaction metadata. Candidate target outcomes must not be counted as committed
work. Both views preserve original operation IDs. No earlier deleted history is invented.

Metadata covers bootstrap request/flight identities and existing cancellation receipts;
prekey request/kind/validity, public fingerprint and consumed/abandoned source operation;
public authenticated roster/renewal history; live and previously closed sessions; all
retained epoch floors, outgoing IDs and ciphertext fingerprints, unconsumed lengths,
out-of-order consumed IDs, skipped indices and reservations with original fanout IDs;
and every original fanout recipient/credential/context/session/message and disposition.
Prior session, epoch and fanout report identities remain unchanged. Private keys, recovery
tokens, signing/KEM coins, plaintext, associated data and private input commitments are
not projected. Public metadata includes account/device linkage and lengths and should
remain private to the host's accounting storage.

Canonical report metadata is `QPRDMD01`; all counts/lengths and integers are unsigned
big-endian u64, optional fields have an explicit presence byte, and records/views follow
the deterministic typed encoder in `src/durable/retired_report.rs`. The original cleanup
proposal is included in full. An HKDF-separated HMAC-SHA256 key derived from the original
wrapping key authenticates the complete canonical report. Metadata is bounded by four
times the existing 2 MiB journal-image limit. This private-keyed identity is not a public
plaintext hash, a delivery receipt or permission to erase.

Before returning a proposal, the coordinator commits a separate `retired-report` row
containing **QPRRPT01[8] || QPRCLP01[313] || report_id[32] = 353 bytes**. The exact inventory
must match the existing `retired-cleanup` row. Ordinary installation entry points remain
suspended; older readers reject the additional named row. `report_proposal()` recovers
the original expectation after unknown commit or missing journal. An exact repeated
`prepare_report` reads that saved expectation without selecting another backup.

The independently authorized controller then calls `retain_retired_report`. Its first
report for that retired subject is permanent; a different report conflicts even with the
same inventory. Witness format **QPANC013** extends v12 with a nonempty sorted report map
(`u16 count`, then `subject_id[32] || QPRRPT01[353]`). It retains the complete old entries,
replacement decisions and inventory map. Older supported images have an empty report
map; original 256-entry/1 MiB limits remain, without eviction. Storage authentication
cannot excuse a report with a missing/different independently retained inventory.

`retired_report_receipt` uses distinct signature purpose **20** and a 3730-byte envelope.
`verify_retired_report` authenticates the original saved expectation and inventory.
`report(verified_inventory, pin, receipt)` only then rereads the exact original journal
and archives and recomputes the same report identity before returning complete typed
metadata and canonical bytes. Losing original data after saving the proposal allows
commit reconciliation but never an empty/replacement report. The witness authenticates
retention, not semantic completeness supplied by an untrusted recovery controller.

This stage performs no host accounting ACK and no logical erasure. Those require their
own explicit durable decision and crash reconciliation. It does not make an old runtime
current, assert remote delivery, or claim erasure of retained pages/backups. Foreign
bindings and installed replacement flows still require separate integration/qualification.

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

### Independent closure without a sealed target

`close_unprepared_credential_renewal` takes independently authenticated grant and
policy metadata with an exact `QPCRNC01` cancellation. Its canonical fields are
`tag[8] || witness[32] || subject[96] || operation[32] || statement[32] || expected_head[48]`.
Its binding uses `Q-PERIAPT-ANCHOR-CREDENTIAL-CANCELLATION/v1`. No target head is
created. The successor version is derived from the root-signed grant, not an
additional caller-selected integer.

An empty slot admits cancellation only when the full predecessor identity,
authority, validity and head match and its version exceeds the permanent floor.
The transaction retains a Closed-only slot and floor together, without changing
operational state. Exact cancellation retries return Closed. Any existing proposal
or other cancellation conflicts; Applied is never relabelled Closed. After ACK,
an old version remains Retired even though its old head might still match.
Ordinary Advance/Fence and roster refresh remain excluded while any slot is held.
`HistoricalCredentialRenewal` and `HistoricalSessionPolicy` permit this cleanup
after expiry without current runtime permission. New Prepare still requires the
current types and admission checks. Original-enrollment durable coordination and
foreign-owner integration of grant-only cancellation are not yet implemented.

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
bytes remain unchanged and generic reopen remains suspended. The dedicated
`DeviceJournal::recover_credential_renewal` now checks the complete retained
proposal and original signer before obtaining a fresh typed CredentialStatus.
Applied installs only the exact sealed target while retaining QPWINT02; an exact
retry reads it without another commit. Prepared, Closed and Unavailable preserve
local bytes. A local target paired with Prepared or Closed is a conflict. This
works after credential expiry and policy-instance closure and returns no owner.
Inspection recognizes either original or exact target image with the same intent;
ordinary QPWINT01 recovery remains strict. Tests cover all six before/after cuts
at three measured local commit syncs and an actual kill after commit before return.
Original enrollment now coordinates its exact durable terminal, ACK, pending
deletion/readback and coordination retirement. An opaque internal terminal token
is created only from authenticated configuration readback; callers cannot supply
an Applied/Closed disposition to the journal retirement entry point. An old
Terminal paired with a different pending proposal is refused before ACK.
After the witness has retired its bounded last-ACK receipt, fresh Unavailable can
finish pure local cleanup only under that already-durable exact Terminal and the
independent monotonic-witness assumption. It never creates a NoCommit fact.
The preceding completion receipt remains inside the target until the next exact
approved target replaces it in its own transaction. Operational release separately
requires fresh head and AdmitAuthority checks.

Original enrollment tests add 16 configuration sync fault cuts, eight pending
retirement sync cuts and eight actual cross-store process kills across Applied
and Closed. See [the native coordinator workflow](CREDENTIAL_RENEWAL.md#required-witness-original-enrollment-coordinator).
The C/Swift/Kotlin facade retains its pre-staging required-witness refusal pending
complete foreign coordinator integration. These native tests do not qualify an
installed end-to-end required-witness renewal or an independent implementation.

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

Grant-only cancellation reuses commands 6/8 for exact Status/Acknowledge with its
separate cancellation binding. Its typed reply accepts Closed only for the exact
expected old head; Unavailable and Acknowledged cannot first establish Closed.
Commit/Close commands carrying a cancellation binding are rejected. The ordinary
query and full-proposal reply interpreters cannot substitute for this typed result.

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

An image containing a grant-only Closed slot selects `QPANC004`. Its base and
per-entry floor/ACK layout are the same as 003, with phase 4 adding
`cancellation[248] || signed_successor_version:u64`. A slot is exactly one of the
original proposal states or grant-only Closed; no entry can contain both. A 003
reader rejects phase 4, and older readers reject the 004 tag. After every grant-only
slot has been acknowledged, the remaining floor/ACK state has exactly the 003
meaning and the next write uses 003. No floor or prior acknowledgement is reset.
Opening never writes an upgrade or downgrade. The existing aggregate CAS, immediate
persistence, authentication and unknown-commit behavior apply to both formats.

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
The OpenSSL/Python oracle now requires 57 signed envelopes and 285 signature
negative controls. It checks the original six witness requests, then independently
decodes the complete root renewal statement and credential/roster relation and
twenty joint requests across Applied and Closed flows. Both flows include fresh
exact retries, the opposite terminal command, status, repeated acknowledgement,
and unavailable status/commit after pruning. It recomputes proposal, command and
attempt hashes and checks every observed head and last commit identity. These
vectors use explicit opaque target expectations; actual sealed-image recovery is
covered separately by native tests. They are not an independent protocol engine.
The existing bootstrap oracle separately authenticates the same enrollment and
policy fixtures. The hosted macOS lane runs both and archives both results.

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

## Independent policy-only witness transaction candidate

`AnchorPolicyRenewalProposal` and `AnchorPolicyRenewalState` describe a separate
policy-only transaction. `QPPWNP01` is a fixed 296-byte public descriptor binding
the original witness, journal subject, `PolicyRenewalId`, two-root policy
statement, expected head, and one-revision sealed target. Its commitment domain,
command tags 11–15 and outcome tags 12–16 are distinct from credential and joint
G/T renewal. A parsed proposal is an expectation, not an authenticated receipt.
The existing fresh signed request/reply envelopes and store transaction are reused.

The trusted witness operator calls `AnchorStore::prepare_policy_renewal` with
independently pinned original/current identities and original/previous/target
policies. The store re-verifies both approvals, requires the same required witness
and unchanged original credential, and compares the actual account authority,
policy predecessor and journal head. Original or predecessor policy expiry does
not provide current permission; preparation still checks the live target runtime,
credential and roster. The operator must authenticate and serialize requests and
deduplicate operation IDs; untrusted requests cannot invoke this control plane.

The data plane can commit, inspect, close or acknowledge only that exact prepared
proposal. Commit persists the journal head and new policy authority together.
Close and commit are mutually exclusive. An independently authorized historical
close can also precede preparation. Exact Applied/Closed history survives expiry;
Unavailable means absent/conflicting/retired history, never proof of non-commit.
After the client durably retains the terminal disposition, its exact ACK retires
the bounded record but retains a monotonic target-policy floor. Old targets cannot
be prepared again after retirement. Unknown commit results require reopening the
same witness and retrying the original operation with a fresh signed attempt.

A retained transaction, including an unacknowledged terminal, blocks ordinary
advance/fence and roster refresh for that subject. After ACK, fresh
`admit_policy_renewal` requires the exact current account authority and P statement
and current validity. Ordinary authority admission does not substitute for it.
Same-credential signed roster refresh preserves the adopted P and original head;
a subsequent P request must use that actual roster and exact predecessor.

The witness image writes `QPANC008` when independent-P metadata is present and
keeps the existing bounded image size and authenticated, durable storage boundary.
Earlier supported image versions remain readable. This candidate format is not a
product migration commitment or permission to rewrite missing/corrupt state.

This component currently excludes subjects with a real G/T adoption, and it
explicitly refuses G/T mutation after independent-P history. Carrying real G/T
through this transaction remains required work, not a local-only fallback.
Actual journal target sealing/retention and exact historical installation now
use the same exclusive pending slot and sealed bytes, as described in
[the independent-P write-intent contract](WRITE_INTENTS.md#independent-policy-only-witnessed-target).
The [original enrollment coordinator](ENROLLMENT.md#required-witness-independent-policy-coordination)
now retains an exact Applied/Closed terminal before sending ACK and removing the
original pending intent. Its historical outcome never grants current permission.
The original owner now retains its separately durable completion and checks fresh
`AdmitPolicy` (15), actual current roster and exact journal head before operational
release. Historical acknowledgement does not advance the journal head or rewrite
its receipt phase. Original-session traffic/rekey and a successive P after expiry
are exercised locally. Cross-language wrappers, installed packages, complete
roster maintenance and independent implementation remain unqualified for this
path. Local-only owner APIs continue to refuse required-witness independent P.
Store-only tests retain explicit digest expectations; separate journal tests use
real sealed targets, preserve an existing prekey, and never release an operational
owner or retire the original intent. Separate enrollment tests exercise actual
terminal/ACK coordination with 16 configuration sync faults, 10 original-pending
cleanup sync faults and lost commit/ACK replies before and after dispatch. Eight
actual process kills now exercise this enrollment path across observation,
terminal persistence, pending cleanup and completion, for both Applied and Closed.
Those cross-store cuts are distinct from the store-only cuts below.

The focused tests exercise exact outcomes, wrong-target/type refusal, policy
successors, roster refresh, all six store mutation boundaries under 28 before/after
sync failures, and four real witness-process terminations after durable commit
before any reply escapes. These finite component checks are not a complete
protocol security proof or 0.2.0 release qualification.

## Atomic roster and journal-head refresh candidate

Required-witness roster maintenance must preserve one actual predecessor across
expiry. A reproduced counterexample to composing two separate updates first
adopts R2 at the witness while the journal still contains R1. After current P
expires, a new P bound to R1 is refused by the witness and one bound to R2 is
refused by the journal. Those refusals are correct; relaxing either comparison
would lose the actual predecessor. The standalone authority-update API remains
available for subjects that have never entered the new atomic-R format. It is
not the coordinator for this new path.

`RosterRefreshId`, `RosterRefreshScope`, `AnchorRosterRefreshProposal` and
`AnchorRosterRefreshState` define an independently typed roster/head transaction.
The canonical `QPRWNP01` descriptor is 417 bytes: original witness and subject,
operation, previous/target roster checkpoints, unchanged current policy checkpoint,
optional exact independent-P statement, expected head and one-revision target
head. The optional statement is absent only for original P0. Its binding domain
is `Q-PERIAPT-ANCHOR-ROSTER-REFRESH/v1`. Parsing supplies expectations, not proof
that a target was sealed or applied.

`AnchorStore::prepare_roster_refresh` independently admits the exact root-approved
same credential and target roster, current policy/runtime, unchanged original
subject and actual predecessor authority/head. Preparing retains one slot while
leaving both the current roster and head unchanged. Device-signed RosterCommit
changes head, authority, effective validity and last command together in the
existing immediate witness transaction. An independently approved historical
close may precede preparation; a later close cannot undo Applied. Exact terminal
history remains readable after expiry. Unavailable never proves non-commit.

Commands 16/17/18/19 are RosterCommit, RosterStatus, RosterClose and
RosterAcknowledge. Each retains the 97-byte command size with a separate proposal
binding and strictly zero padding. Outcomes 17–21 are Prepared, Applied, Closed,
Unavailable and Acknowledged. The existing fresh dual-signed envelope binds the
complete command and attempt; the roster reply interpreter additionally checks
its exact proposal, head and last applied command. Ordinary/P/G interpreters
cannot substitute for this typed result.

A retained R slot, including an unacknowledged terminal, blocks ordinary
advance/fence, operational authority admission, independent P preparation and
standalone roster authority mutation. P and R preparations cannot coexist. ACK
requires the caller to retain its exact original terminal first and leaves a
monotonic roster target floor plus bounded last-ACK binding. Once atomic-R
metadata exists, standalone roster/credential mutation cannot bypass it. Current
scope excludes real G/T composition. After R retirement, a new independent P can
use the actual unchanged or adopted roster, preserving the R floor.

`QPANC009` retains the complete prior witness fields and adds a separately typed
R slot/floor/ACK extension per entry. Previously supported versions through 008
remain readable; opening
never resets or rewrites them. Size, entry and database bounds and the original
MAC/commit boundary remain unchanged. This is an unpublished candidate format,
not a product migration commitment.

The store tests use real signed root rosters and witness messages but explicit
opaque target-digest expectations. They cover exact transitions, expiry/closure,
policy composition, old-target/type refusal, slot exclusion and 32 actual
before/after-sync faults across prepare, unprepared/prepared close, commit and
Applied/Closed ACK. All fault counters are consumed and their exact I/O errors
are preserved. Separate [real R journal checks](WRITE_INTENTS.md#atomic-roster-target-in-the-original-journal)
now seal and recover actual encrypted targets under original P0 or completed
independent P. Low-level recovery retains pending and releases no operational
owner. The original enrollment coordinator separately authenticates a durable R
Applied/Closed terminal before ACK (19) and exact pending cleanup. Eight actual
R process terminations now cover Applied/Closed observation, terminal persistence,
cleanup and enrollment retirement. Current owner admission and successive R/P
use the actual adopted roster. Native original session and two-recipient fanout
checks now preserve the original offers/outboxes/consumption outcomes across R,
including lost ACK and current release fences. Network, foreign and installed
platform qualification remain open; these native checks are not release
qualification.

# Original device enrollment

Status: unpublished native candidate, `qperiapt-enrollment/1`. This coordinates
local request persistence, exact credential admission and the existing installation
state machine. It does not provide an account login service, network enrollment
transport, credential replacement, root replacement or a finished product lifecycle.

## Inputs and first use

The application supplies an independently trusted account root and an approved
`DeviceDescription` (device ID, generation, policy family and finite validity).
These become an `EnrollmentIntent`. The authority verifies a request against its
own approved intent; an incoming request cannot select those expectations.

Explicitly provision the file-backed `JournalKey` once and keep its file outside
journal backups. `EnrollmentPaths::new` binds that existing key file, the future
signer file, enrollment database and three `InstallationPaths` files. All six
paths must be distinct canonical absolute paths with admitted private parents.
`DeviceEnrollment::provision` opens the existing wrapping key and commits a fresh
`SigningKeyId` and exact scope before creating a signer. It refuses existing signer
or installation files. `open` never selects provisioning after an error.

`request(now)` creates or reopens the signer for that committed ID, constructs the
dual-signed proof of possession, commits the exact request, then returns its bytes.
Once the request is committed, retries return those same bytes and public key.
No raw signing seed or wrapping-key accessor is introduced.

On the authority side, `VerifiedEnrollmentRequest::verify` authenticates the exact
approved intent and both key components. The host must independently authenticate
and authorize the user's account action before calling `RootSigningKey::issue_enrollment`.
It must also maintain and sign its current complete roster. Proof of possession
is not account membership, registration approval or a freshness oracle.

The client calls `accept` with the certificate, roster, an independently obtained
current `AccountPin`, and the live verified protocol policy. Both the original
signer and the complete approved description must match. Acceptance commits the
original request, credential, roster/checkpoint, policy binding and one future
journal ID. It neither trusts a checkpoint selected by an untrusted response nor
permits a different accepted credential/roster/policy to replace this transaction.
Equivalent signatures over the same accepted credential body may read back the
original acceptance; they do not replace its stored bytes or journal ID.

## Installation and restart

| Enrollment status | Next action and meaning |
| --- | --- |
| Preparing | Call `request`; only this committed intent may create its absent signer. |
| Requested | Resend the exact request or admit the independently authenticated response. No installation exists yet. |
| Accepted | Call `prepare` to create/reconcile the original empty installation. Retain any required witness genesis and enroll it through the independent authority. |
| Activating | Retry `activate` with the original policy and required witness. Activation may already have committed in the installation. Do not recreate or reprepare children. |
| Active | Reopen/activate the original installation and recheck current local and required-witness authority. This persisted phase is not a live authorization receipt. Missing children remain errors. |
| Refreshing | A same-credential roster target and expected predecessor are durable. Reopen and `activate` the original installation; reconcile its original pending journal command, CAS the resulting roster, install the exact target, then complete Active. No replacement lineage or different pending target is allowed. |

`prepare` delegates child creation and genesis reconciliation to `DeviceInstallation`.
`anchor_client` constructs the client from the original controlled signer, an
explicit carrier/timeout and the independently pinned witness required by that
policy; callers do not have to reopen signing-key files themselves.
Its retained journal ID is supplied by the already committed acceptance; a failed
or interrupted creation cannot choose another ID. Required witness configuration
cannot become local-only on failure.

Before invoking installation activation, the enrollment owner commits Activating.
After installation activation commits, it commits Active and rechecks the current
journal roster, live policy and exact required-witness authority before returning
`EnrolledDevice`. All anchored enrollment activations, including first use and
ordinary reopening, require the signed authority-admission operation documented in
[the witness contract](ANCHOR_WITNESS.md); a head query is insufficient. Any failure releases no operational
owner. The enrollment can therefore be Active even when its caller received an
error; reopen the original record and retry the original activation.
`EnrolledDevice::parts` borrows the existing `DeviceService`, signer and verified
local identity. The enrollment lease remains held until this result is closed or
dropped. Operational SDK policy, roster, expiry and traffic checks still apply.

## Formats and trust boundaries

The request has the existing fixed dual-signature envelope. Its body is:
`QPENRQ01 || signing_id[32] || account[32] || device[16] || generation[u64be] ||
valid_from[u64be] || valid_until[u64be] || family[32] || public_key[1985]`.
Its signature purpose is the new value 14. Existing signature-purpose values,
credential/roster formats, SDK KAT inputs and hybrid implicit rejection are unchanged.
The public signing ID is correlation data, not entropy or authorization.

`QPENST01` stores the scope binding, signing ID and phase. Accepted phases retain
bounded request/credential/roster fields, exact roster and policy commitments and
the original journal ID. The image is authenticated with a distinct HKDF-derived
HMAC key under the wrapping owner. Each variable field is capped at 8192 bytes;
the whole image is capped at 24 KiB. Database access uses the shared exclusive
private-file backend and immediate transaction durability. The optional QPENST02/03
renewal extensions preserve QPENST01 bytes when absent and have their own 128 KiB
bound; see [renewal formats](CREDENTIAL_RENEWAL.md#encoding-and-compatibility).

The enrollment record is trusted local configuration, kept independently of journal
backups. Its MAC detects unauthenticated edits; it is not an anti-rollback witness.
Existing partial wrapping, signer or configuration destinations remain refused.
New immutable wrapping/signing files use complete staged publication, so a crash
before rename cannot expose a partial formal key. In Preparing, the enrollment's
committed original intent may retry an absent unpublished signer with the retained
SigningKeyId; once Requested, it must recover the exact original signer. Private
staging orphans are never selected as keys or swept automatically. Initial enrollment, installation, journal and archive databases now commit in
private staging and publish while retaining their original exclusive Database owner.
A failed initial enrollment publication can be retried only under its original
explicit first-use intent, before any released request or active identity. A
published configuration is always reopened; an active missing identity is never
replaced. Unpublished staging may survive either an error or process interruption. See [signing-owner recovery](SIGNING_OWNERS.md).
Hardware key storage, orphan maintenance, independent authority transport,
all-language archive qualification, Android/WASM persistence, current device runs and
complete replacement/upgrade remain open.

The regression suite covers actual signature/policy checks, real SDK prekey work,
exact restart, exclusive leases, request/acceptance/activation sync faults, process
interruption after commits, Active child loss and policy closure at final release.
These selected cuts are not physical power-loss or full lifecycle qualification.

The archive-shipped ordinary TLS connection now uses this owner from registration
through activation, original-state restart, bidirectional traffic and signed rekey.
The package gate binds public registration materials to the actual connection and
independent database-lease probes; see [installed connection](PACKAGE_CONSUMER.md).
The separate signed-TCP roster-refresh trace still uses the preconfigured
installation API. Expired-bootstrap restoration now retains the enrollment owner
and refreshes its original journal's current roster before reopening the session.
Enrollment retains its original scope. The explicit
[same-key credential renewal](CREDENTIAL_RENEWAL.md) transaction can extend validity
and reconcile an expired pending target; root/key/generation/policy replacement
remains separate. Required-witness local renewal is not yet enabled.

## Continuing an original identity under a current roster

`refresh_roster(previous, roster, pin, policy, now)` begins an explicit update of
an already Active enrollment. The independently supplied current pin and roster
must retain the exact original credential, root, device/generation, key and policy.
The original credential and enrollment intent must still be valid now. An expired
old roster is an expectation stored in authenticated configuration, not renewed
authority; a fresh roster cannot extend an expired credential or replace a key.

The method durably records `Refreshing { journal, previous, next }` before returning.
This reports local progress, not permission to communicate. Exact pending retries
retain the original signed target bytes. An already-current target can be read back;
that observation does not prove which invocation applied it. Different pending
targets, stale predecessors and same-version forks fail closed.

`activate` retains the enrollment lease while opening the original installation.
Opening an anchored journal first reconciles its exact original pending write.
Only then may its resulting roster equal the expected predecessor or exact target.
The existing `install_roster` operation preserves revocation/generation history,
commits the target, and reuses an already-current target without another advance.
After the final registration Active commit, a fresh signed witness check confirms
this exact authority and journal head before any owner is released. An original
pending revocation can therefore commit during recovery and subsequently cause the
refresh CAS to fail. Failure does not imply that the recovered original operation
had no effect. A newer journal head is not silently adopted or reset; conflicting
control-plane updates require explicit resolution and cannot replace this intent.

The witness operator must separately call `AnchorStore::update_roster_authority`
for the original subject and independently verified current device. The SDK's new
read-only check cannot perform that control-plane update. Even when the journal is
already at the target, an old or expired witness grant returns authenticated
`AuthorityDenied`, and no enrolled service is released. A lost confirmation may
leave local Active committed; reopen and obtain a fresh confirmation, never treat
the local phase or a Query reply as evidence of current witness authority.

Refreshing uses phase byte 5 in `QPENST01`, with the usual target admission fields
followed by `previous_version:u64be || previous_digest[32]`. The predecessor must
be strictly older. Existing phase 0–4 encodings are unchanged. Older candidate
readers reject phase 5; do not roll back readers while an update is pending.
This unpublished schema extension is not a general supported-version migration.

For an established session, authenticate its original public bundle with
`request_reopen` and call `DeviceService::reopen_peer` on the service borrowed from
`EnrolledDevice::parts`. This retains the enrollment owner while the existing
journal/archive checks admit the original context against current rosters. Do not
construct a new context to replace the original session or drop the enrollment
lease to call a lower-level installation constructor. The public TLS restoration
trace now exercises this route after both its initial roster and advertisement
expire, including an application effect committed before a lost receipt.

The selected regression cuts cover the registration intent, journal and final
registration commits, typed before/after-sync failures, stale/revoked journal
competition, a pending revocation recovered before CAS, expired/mismatched witness
grants and a lost signed authority confirmation. They do not constitute physical
power-loss qualification, all-language enrollment, credential/root/policy replacement,
or a complete multi-device/upgrade lifecycle.

## Preparing real credential renewal

For real credential renewal, call
`credential_renewal_request(operation, original_policy_history)` on the original
enrollment after retaining a new `CredentialRenewalId`. The local native reader
checks the actual acknowledged journal credential and policy against the saved
enrollment. It returns the exact original and predecessor certificate bytes,
actual signed predecessor roster and existing G authorization scope.
`original_device()` and `original_roster()` expose the original verified identity
and exact signed roster alongside `original_credential()`, allowing a public
consumer to carry both original and predecessor materials without internal fields.

A newer actual roster may be used when it still contains the same retained
credential. This avoids requiring a live-credential roster refresh before
renewing an expired credential. A changed credential/generation, revocation,
pending operation or unacknowledged journal receipt is refused, rather than
guessed or acknowledged implicitly. This does not change the stricter
enrollment-roster equality required by the policy-only request below.

The account issuer can use
`issue_credential_extension(request.previous_device(), new_until, now)` to issue
a same-key, same-generation certificate, then approve and retain its target
roster. Pass `request.materials(successor_certificate, successor_roster)` and
`request.authorization()` to the existing `issue_credential_renewal`.
The receiving application independently verifies that grant and stages it in
the original enrollment through the existing current-policy G path.

These are public metadata and signing inputs, not user authentication or an
issuer transaction. The issuer still authenticates and authorizes the user,
serializes its current account state, durably deduplicates the original operation
and retains the exact issued response. Keep the original request for an unknown
issuer result; reading another snapshot does not reserve or replace that request.
Staging and journal commit retain their current-policy and exact-predecessor
checks. The request reports the actually adopted policy/authorization as context;
G itself continues to bind original P0, not an additional unsigned Pnext claim.

Preparation works without the private device signer or a live runtime, including
after expiry. It creates no files, writes no new enrollment/journal operation and
returns no owner. The current G grammar still requires an authenticated
historical credential/roster snapshot with overlapping validity intervals;
non-overlapping intervals are refused, not synthesized. That renewal case,
required-witness preparation, serialized external request/issuer services and
foreign-language bindings remain separate integration work.

The separate-crate `tests/credential_request.rs` consumer exercises original
enrollment, two real G renewals after predecessor expiry, unchanged original
journal/signer/wrapping key, and metadata preparation after runtime/signer loss
using only public APIs. Its issuer runs in the test process; it is not an
independent remote implementation or an installed-package interoperability claim.

## Deriving an independent policy renewal request

Retain a new `PolicyRenewalId`, then call
`policy_renewal_scope(operation, original_policy)` on the original enrollment.
The local-only native entry reads both that enrollment and its actual journal to
derive the original owner/C0/P0/journal, current credential and roster, and exact
previously adopted policy authorization. It supports original P0, prior real G/T,
and a completed independent policy renewal. The application still obtains and
independently verifies target policy/materials before asking both issuers to approve
the resulting `PolicyRenewalStatement`.

Call `policy_renewal_request(operation, original_policy)` when the consumer also
needs identity materials. It performs the same admission as the scope-only reader
and returns an immutable `PolicyRenewalRequest`: `scope()`, exact original/current
signed credentials and rosters, and their signature-verified device snapshots.
The current roster must still equal the retained enrollment and actual journal;
this does not borrow a fabricated G operation or relax the policy-only fence.

`request.materials(original_history, previous_history, verified_target)` combines
those snapshots with independently authenticated policies for
`PolicyRenewalStatement::new`. Statement construction still checks the complete
scope and current target/credential/roster validity. Both root approvals, current
staging and journal commit remain required. Returning a historical identity does
not convert an expired or revoked device into current permission.

The separate public Rust consumer covers two real credential renewals followed
by independent two-root policy adoption on the same original journal and signer.
For a restart or a separate verifier, `AccountPin::verify_historical_device`
rechecks both signed identity records, exact independent pin and membership at a
valid historical overlap. It refuses touching or disjoint validity intervals and
does not grant current permission. Keep the account/root/family/checkpoint pin
independently of received request bytes. Current statement and operation boundaries
still check actual time, policy and roster authority. The public consumer discards
the original request object, reloads its retained identity bytes and re-verifies
them before creating the dual-root statement.

This is an in-process reference issuer, not a network request format, authenticated
issuer service, independent protocol implementation or foreign-language binding.

The request is a historical snapshot, not a reservation or current permission.
It needs neither a live SDK runtime nor the private device signer. Pending
operations and unacknowledged journal receipts must finish through their original
recovery path first. A journal/configuration roster mismatch requires original
roster reconciliation; the method never selects a guessed predecessor. Staging
and journal commit retain their exact-C/R and policy-predecessor checks, so a
concurrent update can still refuse an otherwise valid signed request.

## Required-witness independent policy coordination

This native candidate coordinates one independent P under the unchanged original
credential, journal and required witness. It does not carry a real G/T adoption.
Retain the original operation, full proposal and signed approvals across an
unknown outcome. All steps keep the original installation lease; no replacement
journal, signing key or protection mode is created.

1. Build `policy_renewal_anchor_client` from the original policy history, controlled
   device signer, independently pinned witness and bounded transport. It requires
   no live SDK runtime. `witnessed_policy_renewal_request` derives public issuer
   materials from the actual acknowledged journal and a fresh witness head check.
   The request is a snapshot, not a reservation or an issuer authorization.
2. Independently verify both root approvals and use `stage_policy_renewal` to
   retain the original required-witness approval. Then call
   `prepare_witnessed_policy_renewal` with the exact original/previous/target
   policies and current time. This reserves one sealed target and saves its exact
   proposal; it does not prepare the witness. After an uncertain return,
   `recover_witnessed_policy_renewal_preparation` recovers that proposal without
   resealing. Its `None` result means local absence only.
3. The independently authorized witness operator prepares that exact proposal.
   `commit_witnessed_policy_renewal` checks the complete caller proposal and target
   policy, admits current inputs for a new commit and dispatches the exact command.
   `reconcile_witnessed_policy_renewal` only queries the original operation;
   `close_witnessed_policy_renewal` closes an existing sealed preparation. These
   entries reconcile with a fresh signed status and install only exact Applied
   target bytes. Prepared/Unavailable do not become a terminal.
4. Enrollment persists Applied as the original policy completion, or Closed as a
   separate retained approval. It authenticates that durable readback before
   constructing the private capability needed for witness ACK and original-pending
   cleanup. A caller-supplied disposition or signed approval cannot construct it.
   After cleanup readback, enrollment saves the retirement flag.

`witnessed_policy_renewal_progress` reports Reserved or a terminal with its exact
proposal, target, disposition and retirement flag. Reserved is local reservation,
not evidence of witness preparation. Closed remains distinct from Committed and
from the local expired/uncommitted resolver. Retirement describes witness ACK and
pending cleanup only: **the journal policy receipt is still AwaitingEnrollment,
and no renewed service/session owner is released by these methods**.

Lost commit/ACK replies and uncertain local writes must reopen the original
enrollment and reconcile the same operation. Historical recovery remains possible
after policy/credential expiry or runtime closure; it grants no live authority.
Even a known retired terminal rejects a substituted complete proposal or target
policy. Fresh Unavailable permits only cleanup under an already durable exact
terminal and the monotonic-witness assumption; it never proves non-commit.
After Closed and retirement, the unchanged P0 owner may activate only while the
original credential, policy, roster and fresh witness admission remain valid.

`activate_witnessed_policy_renewal` separately returns the same original service,
signer and enrollment owners. `activate_witnessed_policy_renewed_session` restores
an original established session through its unchanged bundle, transcript, archive,
role and journal identity. A privately constructed completion capability is held
by that original owner after authenticated enrollment readback. It must match the
journal's exact P approval, proposal, original identity and protection. A direct
journal reopen lacks this capability and cannot activate the adopted policy.

The serialized journal receipt remains AwaitingEnrollment: completion is an
explicit durable fact in the owning enrollment, not a fabricated journal phase.
This avoids a new metadata-only journal head advance after policy expiry. It does
not grant operational permission: every applicable traffic/fanout release checks
current credential and actual roster, live target/runtime and a fresh signed
`AdmitPolicy` (15) response for the exact current authority, P statement and head.
The same checks apply to already cached ciphertext. Historical queries remain
metadata-only. No new bootstrap or prekey-generation permission is granted.

`QPENST16` adds the last Applied-and-retired proposal to the existing witness
metadata under the original enrollment MAC. It survives staging and closure of
the next P; a new Applied retirement replaces it. This lets a next approved P
use an expired actual predecessor without acknowledging history through an
unauthorized ordinary Advance. The reader also accepts QPENST15 and derives a
completion only from its exact AppliedRetired terminal. Reading does not rewrite
old configuration. Inconsistent metadata or a missing completion for AppliedRetired is
rejected. This is an unpublished candidate format, not a product migration
commitment. Local-only enrollment encoding is unchanged.

Focused native checks use real signatures and the actual journal/witness through
a signed in-process transport. They cover the original enrollment/cleanup sync
fault matrix; eight real process terminations across Applied and Closed after
observation, terminal persistence, pending cleanup and final completion; original
expired recovery without a runtime; successive P after expired-predecessor ACK
loss; current owner/roster/runtime refusal; and original-session bidirectional
traffic, one actual rekey, cached message and fanout release fences. These are
finite same-implementation tests, not physical power-loss, live network/TLS,
installed-package or independent-protocol qualification. Required-witness roster
maintenance through enrollment, G/T composition, target-free cancellation,
foreign bindings and supported-platform installation remain open. macOS
qualification targets Apple Silicon only.

## Roster maintenance after independent policy renewal

The native policy-only candidate retains its two-root approval independently of
credential grants. After `activate_policy_renewal` adopts Pnext, the original
enrollment can use `refresh_roster` with that exact current policy, an independently
pinned roster and the unchanged credential. An outstanding policy Pending must
finish first. The update preserves the original journal, controlled signer,
credential history and adopted approval; it does not create a credential grant.

`QPENST11` explicitly marks this monotonic roster binding. Older `QPENST09/10`
records retain exact-roster semantics. Refreshing stores the exact predecessor and
target checkpoints. Reopening through `reconcile_policy_renewal` installs the target
only when the journal still has that predecessor and current C/R/Pnext/runtime
admission succeeds. `activate_policy_renewal` returns an owner only after this
reconciliation and a fresh check against the actual journal roster.

An exact target already in the original journal can finish configuration through
`recover_historical_policy_renewal`, even after the policy/runtime expires. This
finishes metadata only and grants no operational owner. A journal at any other
checkpoint is a conflict; a historical approval cannot install an absent target.
After a sync error or interrupted process, reopen this original enrollment and
recover the same update. Retrying a matching checkpoint preserves the first saved
roster bytes, including its original randomized signature.

This native component covers same-credential local protection. Required-witness
policy-only updates and foreign-language/installed-package
qualification remain separate unfinished work.

## Real credential renewal under an adopted independent policy

After an independent Pnext adoption, `stage_credential_renewal` accepts an actual
account-root G for the same original key, generation, owner and P0. Supply the
currently adopted Pnext; a retained older policy does not authorize the update.
The original `activate_policy_renewal`/`activate_policy_renewed_session` path
coordinates this G and rechecks current C/R/Pnext/runtime before returning an owner.
The independent policy approval is preserved byte for byte and is never converted
into a credential grant. A policy Pending, G Pending and roster Refreshing cannot
overlap new transitions.

`QPENST12` identifies this enrollment transaction; `QPRHST06` identifies the journal
state with the real root-signed G and its original completion receipt. Previous
formats retain their original exact-credential meaning. The journal compares the
actual predecessor before committing, retains the original policy authorization,
and withholds operational use until enrollment completion is acknowledged. Later
G grants and roster updates preserve that authorization. A subsequent independent
policy approval binds the then-current C/R directly again.

The latest carried G is retained as bounded historical public evidence separately
from the active membership index. A higher device generation may prune the old
active G entry, but cannot erase the old committed result needed by interrupted
enrollment. Retaining that evidence never restores old-generation membership.

After an unknown result, reopen the original enrollment and inspect its G status.
`recover_historical_policy_credential` requires the exact original G operation and
statement plus independently verified P0/Pnext history. It can complete an already
committed G with the runtime closed and private signer unavailable. An absent G
remains Pending/Suspended; this is not an abandonment result. Current expiry or
revocation still denies an owner after historical completion. Required-witness G
carrying independent policy renewal, live-target cancellation and installed
foreign-language qualification remain unfinished.

For an expired fixed G target, call `reconcile_expired_policy_credential` with
its original operation and statement, independently verified P0/Pnext history,
and a trusted current time. An exact existing journal commit remains Committed;
expiry never relabels it as uncommitted. Otherwise the journal must still prove
the exact same-generation predecessor in its monotonic history, and at least one
of the signed target credential, target roster or adopted policy validity
intervals must have ended. Only then is `ExpiredUncommitted` retained. A higher
generation or another state that lost this proof is a conflict and leaves Pending.
Runtime closure by itself is not an expiry condition.

This classification needs neither a private signer nor a live runtime and does
not grant an owner. After an uncertain config write, repeat it for the original
operation. A known last completion also finishes its outstanding G ACK when it
is still the current transaction. Successful abandonment keeps the observed
journal head and a monotonic time floor while clearing only the original Pending.
The original journal is not reset. Obtain a separately authorized new operation
from the actual predecessor; if Pnext expired first and the old credential is
still current, an independent next-policy approval can proceed first. The floor
survives both subsequent policy adoption and G completion, and the abandoned G
operation cannot be revived under a newer policy.

The last exact abandonment stays queryable until another abandonment or a later
G completion replaces it. Applications needing longer history must retain the
returned result. Live-target cancellation and ambiguous higher-generation
credential supersession remain unfinished; a conflict is never
treated as proof of no commit.

## Resolving an original independent policy operation

After an unknown policy-only result, retain the original operation and statement
and call `resolve_policy_renewal` with independently verified P0/target policy
history and trusted current time. This local native metadata entry uses neither
the live runtime nor the private signer and returns no operational owner.
An exact adoption in the original journal is recovered as Committed, including
its enrollment completion and receipt ACK. Later roster advance, revocation,
credential expiry or policy expiry does not turn that adoption into no commit.

Otherwise, the actual journal must still contain the exact policy predecessor.
Only then can signed fixed-target expiry (unchanged credential, roster or target
policy) or strict advancement of the actual roster make that original approval
permanently unusable and produce `AbandonedUncommitted`. A still-live target with
the same roster remains Pending/Suspended. A different or later actual policy
remains a conflict; the resolver does not infer absence from that error.

The original Pending approval becomes a separately typed retained result. It
preserves the original operation, statement, target, full approval, observed
roster, reason and observation time; the journal is unchanged. `QPENST13` wraps
the explicit prior enrollment format and this extension under one original MAC.
An independent monotonic time floor survives later credential/policy transitions.
After an uncertain configuration write, reopen and retry the same operation.

Obtain a fresh approval from the actual predecessor after resolution. When the
original policy is still current, its ordinary roster/owner path remains usable;
an adopted independent policy keeps its exact prior approval and owner path.
If only an unadopted first policy failed and C0/P0 are expired, the existing real
joint G/T renewal may proceed from P0. This does not solve joint expiry of an
already adopted independent policy and its credential.

The last abandoned policy result remains queryable while a new operation is
Pending, until another abandonment or a later policy completion replaces it.
Applications needing a longer history retain returned results. The local record
does not provide rollback protection against restoration of the entire
authenticated enrollment and journal without an external witness. Required-witness
resolution, live-target cancellation and installed
foreign-language qualification remain unfinished.

## Resolving an original roster refresh

Retain the previous and target checkpoints returned by `refresh_roster`.
After an unknown result, `resolve_roster_refresh(previous, target, P0_history, now)`
uses the original enrollment and journal leases to read the actual head and
retain one explicit result. It requires independently verified original policy
history and trusted current time. It does not require a live runtime or private
signer and never installs a roster or releases an operational owner.

An exact actual target yields `Committed`. A journal below the target plus
expiry of the signed target roster yields `ExpiredUncommitted`. A different
head at the same target version proves `SupersededUncommitted`, because the
journal rejects a conflicting head at that version. A higher head yields
`SupersededUnknown`: the target might have committed before being superseded.
The API does not infer absence from a newer head or from a generic conflict.
A live target beyond the actual head stays Pending/Suspended; credential or
policy expiry alone is not roster expiry.

The observed signed roster, exact original target bytes, checkpoint pair, result
and observation time are retained under `QPENST14`. The wrapper preserves the
explicit older format, including `QPENST13` when an independent policy outcome
also exists, under one MAC. Current operations observe both floors.

Where the observed head contains a valid historical snapshot for the retained
credential, configuration is aligned to that actual head. It still needs current
credential/roster/policy/runtime admission before returning an owner; in
particular, an old expired roster does not become current again. Obtain a fresh
independently pinned roster, or a real G/T authorization when C0/P0 have expired.
An adopted independent policy and its real G history remain unchanged.

If revocation, a replacement credential or non-overlapping validity intervals
prevent this alignment, status is `RosterResolved(result)`. Historical metadata
remains readable and owner activation is suspended. A later refresh must name
the observed head and pass the existing membership, lineage and journal checks.
It cannot restore a revoked generation by clearing the old Pending.

After a save error or process loss, reopen and repeat the same checkpoint pair.
The last result remains queryable through later policy/credential/roster
transitions until another roster resolution replaces it; retain it externally
for longer history. Required-witness resolution, cancellation of a live target,
full authenticated snapshot rollback protection and foreign-language/installed
qualification remain separate requirements.

## C ownership bridge

The unpublished C registration owner delegates this same transaction, from an
approved intent and explicit wrapping-key provision through request, acceptance,
storage preparation, activation and same-credential roster continuation. Successful
activation moves the entire `EnrolledDevice` into the existing device parent;
peer calls borrow its service/signer while its registration lease remains held.
It does not extract those parts into a lower-level installation owner. Missing
registration cannot select a legacy constructor or recreate a key. Failed native
transitions expose their original error and consume the C registration owner;
the caller disposes its handle and resumes the original state, including possibly
committed Active. SDK policy/store, application TLS configuration and independent
authority transport remain application integration inputs. See
[the C entry sequence](../../bindings/c/ContinuityPackageConsumer/README.md#registering-an-original-device)
and its header for input lifetimes, exact disposal and cancellation behavior.

Swift and Kotlin wrap this same C transaction with immutable public inputs and
six-phase status validation. Their setup/registration transfer cell moves one
native owning reference into the device only after successful activation; neither
ARC nor Cleaner owns a second wrapper for the same raw handle. On failed transfer,
the original language reference remains available for disposal. Successful transfer
makes closing an old registration alias harmless to the device. The package gate
requires observed old-wrapper release, separate-process lease exclusion, original
session retry and both witness carriers. These finite checks do not provide
Android/browser persistence or credential/root/policy replacement.


## Original enrollment atomic roster coordination

`prepare_witnessed_roster_refresh` accepts a separately pinned root-approved
same-credential target, original P0 history and the unchanged current verified P.
It retains the original R operation, expected/target roster, exact P checkpoint
and optional independent-P statement before sealing. The actual original journal
must agree on the predecessor. The first saved target bytes are reused on retries;
this method does not perform independent witness preparation. After an uncertain
return, reopen the original enrollment and inspect
`recover_witnessed_roster_refresh_preparation`. A locally absent pending is not a
witness Closed or NoCommit result.

The witness operator independently calls `AnchorStore::prepare_roster_refresh`
on that complete original proposal and its verified inputs. The original signer
client can then commit, close or reconcile that exact proposal. Commit requires
live target membership/P/runtime; status and closure can use historical authority.
Fresh Applied installs only the already sealed original target. The enrollment
then saves and authenticates its terminal, adopting the target roster only for
Applied and retaining the predecessor for Closed. That private terminal capability
is the sole authority for witness ACK and exact journal pending removal. Finally
the enrollment saves retirement. Unknown commit/status/ACK/configuration/cleanup
outcomes reopen the same installation and operation. Even retired-result lookup
checks the caller's full original proposal before returning history.

`QPENST17` wraps the existing enrollment image with the bounded R scope, signed
target roster and optional complete proposal/disposition/retirement metadata,
under the original MAC. Previous supported formats remain readable without an
implicit rewrite. Malformed scope, signed roster, phase, flags or trailing bytes
are rejected. This is an unpublished candidate format, not a product migration
commitment. The independent P completion stays intact when R advances; its
credential binding permits a monotonic roster while still refusing real G/T.

A staged intent with no released proposal and no journal pending may be explicitly
abandoned using `abandon_unprepared_roster_refresh`, under the original service
lease. Its retained `AbandonedBeforePreparation` result is distinct from witness
Closed and grants no ACK authority. This handles expiry between the intent save
and journal preparation. A saved/reserved target cannot use that exit. The next
R must exceed the retained attempted target version, including after Closed or
local abandonment; it cannot recycle an old target version.

Unretired R blocks new P requests/staging and operational owner release. After
retirement, original P0 uses ordinary activation; a completed independent P uses
`activate_witnessed_policy_renewal` and fresh current authority admission. No new
signer, wrapping key, installation or journal is provisioned. The native tests
check current owner/lease identity, exact ciphertext, P after R, R after a closed
P, next R after an expired Applied/Closed target, reply loss, consumed sync faults
and eight actual process cuts. Historical cleanup after expiry grants no current
permission. Tests also reject substituted proposals before any dispatch, including
when the genuine result is already retired.

The signed transport in these checks is in-process. Original session/fanout
behavior across R is now checked separately below. Broader concurrency, real G/T
and external lost-device revocation or key replacement, network/foreign bindings,
installed packages and platform guarantees remain required for the full 0.2.0
lifecycle. A previous legacy split witness/journal roster state remains a separate
recovery/migration gate. macOS support is Apple Silicon only.

### Original traffic across R

Real original enrollment/installation owners establish and archive their sessions
before P0 expires. After independent P adoption and each endpoint's atomic R
transaction, historical reopen retains the same transcript, session, signer and
journal. An already prepared PQ offer and individual outbox replay as the same
bytes after a lost R ACK, then complete the same control exchange and decrypt
bidirectional epoch-1 messages under current authority. This demonstrates protocol
continuity, not fresh entropy or a post-compromise security claim: a contribution
retained before R remains that original contribution.

A separate three-device scenario establishes two sessions to one independently
root-authorized two-device recipient account. One member is consumed and ACKed;
the other remains unconfirmed. Sender-side R and independent P preserve the full
batch, each original member/message ID, the consumption distinction and exact
remaining ciphertext. Changing the installed recipient roster suspends that
original batch under its original roster checkpoint, even if membership is the
same. It cannot silently replace recipients or release a member through ordinary
individual replay. Explicit session closure emits complete historical accounting;
the test host writes and syncs those reports before acknowledging closure. The
first message stays Acknowledged and the unconfirmed second stays DeliveryUnknown;
only then may the original fanout metadata retire. No business exactly-once or
remote atomic-effect guarantee is implied.

Six additional negative scenarios exercise cached individual and aggregate
release after R: witness time expires P independently of the SDK time, the runtime
closes during the final signed admission reply, or an actual root-signed peer
revocation is installed locally. Each release fails through its specific authority
boundary and leaves the original authenticated journal revision/digest intact.
The revocation scenario validates dispatch enforcement after receipt of a trusted
update; it does not qualify an external lost-device revocation control plane.

## Permanent enrolled-device retirement and logical signer erasure

The native `RetiredDeviceEnrollment` coordinator holds the original enrollment lease
through cleanup. `EnrolledDevice::retire(pin, retired_subject)` consumes the existing
service and signing owner while keeping that enrollment lease. After a process loss,
`RetiredDeviceEnrollment::open` uses the original paths, enrollment intent, verified
permanent retirement and original witness pin. It authenticates historical original
identity metadata without returning an operational owner or requiring a live policy.
This path currently requires the original **Active, required-witness installation**.
Pre-activation retirement, local-profile retirement, foreign bindings and other
platform durability remain separate qualification gates.

`installation()` borrows the existing restricted installation flow described in
`ANCHOR_WITNESS.md`. Its saved inventory, complete report, explicit durable host record,
independent purpose-21 acknowledgement and journal erasure keep their existing order.
A subsequent borrow reopens only that same saved expectation, including after
`erase_journal` closes its child. A missing file or another backup is never selected
as a new original. The host still owns business-effect accounting and deduplication.

After authenticated journal erasure, `prepare_signer_erasure(ack_receipt)` verifies the
original host decision and persists an exact signing-file plan **before** file mutation.
The plan binds the original signing-file identity, device role and public key, complete
sealed bytes, filesystem device/inode, and the original report. Exact preparation
retries keep the first plan. `erase_signer()` needs only this saved acknowledged plan;
it returns success after durable logical erasure and always closes the owner. Reopen
and query `signer_erasure_status()` or retry the same plan after an uncertain result.
`Retained` means encrypted seed bytes remain, even if a partial retirement header already
prevents ordinary opening. `Erased` requires the exact terminal inode and independently
verified host acknowledgement. Missing, foreign and corrupt files fail explicitly.

The additional enrollment row, named `retirement`, is `QPERTR01` under the existing
binding-specific enrollment MAC. It includes the exact original enrollment-row digest,
signing identity and original cleanup inventory. The pre-plan form is 450 bytes. The
4621-byte prepared form additionally retains `QPSRPL01` (441 bytes) and the full
3730-byte purpose-21 receipt; the row is bounded at 8192 bytes. The original enrollment
row is unchanged. Ordinary enrollment admission returns `Suspended` once the retirement
row exists. Older readers refuse the extra row, rather than silently dropping it.

File erasure holds an exclusive lease on the exact private, admitted inode. It writes
`QPSRET01` over the eight-byte public header and syncs that file, then truncates it to
those eight bytes and syncs again. No admitted basename is unlinked or replaced.
During recovery, only original/retirement header-byte mixtures may be reconstructed
in memory. The entire remaining ciphertext must reproduce the original fingerprint,
authenticate under the original wrapping key, and reconstruct the original device
public key. Even a forged local plan MAC/fingerprint cannot authorize erasing another
public key using the old device's signed host ACK. A replaced pathname is preserved;
an operation that erased only its original admitted inode reports the name conflict.

The terminal tag by itself proves no host decision. The independent enrollment plan,
original report receipt and original file identity are all required for reconciliation.
The original wrapping key remains necessary for historical metadata verification.
Retained pages, filesystem snapshots/backups, closure archives and signing owners
previously copied outside this coordinator remain outside the logical erasure claim.
This is not cryptographic erasure or proof that an attacker has lost earlier knowledge.

Regression coverage includes a live enrolled-owner transfer; policy adoption and carry
at all three real G transaction cuts; wrong-purpose/corrupt receipts; missing, swapped
and modified signing files; a correctly MACed foreign-file fingerprint; all nine public
header write prefixes and ten before/after I/O cuts; separately calibrated enrollment
marker and signing-plan commit failures; four owned-child process cuts; and an admitted
basename replacement while the child is paused. Full initialization-state, installed
foreign-language and physical-device acceptance is not inferred from these cases.

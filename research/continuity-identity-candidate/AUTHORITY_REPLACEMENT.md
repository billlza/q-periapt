# Account-root and witness authority replacement

Status: the native witness account-root transaction, original-journal fence,
original-enrollment parent fence and explicit peer-account retirement are implemented;
the complete managed account cutover and witness-key handoff
are **not implemented**. Both
remain part of the required 0.2.0 lifecycle. Existing registration, credential
renewal, policy continuation and device replacement do not complete that lifecycle.

## Preserve the current identity meanings

`identity::account_id` commits to the complete root public key. A new root has a
new cryptographic account ID, even when the device key, device ID and generation
are unchanged. `AccountPin::new` correctly refuses an old account ID paired with
the new root. The enrollment intent, immutable storage owner and signed rosters
also bind the original root/account. Those checks must remain.

A product may keep the same **application account** across this transition, but
that mapping needs independently authenticated host authority. It must not rename
an old cryptographic account, rewrite its journal header or derive the application's
account association from a replacement message. The original account, session,
message and delivery identities remain attached to historical records.

Creating a new `AccountPin` does not revoke an existing pin, verified roster or
stored roster. Closing a root signing owner only removes that owner's ability to
sign; it does not revoke issued credentials. `VerifiedRoster::from_journal`
authenticates the original stored authority; it is not a root-replacement registry.
The product transition therefore needs a durable current-authority owner whose
fence applies to cached objects, reopened state and newly admitted peers.

The [source-bound boundary experiment](../sdk-alpha1/evidence/20261010-authority-cutover-boundary/CHECKS.json)
executes six isolated cases and an existing pinned-root negative control. Its
real witness-store case retires the original device, enrolls a new-root account,
then explicitly enrolls a previously unseen device under the old root. The old
device remains retired; the other two subjects remain current after reopening
the MAC-authenticated witness store. These are trusted-control-plane operations with actual
signatures. The result confirms the existing per-device contract and rules out
using that composition as account-root retirement; it is not a network enrollment
exploit or an implemented replacement transaction.

## Authorization and disclosure scope

Recovery after disclosure of the old root requires approval independent of that
root. An old-root signature, even together with a new self-signed root, cannot by
itself distinguish an authorized recovery from an attacker-selected successor.
The host must authenticate the application account and independently obtain the
exact target root and roster expectation before approving the transition.

Approval must bind the host's original account association, original authority
revision, original and target cryptographic account/root, operation ID, target
enrollment identity, policy family and witness authority. Retries retain this
whole operation. The target's credential and device proof must still verify under
the independently selected target root. Public IDs and a structurally valid
descriptor do not supply this approval.

Root-only disclosure is separate from device signing-key, policy-root, witness,
wrapping-key or entropy-source disclosure. Recovery cannot reuse an authority or
secret whose continued trust is assumed without stating that assumption. It
cannot promise to remove knowledge already obtained by an attacker.

## Durable cutover obligations

The following are required state properties, not allocated wire tags or a final
storage layout:

| State | Required behavior |
| --- | --- |
| Current | Only the independently retained current authority admits new operations. |
| Replacement intent retained | The exact approved operation and target survive restart; old authority is fenced before the transition reports that fence as durable. Unknown persistence outcomes permit only original-operation reconciliation. |
| Target prepared | Original target configuration/enrollment and any witness preparation are retained. Preparation alone grants no target traffic authority. |
| Target committed | The durable authority revision selects the exact target. Final activation checks it before returning an owner. Cached old owners cannot release new operational results. |
| Historical cleanup | Old sessions and operations retain their original identities and explicit outcomes. Cleanup cannot reactivate the old account or turn unknown delivery into success. |

An approved recovery cannot fall back to the compromised root because target
creation, network access or witness confirmation fails. Partial target creation
must resume the original operation, without reusing the old journal as the new
account or silently generating another enrollment. Any cancellation semantics
must distinguish a planned rotation from recovery after revoked trust; cancellation
must not be invented as an automatic error path.

The owner must govern both local-account and peer-account admission. Borrowed
Rust handles, foreign aliases, reopened journals and fresh configuration imports
must not bypass its persisted authority revision. Existing session views are
historical inputs; carrying a session into a new root requires its own explicit
construction. The initial replacement path should establish a fresh authenticated
session under the new account while preserving old loss/delivery accounting.

## Required witness boundary

Existing witness device replacement retires named device subjects. Root retirement
must also reject future enrollment under the retired account/root, including a
device ID that was never previously observed. Enumerating only existing subjects
leaves that case uncovered. A durable account-wide retirement floor must govern
both trusted-control-plane enrollment and ordinary subject operations; host
approval of a stale descriptor cannot erase the floor.

Keeping the witness key during account-root replacement and replacing the witness
key are distinct transitions. `AnchorPin` binds both the witness instance ID and
its full public key: reusing the instance ID with another key changes its binding.
New witness enrollment at revision one must not stand in for transfer of an old
head, fence, last-command identity, retired authority floors or pending outcomes.

A witness-key handoff needs exact retained state and independently authorized
target trust. If the old witness is compromised or unavailable, its signature or
silence cannot prove a safe current head or an uncommitted operation. That case
needs an explicit recovery construction and unknown-outcome treatment. Neither
root replacement nor fresh installation silently supplies it.

## Acceptance before product admission

### Native witness transaction

`account_root_replacement_proposal` retains an independent operation ID, both full
roots, a fresh target account/journal and all old-account subjects. The operator
must authenticate application-account recovery and the target enrollment outside
this API. Incoming bytes or the old root's signature cannot supply that approval.
The target must use the same required witness and different root-key components.
Unknown legacy entry identities suspend preparation until independently classified.

`replace_account_root` compares the exact original descriptor, current target
authorization and complete old-account snapshot before one atomic store commit.
It admits the target genesis and permanently fences old-root enrollment, including
unseen device IDs, old subject requests and device-replacement attempts. Unrelated
account progress does not invalidate the old-account snapshot. A changed old head,
new old-account subject, competing target or reused operation identity conflicts.
Requests served before the commit may still arrive late over a transport; this
witness transaction does not replace a local managed-authority fence.

`account_root_replacement_status` and exact committed retries preserve historical
Committed after target expiry. Unavailable never permits fallback. Sync failures
consume the current store owner and can follow commit: reopen the same instance
and reconcile the original descriptor. No frozen head, pending command or unknown
delivery is reclassified as successful consumption.

`retired_account_observation` returns frozen public metadata.
`retired_account_receipt` signs purpose 22 over
`QPARTR01[8] || witness_binding[32] || proposal_binding[32]`; its verifier is
`AnchorPin::verify_retired_account`. It is a 72-byte body and 3449-byte envelope.
The statement proves historical retirement under continued witness key/storage
trust, not freshness, successor permission, physical erasure or witness migration.

The canonical unsigned proposal is `QPARPL01`, with a 4452-byte fixed portion and
209 bytes per frozen subject. At most 256 subjects and 65536 input bytes are
accepted. Its binding uses domain `Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-REPLACEMENT/v1`.
The store emits `QPANC015` when account replacements exist without preparation freezes. It retains all old
entry layouts, device retirement, cleanup, reports and acknowledgement records.
Earlier layouts keep their canonical nonempty-table requirements; empty older
sections are permitted only inside this new aggregate format. Unknown versions,
including reserved `QPANC005`, still refuse admission.

The existing 256-entry and 1-MiB aggregate limits still apply, along with a maximum
of 256 account-replacement records. Capacity failure commits nothing and is not a
successful emergency fence. Capacity planning/reclamation, the local authority
owner, account authentication, foreign adapters and complete cutover failure
qualification remain product requirements. The witness's own rollback protection
remains an independent deployment assumption.

The [2026-10-10 native qualification](../sdk-alpha1/evidence/20261010-account-root-retirement/CHECKS.json)
retains 828 passing Release library tests, 12 focused root-retirement test entries
(including one subprocess helper), 15 compile-fail doctests, strict Clippy and the
Rust 1.90 check. The focused paths exercise four real pre/post-sync failures and
process termination after durable commit but before return. These fresh macOS
arm64 fixtures qualify this native component; they do not complete the managed
local/foreign cutover or the platform requirements below.

### Local original-journal transaction

`DeviceJournal::begin_account_root_replacement` consumes that journal's operational
ownership and retains the exact independently approved witness proposal. Its
`AccountRootJournalRecovery` result cannot return a traffic owner. The original
encrypted image and pending write/cancellation bytes remain unchanged, including
unresolved outcomes. This local transaction does not advance the witness head and
therefore does not itself invalidate the original root-replacement snapshot.

The separate `account-root-fence` row uses `QPARJF01`, a dedicated HKDF-derived MAC
key, the original subject/image and the exact pending-intent commitment. Ordinary
opening and existing lifecycle recovery reject it. `resume_original` only
reconciles the independently retained original inputs against existing storage;
missing or conflicting files never create a new journal or an old traffic owner.
I/O errors close ownership and may follow commit.

`LocalFenced` reports no witness outcome. `retain_witness_retirement` authenticates
purpose 22 and durably retains its original statement before reporting
`WitnessCommitted`. Re-signing the same statement does not replace the first
retained receipt. Historical observation remains possible after runtime closure;
neither state admits the successor or turns an unknown old delivery into success.

The [local-fence qualification](../sdk-alpha1/evidence/20261010-account-root-local-fence/CHECKS.json)
retains 838 passing Release library tests, ten focused entries (one subprocess
helper), 16 compile-fail doctests, strict Clippy and the Rust 1.90 check. Four
fence-sync faults, six receipt-sync faults and four real process-termination cuts
preserve the original image, pending intent and operation. These are native macOS
arm64 component results, not full managed-cutover or cross-platform qualification.

This is one **required-witness journal** component, not the independent current
account-authority store. In particular, restoring the whole journal from before
the local fence can remove that row before the witness commits retirement. The
parent intent is retained by the enrollment integration below. A stable current
authority revision must still govern all configuration imports/reopen. Peer-account
admission, successor installation/activation and the account-specific historical
cleanup workflow also remain to be integrated. A per-journal marker must not be
described as an executed managed account cutover or whole-host rollback protection.

The [fresh backup-boundary experiment](../sdk-alpha1/evidence/20261010-account-root-backup-boundary/CHECKS.json)
confirms this distinction with a real two-endpoint handshake and application
ciphertext. Before witness retirement, restoring the complete pre-fence journal
permits anchored reopening and release of the identical cached ciphertext. After
witness retirement, the same restored bytes cannot reopen a traffic journal. The
fixture transport reports the witness's refusal as unavailability; a separate
purpose-22 receipt supplies authenticated historical retirement. This does not
test whole-host or witness rollback.

### Original enrollment parent transaction

`EnrolledDevice::begin_account_root_replacement` consumes the old service and
signer, retains the exact independently approved proposal in its original
enrollment database, then fences the original journal. The existing enrollment
lease and wrapping-key/path binding remain authoritative. Its separate
`root-replacement` row uses `QPERPL01` and authenticates the unchanged enrollment
image, signing identity, journal identity and complete proposal. It does not
rewrite the original enrollment, key, credential, policy or roster history.

`AccountRootEnrollmentRecovery::resume_original` opens only those existing paths
and the independently retained original intent. A failed first parent commit can
be reconciled with the same proposal. Once the marker exists, a competing proposal
is refused, and ordinary enrollment opening, activation and credential/policy
recovery cannot use the parent for traffic. Restoring only the old journal does
not remove this enrollment fence. Recovery re-establishes the exact child fence;
missing children or signer files never trigger replacement or key generation.

`IntentRetained` reports no witness outcome. Receipt retention first verifies the
exact purpose-22 statement and durably retains it in the child, then in the parent.
Only the latter boundary acknowledges `WitnessCommitted`. Loss between commits
requires the original operation/receipt; it cannot infer no-commit. A retained
parent receipt also survives a later child-backup restoration. Historical recovery
does not reopen signing material or require a live traffic runtime.

The native focused checks exercise restored child backups, two competing intents,
bad signatures/MACs, authenticated wrong-image markers, extra schema and missing
children. They measure three parent sync barriers for intent and three for receipt,
inject all twelve pre/post-sync faults, and terminate owned processes at both sides
of both commits. Target enrollment activation remains a separate current-authority
check; the same prepared target refuses before witness admission and succeeds after
the actual witness commit. These component checks do not qualify installed foreign
calls or replace the full regression and platform gates.

This parent is one original local enrollment. It does not implement a stable
application-account authority registry, govern arbitrary low-level journal imports,
fence cached remote-account owners, select/activate a successor on the user's behalf,
or transfer the witness key. Restoring the parent or whole host is outside this
local backup boundary. These remaining obligations still block managed cutover.

### Explicit peer-account retirement

`DeviceService::retire_peer_account` explicitly adopts an `AnchorRetiredAccount`
that the host has authenticated and independently approved. Receipt verification
remains pure. Adoption requires a known remote account, the original installation's
required witness and current local credential/policy authority. It cannot retire
the local account or admit an unknown peer. A different witness is refused even
when its signature is valid.

The original roster record gains a `QPRHST07` prefix containing the operation ID,
statement commitment, successor account and witness binding (136 additional bytes).
The encrypted journal authenticates this local decision; these fields are not a
transferable witness signature. Retain the original proposal and receipt for exact
reconciliation. Historical rosters, generation floors, renewal grants, session and
message identities remain intact. Ordinary roster and credential refresh cannot
clear the retirement marker, including an otherwise identical refresh.

The normal encrypted-image/write-intent transaction advances this sender's own
witness head. After acknowledged commit, an older whole-journal backup cannot
remove the peer floor while that witness retains its current state. Storage errors
close the journal and may follow commit; reopening reconciles the original sealed
intent before admitting traffic, and the same retirement can then be retried.
An identical retry performs no additional journal transaction. Capacity and policy
errors do not claim that a durable fence exists; managed approval-intent retention
before this component remains part of the unfinished account-authority owner.

Operational admission checks the marker for cached sessions, fresh bootstrap,
message/retransmission and complete-roster fanout. Historical cleanup still reports
the original peer and unknown deliveries; it does not relabel them under the target.
The successor account is recorded for correlation only. This operation selects no
application-account mapping, creates no successor session and transfers no witness
trust. Foreign adapters and complete managed cutover remain required.

The peer-adoption process regression also kills the actual sender process at four
boundaries: before an intent exists, after the original sealed intent is durable,
after the real witness commits while its signed reply is withheld, and after the
local image commit before the API returns. The parent retains the same durable
witness and independently verifies its signed head replies. Restart resumes the
exact original statement, preserves unknown delivery accounting and never advances
the head again merely for an identical retry. Before intent persistence, the test
correctly observes that no durable local fence exists yet; it does not infer one
from host approval. These are process-loss checks with a bounded test IPC carrier,
not TCP/TLS qualification, simultaneous witness failure or physical power-loss tests.

### Remaining product acceptance

Actual installed owners must exercise the same original operation across cuts
before and after each durable boundary, lost replies, competing targets, stale
approvals and reopening. Check cached aliases and old configuration imports after
commit, old-root issuance for a previously unseen device, full-roster fanout races,
and old-account traffic/ACK rejection under the new account. Reports must retain
unknown old deliveries without relabeling them as delivered or replaying their
business effects under a new identity.

Keep signature/namespace experiments, authenticated-store transitions, witness
transactions, installed foreign calls and platform persistence as separate evidence.
A pin decoder or a successful new registration is not an executed root cutover.

### Application authority registry component

`AccountAuthorityStore` is a native foundation for an independently authenticated
application account ID and its current cryptographic root. It retains the exact
approved replacement proposal, advances its own revision by one on verified
witness retirement, and preserves original-operation history. A pending entry
suspends both roots at this registry. Its old read leases stay revoked after a
replacement or owner close; an unrelated application's successful update does
not revoke other entries. An uncertain database mutation closes the owner and
all its leases, and recovery must reopen the same path/key/identity and retry
the original proposal or verified retirement.

The public state is MAC authenticated under a separately retained key, with
path, registry identity, policy family and witness binding. The committed bit
records the locally verified decision; the registry does not retain a separately
transferable witness signature. This is neither encryption nor protection from
rollback of the entire registry or host. The bounded format currently retains
64 associations and 256 replacement operations globally, with explicit capacity
errors. Resetting history to regain capacity is not a supported recovery path.

`DeviceJournal::adopt_account_authority` now explicitly binds an existing
required-witness journal to the original registry and local application revision
through its ordinary image/write-intent/witness transaction. The new authenticated
image variants `QPVLT023`/`QPVLT024` add a 104-byte registry/checkpoint binding;
unbound `QPVLT021`/`QPVLT022` encodings remain unchanged. This is an explicit format
transition: older readers cannot open the new image. The original witnessed head
refuses a restored pre-binding backup. Neither format conversion nor missing
storage is silently recreated during reopen.

`open_anchored_with_account_authority` requires the same registry scope before
replaying any saved adoption intent and rechecks it after witness I/O. Ordinary
open refuses a bound image or pending bound target. Each live local and peer
admission reads the registry's current mapping; post-witness message, ACK and
fanout release checks repeat that admission. A shared registry read lock checks
the selected accounts at one point before returning, while replacement invalidation
takes the write lock before persistence. This does not recall bytes already returned
before a fence. A parent intent that precedes the journal fence resumes through
the existing restricted `AccountRootJournalRecovery`, without reopening old traffic.
Historical peer-delivery accounting preserves its original account and unknown
outbox even when current peer traffic is refused.

This is still a native journal component. Owning installation/enrollment binding,
original successor enrollment coordination, lifetime-capacity migration, foreign
owners and witness-key handoff remain required for managed cutover.
An executed counterexample also remains open: an ordinary old-device message
committed after proposal capture makes that original witness snapshot stale.
The registry correctly retains its original pending intent and refuses to replace
it with a fresh proposal, but currently has no terminal reconciliation path for
this race. Managed orchestration needs a preparation freeze or an authenticated,
durably terminal decision that the original proposal can never commit. An absent
observation, local reset or silent proposal regeneration is insufficient.
Observing a committed historical operation never authorizes its successor if a
later operation has already retired that root.


### Durable preparation freeze component

`AnchorAccountFreezeRequest` binds an original independent approval to the witness,
old cryptographic root and a separate freeze operation ID. Retain that request
before submitting it through the independently authenticated control plane.
`freeze_account` captures all then-current old-account subjects and freezes the
whole namespace in the same witness transaction. An old device can advance before
this transaction and its new head is then included; it cannot change the snapshot
after it commits. Known subjects and future unseen devices are refused through the
ordinary request, trusted enrollment, replacement and renewal admission paths.
Unrelated accounts remain usable. Unclassified legacy entries prevent the freeze.
A root signature alone remains insufficient control-plane authority.

Freeze is a historical preparation fact, distinct from permanent replacement,
delivery, erasure or permission for a successor. No target is enrolled by freezing.
After an uncertain commit, reopen the same witness and retry the original request;
a matching retry returns the retained original snapshot without advancing revision.
A changed request or reused operation under another root conflicts. Absence does
not mean terminal non-commit, and no unfreeze/reset operation is provided. Delayed
pre-freeze operating replies remain possible; local account-authority admission
must still fence release.

The `QPANC016` authenticated witness image retains canonical `QPAFRZ01` snapshots,
including for an empty namespace. Prior layouts and unfrozen `QPARPL01` descriptor
bytes stay unchanged. A frozen replacement uses `QPARPL02`, adding 32 bytes for the
original freeze binding. `frozen_account_replacement_proposal` accepts only the
exact retained freeze; both fresh commit and image validation enforce this binding.
An equal old head is insufficient to reuse an unbound legacy proposal. Actual
replacement still requires independently approved, currently valid target inputs.

`account_freeze_receipt` carries the bounded complete snapshot followed by a
3449-byte signed envelope. Signature purpose **23** authenticates a 72-byte
`QPAFRS01` statement containing the witness and a domain-separated digest of the
complete snapshot. This preserves the existing 16 KiB signed-body ceiling while
supporting all 256 subjects. `verify_account_freeze` requires the independently
retained original request and pin, bounds and parses the complete snapshot, then
checks both signature components and the exact commitment. Neither this receipt
nor its type can substitute for a retirement receipt or a fresh operating reply.

This native component resolves snapshot capture races only when the caller uses
this preparation path. The existing registry counterexample remains a valid
observation for its old read-only proposal path. Managed orchestration must still
persist an original local draft before freezing, reconcile the exact returned
snapshot, obtain independent target approval, and coordinate original enrollment
and child journal fences. Target expiry and competing approvals need an explicit
terminal reconciliation contract; freezing alone does not supply one. A full
witness can still lack room for the successor, and retained freeze/replacement
history requires a bounded lifetime-capacity migration design. Foreign owners,
installed consumer qualification, witness-key handoff and whole-host rollback
protection remain separate work.


### Original local preparation intent

`AnchorAccountReplacementPlan` (`QPAFPL01`, bounded to 8192 bytes) is an independent
approval of a fixed target and one exact future freeze request. Its dedicated
constructor validates the target through existing witness enrollment checks but
does not claim that a transient old-head observation is the approved snapshot.
A retained exact legacy proposal is never implicitly converted into this plan.

`AccountAuthorityStore::begin_preparation` records that plan under the original
application checkpoint before witness freezing. The new `Preparing` state revokes
old leases and denies both old and target authority through the existing journal
admission checks. The `QPAAST02` registry image preserves the plan alongside the
operation for its entire history; images without plans still use the exact prior
`QPAAST01` layout. Older readers reject the new layout. The existing 64-account and
256-operation limits remain; each record can additionally hold one bounded plan.
These are explicit candidate-format transitions, not a released ABI promise.

After reopen, `preparation` returns the same original plan. `replacement` returns
`Suspended` while only the target template exists, so it cannot be mistaken for an
exact witness proposal. `bind_preparation` accepts only an authenticated freeze
whose full original request matches that plan, then fixes the exact snapshot and
enters `Pending`. The immutable plan survives binding and root commitment. No
request, target or bound snapshot is silently regenerated. MAC-authenticated image
validation rejects a committed unbound template or a binding inconsistent with its
original plan. It records a locally verified decision, not a separately retained
transferable freeze signature; witness continuity and whole-host rollback remain
independent assumptions.

The native combination now retains a local plan before freezing, fences real
cached message release, tolerates actual old-device progress after plan creation,
reopens the original registry, binds the exact witness snapshot, resumes the
original restricted journal and selects the successor exactly once. Each of the
three registry mutations has typed pre/post-sync recovery tests. Three actual
owned child processes are also killed after the corresponding database commits
and before API return; each reopens the same registry/key/identity, retains its
original plan and retries without selecting the root twice. The original witness
remains independently retained by the parent in this experiment. This is still a
native composition, not the owning installed workflow, network qualification or
simultaneous witness-loss test. Original successor enrollment orchestration,
authenticated terminal reconciliation for unfinishable targets, lifetime-capacity
migration and foreign owners remain required. `Preparing` or `Pending` must never
be reset to regain old traffic when an outcome is unknown.

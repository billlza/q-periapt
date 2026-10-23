# Independent account-root statements and registry

`account_root_protocol` reconstructs the original planned root transition from
independently selected account, witness, credential, roster, policy and prepared
journal expectations. It uses the Python/OpenSSL implementation's existing
signature and identity verifiers. It neither imports nor calls the Rust engine.

These statement objects provide public protocol verification. The separate
`AccountAuthority` owner below retains original approvals and current root
selection. `EnrollmentClient` can retain that association before child creation;
its normal session and maintenance owners require the same original live lease.
Restricted original-parent recovery survives root preparation. Child retirement
and live successor activation are still open, so this is not a complete device
root-replacement controller.

## Original expectations

A `Plan` contains the original witness pin, target and freeze operation IDs,
previous account public key, successor `DevicePin`, signed certificate and roster,
historical signed policy, journal ID and exact prepared genesis head. These
expectations must come from the independently approved host operation, not from
the incoming plan being checked. The witness must also match the signed policy's
required witness. The two operation IDs are distinct and retained on retry.

`wire()` rechecks signed metadata and constructs canonical `QPAFPL01` bytes.
`verify_plan()` requires exact equality with that construction; it does not
derive trust from a received root or witness key. Target membership, key
separation, policy family, credential/roster/policy validity intersection, storage
owner and genesis bindings are checked. Historical verification does not assert
that any of those validity windows is current.

## Signed observations

`bind(freeze_receipt)` verifies the original request and complete bounded frozen
snapshot under both ML-DSA-65 and P-256 signatures. Frozen subjects are strictly
ordered and their heads, last-command markers and state commitments are retained.
The resulting `Decision` reconstructs the exact `QPARPL02` descriptor using only
that snapshot and the previously selected target.

`verify_retirement()` verifies the account-retirement purpose and exact decision
commitment. `Decision.verify_closed()` verifies permanent non-commit of that
particular bound decision. `Plan.verify_closed()` instead verifies non-commit
of the original plan for every snapshot. The purposes and statements are
different; none can substitute for another, a freeze proof or a live witness
reply. Original statements remain verifiable after policy expiry.

These methods return immutable historical observations, with no traffic owner.
They do not establish message delivery, erase old secrets, reactivate a suspended
root, select a successor, prove that the caller's durable store was updated or
establish post-compromise security. A controller must retain and reconcile its
own original approvals and owner transitions before releasing new work.

## Installed interoperability check

`tests/account_root_protocol.py` runs against an explicitly selected installed
wheel and provider, reading only public outputs and original fixture trust from
the real native witness CLI. It independently reconstructs plan/decision bytes
and verifies signed freezes, retirement and both closure types across commit,
exact-close, plan-close and replan profiles. It checks altered expectations,
canonical bounds, truncation, both signature components and proof-purpose
substitution. The same check runs after the local operator in reference-account
CI and records imported module hashes and public-input hashes.

This qualifies public root-statement interoperability. It does not qualify an
independent live root-replacement controller, a root-replaced session, a physical
device root transition or full release readiness.

## Original application registry

`AccountAuthority.provision` explicitly creates a private original registry. The
host retains its wrapping key, identity, policy family, witness pin and absolute
directory. These are bound into the authenticated journal scope. `open` requires
existing state; it never creates a replacement for a missing registry.
`open(initial=True)` is only recovery of an original revision-zero creation
intent. It cannot create an empty registry or admit a later revision as first use.

`associate` verifies the independently selected signed original device and
roster under the configured family. It creates revision one for an application
ID. This identifies the original root; fresh device/policy permission remains a
separate check. Root reuse across applications or retained transitions is
refused. At most 64 applications and 256 root operations are retained.

`current` returns only an active mapping. `admit` requires that exact mapping
and returns a revocable lease; check it again before releasing work after I/O.
Preparation revokes the affected application's cached leases before attempting
persistence. An unrelated application's lease survives. Parent close, lost
parent ownership, a failed write or reentrant cancellation revokes permission.
Invalid proofs are rejected before mutation and leave the owner usable.

`begin_preparation` accepts a fresh independently approved `Plan`, not a decoded
incoming plan. It retains exact bytes before returning. `bind_freeze` checks and
retains the original signed snapshot. `commit_retirement` verifies the exact
signed retirement and advances the mapping once, including when the authenticated
retirement reconciles an originally unbound preparation. Retries retain the
original operation, target and selected revision.

`close_plan` and `close_decision` require their distinct signed non-commit proofs;
exact-decision closure requires an already bound preparation. Both preserve the
old-root suspension, including after reopening. `operation` exposes historical
checkpoint and plan/decision bytes for recovery without granting work. A later
approved target must preserve any authenticated original freeze request and
snapshot binding. An unbound closure cannot assert that a freeze was observed;
it preserves any prior authenticated retry scope. The host should keep the
original request to reconcile an in-flight unknown freeze. Closed operations
cannot reopen, and committed operations cannot close.

This registry uses the existing encrypted exact-target journal and publication
barriers. Its history has a dedicated bounded allocation within the unchanged
64-MiB directory quota; ordinary session business payloads remain limited to
2 MiB. Stored descriptors are reconstructed from the authenticated original
journal only. They cannot supply new host approval or transferable proof.
The registry is intended to live outside replaceable session backups; it does
not detect rollback of all host-retained authority state by itself.

`tests/account_authority.py` uses real native host/enrollment/witness outputs in
one policy family. It checks active versus historical selection, per-application
lease revocation, invalid proofs, exact versus plan closure, replan, path and
configuration binding, storage errors and actual SIGKILL at all eight publication
boundaries for creation, preparation, freeze, closure and retirement. It records
whether the implementation is source development or an installed wheel. CI runs
the installed scope with that run's generated signed inputs.

## Bound clients and restricted original recovery

After accepting the original device credential, call
`EnrollmentClient.bind_account_root(registry)` before preparing its child. This
retains the exact registry scope and application/revision/account mapping through
configuration-pending, registration-bound and configuration-ready writes. Reopen
with the same `account_authority`; interrupted association resumes those original
records. A missing registry, another registry with the same account, or a missing
known registration binding is an error. Existing clients with an unbound child
use the explicit migration below; they are never silently recreated or relabelled.

New bound children use `QPREFJ02` / `QPREFW02` encrypted headers. Their additional
168 bytes authenticate the original registry scope and checkpoint as associated
data. Ordinary `01` images retain their format. All live session and maintenance
factories require the matching lease for a bound header, including direct raw
opens. Business state, message IDs, outbox contents and payload limits remain
unchanged. New bound children carry the binding before genesis. Migration uses
the original exact-target witness transaction and current authority, and cannot
rewrite an already frozen witness head. Registry checks use its serialized in-memory
lease state and do not add a witness round trip.

`prepare_account_root(registry, plan)` consumes the normal client and retains the
approved original plan before returning `RootRecovery`. The registry argument
must match the client's persisted association. Closing the recovery owner does
not reopen the old account. `RootRecovery.open` selects the same original
operation and parent directories after interruption. Its metadata access is a
separate internal capability, rejected wherever a live lease is required.

The restricted owner reports original registration/journal identity and recorded
peer confirmation, and can retain a verified freeze or original-plan noncommit.
It can finish an original partial pre-child association while the registry is
suspended, without enabling traffic. An interrupted existing-child migration is
reported separately as `root_adoption_pending`; this metadata owner does not
pretend that its uninspected child has completed binding. It exposes no signing, sending, renewal, child-session
factory or successor activation. It does not claim that a recorded child has run
or that any business message was delivered.

`tests/root_bound_client.py` checks the 24 association publication cuts, original
registry requirements, revocation and restricted parent recovery. Its recovery
preparation tests reuse a real prepared native target and signed policy, with a
separately approved test predecessor and fresh operation IDs; native terminal
receipts for the former plan cannot authorize this new plan. The public
`enrollment_session_checks.py --account-root-binding` path exercises real native
traffic, rekey, credential renewal, witnessed pending recovery, and registry close
after an actual send commit. Reopening the same active registry recovers the same
ciphertext. That cancellation case does not represent retirement of an old root.

## Migrate an existing child under the original registry

Use `client.begin_root_adoption(registry, now, transport=carrier)` after closing
borrowed children. It authenticates the original child and current permission
before retaining a `QPCLRT02` parent migration marker. The returned `RootAdoption`
has metadata, commit and exact pending-write recovery operations; it has no
traffic facade. Call `migration.commit(now, transport=carrier)` to receive the
normal `EnrollmentClient` after child, registration and configuration are bound.
Omit `transport` for a local-only child.

After an interruption, call `RootAdoption.open(path, client_id, wrapping_key,
registry)` using the same original parent directory, identity, key and registry,
then retry `commit`. Ordinary `EnrollmentClient.open` refuses an incomplete
migration. The source child directory, signing key, pending randomness, messages,
outbox and authority records are retained. An unbound child with pending G/R/P
coordination must finish that original operation before migration begins.

If a witnessed binding result is unknown and ordinary replay is no longer
authorized, `pending_write_request(now, transport=carrier)` returns the existing
purpose-26 proposal, complete metadata and device signature. Submit that original
request through the host's independently authorized pending-write recovery path;
then call `confirm_pending_write(proposal, metadata, now, transport=carrier)`.
Confirmation obtains a fresh witness Query. It cannot invent approval or replace
an unavailable original target. Retry `commit` after confirmation. A fully bound
child can finish parent metadata after credential expiry, but sending still
requires the original credential/policy renewal and current witness authority.

`enrollment_session_checks.py --account-root-adoption` checks real local and
witness peer traffic across this migration. `--root-adoption-cuts` executes 32
actual SIGKILL cuts across the four parent/child writes, and continues the same
operation and ciphertext after each. `--root-adoption-expiry` checks a local
child commit and witness replies lost before/after commit, fixture-clock expiry,
exact pending recovery, same-key renewal and subsequent real peer traffic.
These are process and protocol checks, not hardware power-loss evidence.

After registry preparation suspends the old root, `RootRecovery.inspect_child(now)`
authenticates the original required-witness journal without constructing a live
session or witness client. It returns the original subject and head, public
recovery metadata, any ordinary or typed G/R/P target, intent/control digests,
root-binding state and local coordination phase. `AppliedRecorded` and
`ClosedRecorded` retain a terminal outcome whose local cleanup is unfinished;
they are not new witness observations or permission to send. Unknown delivery
stays unknown. The reader neither replays nor repairs the original operation.

The same reader handles a parent migration interrupted before child binding,
after child binding, or with an unknown binding transaction. Only the original
authenticated pending migration permits reading an unbound child. Normal
Session factories still require a live lease; metadata access cannot substitute
for one. Closing the registry revokes even cached recovery methods. This reader
currently requires an existing required-witness child; it does not turn a missing
or local-only child into a witnessed one.

`enrollment_session_checks.py --root-child-inspection MODE` exercises ordinary
writes with replies lost before/after witness commit, G/R/P pending and retained
applied/closed control, partial parent migration, corruption refusals and owner
closure. The successor is a real separately prepared independent installation;
test-control command 45 supplies fresh native-signed peer materials rather than
backdating expired advertisements. These tests check unchanged original files,
zero witness requests during inspection and identical results after reopening.

`RootRecovery.bind_freeze(receipt, now=now)` now binds the complete signed native
freeze, then retains an authenticated `root-fence` in the original child and
registration. The original child must be named by the freeze; its frozen head
must equal the authenticated local head or a still-retained eligible target.
No ordinary or G/R/P operation is replayed to make the heads agree. An existing
child requires an explicit inspection time. Its encrypted head, intent and
authority control remain unchanged; the new file also binds their exact digests.
Normal registration/session constructors reject a retained fence under their
exclusive directory lease. Restricted original recovery authenticates it.

`retain_witness_retirement(receipt, now=now)` verifies the exact bound retirement,
retains the transferable receipt in child and parent, and only then commits the
registry's successor mapping. Lost returns reopen the same original root owner
and retry the same operation. Equivalent newly signed historical receipts keep
the first retained local bytes and do not increment the registry twice. This
returns a checkpoint, not a successor traffic owner. A closed root operation
cannot use this path to reopen or commit.

The test-control pipe verifies the actual independent target's full certificate,
roster, policy and prepared genesis before freezing or retiring it. The
`--root-retirement` scenarios preserve ordinary unknown results, G transactions
and partial parent migration. `--root-retirement-cuts` uses 28 fresh-process
SIGKILL boundaries across registry intent/head/cleanup and both fence files.
Malformed signatures and isolated corrupted fences/state are refused. These
checks do not establish physical power-loss durability.

`RootRecovery.activate_successor(target, now, transport=carrier)` consumes the
original prepared `EnrollmentClient`, or its interrupted `RootAdoption` owner,
and returns its root-bound client. It requires the committed current registry
mapping and authenticated retirement in each original store. It reconstructs
and compares the complete signed target with the approved plan, checks current
bootstrap inputs, and uses fresh witness admission while binding the target.
The supplied registry must remain alive for the returned client.

Before any child recovery write or witness advance, the target reader checks
the approved genesis. Only revision-one initial state and revision-two state
whose sole change is root binding qualify. Deterministic AES-SIV encoding lets
the reader reconstruct the exact original envelope from unchanged business
bytes; no additional origin file or reset is needed. A different valid initial
state under the same identity is rejected. Once business state advances, reopen
the normal client instead of calling initial successor activation again.

Activation emits no bootstrap flight and establishes no peer connection. The
`--root-successor` fixtures exercise current witness admission, reply loss and
parent publication interruption. The `peer`, `peer-credential`, `peer-before`
and `peer-after` variants additionally exercise the installed independent client
against the native persistent endpoint after an explicit test-controller
approval. The native side verifies the complete target and committed retirement,
checks current signed responder prekeys, and uses its original device journal.
It neither re-enrolls the same device nor replaces the prior store. Invalid
control inputs cannot select a peer context, and normal network traffic has no
access to this test-controller approval.

These variants perform authenticated handshake, retained peer confirmation,
bidirectional message consumption, exact replay, original-store reopening and
one rekey followed by new-epoch traffic. Lost send returns reconcile the exact
original reservation before completing its ciphertext; these are two distinct
durable steps. The control pipe is an interoperability harness, not a new root
distribution protocol or a physical/process-restart qualification.

Preparing another independently approved root suspends the selected successor
immediately. Its existing leases no longer grant traffic permission, and opening
the same client in a fresh process must retain that refusal. Restricted recovery
may still inspect the original child. Replaying a prior committed retirement
returns its historical checkpoint without restoring current permission or
changing the later preparation.

The `peer-root-revocation` variant exercises this boundary after the original
successor handshake, two-way traffic and rekey. It prepares an actual third-root
client, verifies refusal through a cached session and in a fresh process, and
checks that the original client files remain unchanged with no extra witness
requests. The existing historical retirement replay must leave the new registry
preparation intact. This covers local registry suspension after a completed
preparation; it does not commit the third root, freeze it at the remote witness,
or qualify interruption at every later-root publication boundary.

`peer-root-replacement` continues that same prepared third root through an actual
native witness freeze and retirement. The test-control extension requires the
exact committed first replacement in the original witness store, then binds the
later plan's previous account to that replacement's successor. The original
controller still rejects a different account; a truncated or changed predecessor
and a mismatched root chain are refused. This controller approval remains
separate from ordinary peer traffic and from real user-account authentication.

The installed original second-root owner retains child and parent retirement
before the registry selects revision three, then admits the already prepared
third-root client. Equivalent retirement and activation retries retain the
original journal and keys. Historical first-root retirement must not roll the
registry back. `--root-successor-later-cuts` exercises the 28 original registry
and fence publication boundaries across freeze binding and retirement, using
fresh processes and the same persisted inputs. A reserved fence staging slot is
checked against the exact bytes published to `root-fence`; unrelated orphan
files remain unchanged. These checks stop before third-root peer handshake and
traffic, and do not establish power-loss durability or compromise recovery.

The separate `peer-root-continuation` scenario then exercises that third-root
client against the same original native device journal. Native peer selection
requires both the exact committed replacement and the previous account from
its already authenticated peer context. It preserves the original controller
frame bound and native identity, wrapping keys, signer files and prior approval.
Prekeys in this non-restart fixture remain in memory; the signed selections are
checked against that original native key.

The scenario performs fresh mutual handshake and retained confirmation, both
message directions, exact replay, consumption, original-journal reopening and
one rekey with subsequent traffic. The previous peer controller and approval
cannot restore the second root, and an actual second-root ciphertext fails
authentication under the third-root context without preventing new traffic.
This checks an explicitly approved peer switch, not asynchronous global
revocation or a new root-distribution protocol.

The opt-in `--root-successor-process-restart peer-root-continuation` variant
persists the original sealed prekey reservation and restarts both successive
peers at ten actual process boundaries each. Before the third root is prepared,
its predecessor's advertisement is allowed to expire while the established
connection remains authorized. A fresh advertisement is still required for the
third-root handshake; replaying the expired signed advertisement is rejected.
On restart, the retained latest approval selects the original journal. Missing
later metadata fails closed instead of falling back to the previous controller.
Historical lineage is checked against the signed committed root transition,
without granting a live session from the predecessor's expired advertisement.
The previous controller remains retired in every resumed process. These are
explicit fixture-clock and process-termination tests, not physical power-loss
durability or general credential/policy expiry recovery.

`RootRecovery.transition_after_noncommit` consumes the restricted original owner
and transfers existing parent/child fences to a separately approved `Plan`.
Both plan closure and exact-decision closure require their own verified native
non-commit receipt. The next plan must retain the original freeze request and
authenticated subject snapshot. Neither closure nor transfer restores old-root
traffic permission. Business heads, pending intents, authority records and the
closed target remain unchanged; only registry history and the fences advance.

After an uncertain return, `RootRecovery.resume_transition` takes the same path,
keys, old operation, new approval, closure proof and freeze receipt. It reconciles
the registry first, validates both existing fences, then transfers parent before
child. During this explicit operation each fence may describe only the exact old
or next approved operation. Once complete, ordinary recovery uses only the next
operation. Missing, changed or retired fences cannot be reset by this interface.
The signed proof must be supplied again; stored descriptors alone are not a new
host approval. `replan-plan` and `replan-decision` exercise successor traffic after
handoff; `--root-transition-cuts` targets registry and both fence publications.

During a consuming handoff, closing the original recovery owner from a
persistence callback cancels subsequent registry and fence writes and withholds
the returned owner. The registry may also close after interrupted persistence;
reopen the original registry and resume with the same approvals and proofs.
Concurrent calls serialize; a nested handoff is refused. A successfully returned
recovery owner has its own lifetime. `--root-transition-cancellation` exercises
both owner and registry closure at the five publication phases, followed by
original-state recovery and native peer traffic.

`CommittedAdoption` combines the independently selected original `Plan`, an
independently selected winner `Decision`, original-plan noncommit and the winner's
actual signed retirement. Both signatures and both target expectations are
rechecked. Incoming receipts cannot choose the winner. The winner may use a
different freeze only when the original local plan had not bound a snapshot.
An original bound freeze must remain exact.

`RootRecovery.adopt_committed_winner` consumes the old recovery owner. It retains
the original closure, validates the prospective registry, records an adoption
intent, reconciles both original fences with the actual retirement, and only then
selects the winner. `resume_adoption` repeats these inputs on the original paths
after an uncertain result. Missing parent or child storage never creates a new
installation. When the original plan was already bound, missing fences are also
refused. An originally unbound plan can acquire its first fences only after the
winner's frozen subject matches the original authenticated child state.

The registry records this as adoption, not a local preparation. Query the actual
statement with `AccountAuthority.replacement`; `operation` refuses a winner that
never had a local plan. A previously inactive target seen only in closed attempts
may be adopted in the same application. An active root or a root belonging to
another application remains forbidden. Current credential, policy and witness
admission still apply when activating the selected client; historical retirement
does not extend permission.

Existing `QPRFAA01` images remain readable and encode identically. The first
adoption intent selects `QPRFAA02`, which retains explicit original-operation
links and distinguishes adoption intents from completed local selection. Older
readers reject that new format; downgrade is not supported. The compatibility
test uses an actual frozen old installed-writer capture. Neither format detects
rollback of the entire registry and its wrapping key.

`--root-winner-cuts` exercises 30 actual `SIGKILL` boundaries for each of
`bound-fresh` and `unbound-reuse`: original closure, adoption intent, both fence
publications and registry selection. The killed worker reconstructed the exact
host approvals from retained signed inputs; a separate existing parent process
then reopens the original state and performs native peer traffic and rekey.
`--root-winner-cancellation` covers owner/registry closure at the five publication
phases for both profiles, checks no subsequent writes or returned owner, and
resumes the original operation. These tests do not model power loss or arbitrary
thread schedules. The CI cohorts use separate Linux/macOS jobs with the same
60-minute limit and propagate every child failure.

`--root-winner-adoption bound-reuse-continue` continues the adopted root through
another independently approved replacement. The same registry retains the
closed original plan, the adopted decision and the subsequent local plan without
conflating their authority. Both selected roots exchange actual native peer
traffic and rekey. Replaying the old adoption and expired historical retirement
returns its original revision without changing the newer selection or restoring
its permission, including after reopening the registry.
`bound-reuse-restart` additionally kills and executes the native peer at ten
boundaries for each selected root while retaining its original journal, witness,
keys and sealed prekeys. These twenty process restarts remain distinct from
power-loss qualification and from the independent parent's publication cuts.

Still separate: full successor cancellation coverage,
cross-platform root lifecycle
qualification, device qualification
and post-compromise recovery analysis. Do not use these component checks as proof
that the complete root-replacement lifecycle is ready.

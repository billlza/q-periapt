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

Still separate: transferable retirement retention before successor selection,
reconciliation with a signed complete freeze, live successor admission,
independently approved adoption of another committed winner, device qualification
and post-compromise recovery analysis. Do not use these component checks as proof
that the complete root-replacement lifecycle is ready.

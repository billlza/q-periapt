# Same-key credential renewal and original-session recovery

Status: unpublished native candidate, `qperiapt-credential-renewal/1`. This extends
one device credential under the same account root, full ML-DSA-65/P-256 key,
device ID, generation, family and exact protocol policy. It preserves original
registration and storage. Root, key, generation, policy and witness replacement
are separate lifecycle transitions. Credential renewal does not establish
post-compromise secrecy or turn retained randomness into fresh entropy.

## Authority input

The account service independently authenticates and authorizes renewal, serializes
its complete roster and durably deduplicates the caller's `CredentialRenewalId`.
`RootSigningKey::issue_credential_renewal` signs the original, predecessor and
successor credentials, the exact predecessor/target roster checkpoints, full key
commitment and exact protocol policy. It is not an account login or issuance server.
Both signature components remain required. Validity keeps the original start and
strictly extends the predecessor's end; historical predecessor verification must
have a real overlapping interval. Verification does not revive current membership.

The client verifies the complete grant with `VerifiedCredentialRenewal::verify`,
an independently obtained target `AccountPin`, the exact expected policy digest
and trusted time. A pin constructed from the incoming grant is not independent
trust. Retain the original operation, exact signed bytes and statement digest for
reconciliation. The statement digest excludes randomized signatures.

A grant explicitly authorizes retained established sessions of this full identity
and exact policy, including intermediate credentials in the same original lineage.
The journal still has to find the exact original live session/context/role. Key
equality alone is not continuation permission, and a current grant does not create
a session from an old transcript.

## Local enrollment workflow

Close the existing `EnrolledDevice` before reopening its original `DeviceEnrollment`.
Keep the original `EnrollmentIntent`, paths, wrapping key, signer, registration
request and journal/archive identities. Do not provision replacement files.

1. Independently verify the new root grant and retain its operation identity.
2. `stage_credential_renewal(grant, operation, policy, now)` persists its exact intent.
3. `activate(policy, now, anchor)` reconciles the original journal, persists/readbacks
   enrollment completion, acknowledges the journal receipt, then checks current
   credential, roster and policy before returning an `EnrolledDevice`.
4. Use the returned current credential and original signer for new public bundles.
   Admit them through `service.admit_peer` before ordinary protocol operations.

The sequence above is for an explicit local-only policy. A required-witness
policy uses the separate native coordinator below; no failure selects local
fallback. The C/Swift/Kotlin facade still refuses required-witness staging before
writing intent until it exposes the complete proposal/approval/coordinator path.
Its historical status codecs include Closed without claiming that integration.
Peer renewal cannot be used to renew the owning local device.

### Required-witness original enrollment coordinator

Authority-only adoption would permit the witness to adopt `C0 -> C1` while the
original journal remains at C0. If C1 then expires, local NoCommit cannot prove
remote NoCommit. The joint construction binds independent authority adoption to
the original exact sealed head transition, with a permanent successor-version
floor at the witness. Do not use the older authority-only transition to compose
this device workflow.

1. Stage the verified grant through the original enrollment. Use
   `credential_renewal_anchor_client` to retain its protected signer even after C0
   expiry; that carrier grants no current traffic permission.
2. `prepare_witnessed_credential_renewal` reserves the exact target and durably
   reads back its complete proposal in the enrollment configuration. Retrying an
   unknown preparation inspects the original intent; it never reseals the target.
3. The independently trusted witness operator approves that proposal together
   with the verified root grant through `AnchorStore::prepare_credential_renewal`.
   Neither a device-supplied root nor an incoming proposal supplies this trust.
4. Explicit `commit_witnessed_credential_renewal` requires a live target before
   sending Commit. `close_witnessed_credential_renewal` sends exact Close;
   a competing Applied result remains Committed. Reconciliation sends only Status.
5. The coordinator installs only an observed Applied target, then persists and
   reads back terminal configuration. Only then does it send the exact ACK,
   remove/read back the exact local pending row, and retire coordination. Each
   ambiguous result retains the original operation for reopening.
6. Historical status returns no device owner. `activate` requires coordination
   to be complete, live local admission and an exact fresh witness AdmitAuthority.

Conditional QPENST04 retains the complete proposal while coordinating, Applied or
Closed terminal disposition, bounded Closed history and the permanent signed
successor-version floor. Existing local-only QPENST01/02/03 bytes are unchanged.
Closed can precede credential expiry: it leaves the preceding C0/C1 admission
unchanged and must not be reported as ExpiredUncommitted. The historical completed
operation remains distinguishable from a later closed operation on exact retry.

No extra durable ACK phase is required. Retained exact Terminal permits repeat
ACK after expiry and after an unknown pending deletion. With such a Terminal, a
fresh signed Unavailable can also complete pure local cleanup: under the existing
independent monotonic-witness assumption, its terminal slot could only have been
removed by ACK, and later approved work may have overwritten last-ACK. Without
Terminal, Unavailable remains unresolved. Cleanup compares the exact terminal
image AND the full pending proposal/wire, so an old configuration cannot erase a
different pending target. It never changes the image or supplies current authority.

The local completion receipt remains inside the exact target. The next original
renewal compares it with authenticated enrollment completion and replaces it
inside its own newly sealed target; cleanup does not create an extra Advance.

The journal preparation stage now has a durable renewal-intent discriminator.
`prepare_local_credential_renewal` authenticates and reserves one sealed target,
reads back its exact wire, and closes the journal on success or failure. It does
not send Advance or change the local image or witness authority. Ordinary pending
writes retain `QPWINT01`; renewal preparations use `QPWINT02`, binding the original
operation and statement to the sealed target's verified root grant and receipt.
Ordinary `open_anchored`, cleanup recovery and ordinary local apply refuse this
intent before dispatch (`Suspended` at the old image, `Conflict` at an already
installed target with retained intent). This prevents a restart before witness preparation
from advancing the head without adopting the target authority.

`inspect_credential_renewal_preparation` authenticates the existing protected
image, independent journal identity, original credential and policy binding. It
returns the original 296-byte `QPCRNP01` proposal: witness binding, immutable
subject, operation/statement and exact adjacent heads. It remains available after
expiry or policy closure and never reseals the target. The metadata is not a
witness receipt, current authority or permission to release an operational owner.
`None` describes only absence of a local intent; it is never witness NoCommit.
Pending bytes must remain intact until the dedicated joint transaction protocol
can establish a terminal outcome; this preparation API alone is not a usable
end-to-end enrollment renewal path.

`recover_credential_renewal` performs the dedicated local half under the original
journal lease. It checks the complete retained proposal, original identity,
policy/witness binding and client signer before sending a fresh CredentialStatus.
Only a typed Applied observation installs the already-sealed target. The write
transaction rechecks the exact pending bytes and expected image; it changes only
the image and keeps QPWINT02. Authenticated readback precedes success. On an exact
retry, the target and original intent are read without another commit. Inspection
accepts either original image or byte-identical target with that same intent;
the ordinary QPWINT01 loader is unchanged.

Prepared/Closed/Unavailable are read-only historical observations. A local target
with Prepared or Closed is an explicit conflict. Unavailable never undoes a
target or establishes NoCommit. This method sends no Commit, Close, ACK or ordinary
Advance and returns no operational owner, even while credential/policy admission
is live. After expiry or policy closure it can still reconcile historical Applied.
The original enrollment coordinator retains an authenticated exact terminal
before witness ACK and local pending removal, as described above.

Fresh, exact preparation and
closure observations are also required: Query confirms only the journal head;
AdmitAuthority returning Denied is not evidence of an unapplied renewal.

Cancellation/expiry closure must be mutually exclusive with applying the exact
transition. A closed preparation cannot later become an ordinary Advance, and
late control-plane retries cannot recreate a pruned preparation. The bounded
retention/floor and acknowledgement contract is implemented at the witness;
absence of a retained record cannot become NoCommit. Device pending bytes may
be removed only after its corresponding terminal outcome is durably retained.

Native tests cover exact preparation before witness adoption, authenticated marker
changes, scope refusals, all four before/after cuts at the two measured reservation
syncs, policy closure after persistence, and an actual process kill before return.
They check unchanged original image/authority, refusal without ordinary dispatch,
and byte-identical pending recovery. Database drop performs additional syncs after
the durable reservation; the fault census above describes the reservation commit.

Original enrollment tests now exercise two successive Applied targets, early
Closed preserving C0/C1, exact retry of T1 after T2 closes, lost Commit/Status/ACK
replies, expired/policy-closed recovery, old-terminal/client rollback, and the
last-ACK overwritten by later approved work. The configuration path measures four
commit syncs for each terminal outcome (16 before/after fault cuts); exact pending
retirement measures two syncs per outcome (eight cuts), and absent-pending retry
performs no new commit. Eight actual process kills cover observation/local apply,
terminal configuration, pending retirement and coordination retirement for both
Applied and Closed. These are native candidate tests, not independent protocol
implementation, installed foreign, physical-device or release qualification.

The native witness implements exact prepare/apply/close/status, a permanent
signed-successor-version floor and bounded terminal acknowledgement; see
[the joint witness contract](ANCHOR_WITNESS.md#joint-credential-renewal-and-bounded-terminal-retention).
Independent operator approval transport, installed foreign coordination, current
and minimum physical platforms, and the full security/performance/release gates
remain separate work.

`credential_renewal_status` reports historical progress, never traffic permission:

| Status | Meaning and next step |
| --- | --- |
| `Absent` | No renewal intent has been retained. |
| `Pending` | Intent is durable; journal commit may already have happened. Use the original local activation/expiry path or the required-witness coordinator, according to the original policy. |
| `Committed` | Exact journal completion was observed and enrollment completion persisted. Current expiry or revocation can still deny every operational owner. |
| `ExpiredUncommitted` | The expired target was excluded by authenticated monotonic predecessor history and abandonment persisted. A separate root grant may now be staged from the actual current predecessor. |
| `Closed` | The independent witness closed this exact target without applying it. The preceding credential may still be live; the rejected successor version is permanently retired. |

An I/O error is not proof of non-commit. Reopen original configuration and use the
same operation. A completion receipt survives later roster/generation updates until
its exact enrollment readback is durable. A completed-but-unacknowledged T1 is
pruned only under the exact prior-completion rule; a pending T2's own receipt is
never mistaken for T1.

## A target expires while Pending

For local-only policy, call `reconcile_expired_credential_renewal(operation, statement, policy, now)` on the
original enrollment. It holds the original configuration and journal leases through
classification, config persistence and authenticated readback; it returns no service.
Required-witness policy uses `reconcile_witnessed_credential_renewal` instead.

An exact journal receipt is reconciled as `Committed`, including after expiry,
revocation or generation advancement. Without that receipt, absence alone proves
nothing. The current authenticated history must still contain the exact predecessor
generation and credential, with the same authority and original lineage. History
never restores an older credential at that generation and root renewal strictly
extends validity, so later roster-only updates can preserve a NoCommit proof.
Successor or higher-generation history, older/forked heads and conflicting receipts
remain unresolved errors. Restoring an older Pending configuration after a target
was installed cannot manufacture `ExpiredUncommitted`.

Only an actually expired target may be abandoned. The durable terminal records the
operation, statement, observed head and observation time. A monotonic trusted-time
floor prevents backdating to reactivate an abandoned target. The last abandonment
is retained until another abandonment or a later successful completion replaces it;
the floor persists thereafter. Older unavailable terminal outcomes are rejected,
not inferred. Applications retaining a longer audit history must keep their results.

A separate new grant still has to name the journal's exact current predecessor.
Historical NoCommit classification does not re-add a revoked device or loosen new
commit admission. The local-only profile does not detect whole-database rollback.

## Peer renewal, fresh operations and old sessions

`service.admit_peer_credential_renewal` installs the independent peer grant and
roster in one original journal transaction. The same current target is only exact
operation/statement readback. A different current head, observed revocation or
conflicting operation fails. It cannot mutate the local device's credential.

Fresh current-credential bundles retain their actual public credentials and
transcript bytes. `service.admit_peer` privately binds the local current credential
to the original journal/role/storage owner, after checking the exact current root
grant and policy. Both peer preview and private mapping use one authenticated image
and one final witness release fence. Every new operation rechecks current membership
and grant; a cached context is not authority after another successor or revocation.
No public API accepts a caller-selected replacement storage-owner hash.

For an established session, use `service.reopen_peer_bundle` with its original
bundle, independent pins, original role and exact session ID. The service verifies
historical public material, finds the live original Messages record and retained
archive, resolves current credential authority from its journal, and returns a
private view over the unchanged transcript. Original ciphertext, ACK, rekey and
session identities remain exact. Ordinary `bundle.request_reopen` retains its
current-credential requirements; it is not the expired-credential continuation path.
A retained view cannot start another bootstrap or query arbitrary bootstrap status.
Its message status and cleanup remain scoped to its exact journal/session/role.

Prekey IDs, sealed scopes, recovery material and one-time tombstones remain under
the original journal. Existing Available/Reserved material can only be recovered
with its exact request, kind, validity and SDK binding. Credential renewal neither
extends a leaf's lifetime nor replaces its retained randomness. Leaf release checks
live policy after persistence and witness admission. The owning service's
`prekey_status`/`retire_prekey` can inspect or retire original inventory after expiry,
policy close or later generation changes; these calls release no new key or traffic
permission and cannot reactivate a consumed or retired ID.

## Encoding and compatibility

The signed statement is 369 bytes, tagged `QPCRNW01`, with signature purpose **15**.
`QPRNB001` contains six nonempty u16-length fields: signed statement envelope,
original/predecessor/successor credential and predecessor/successor roster. Each
field is at most 8192 bytes and the entire input is bounded by 65,536 bytes.

Without renewal, existing `QPENST01` (24 KiB bound) and `QPRHST01` bytes remain
unchanged. `QPENST02` preserves original credential/roster scope plus bounded pending
wire and last completion. `QPENST03` additionally records the time floor and at most
one last expired-uncommitted terminal. Both extended enrollment images remain under
128 KiB. `QPRHST02` retains at most one current grant per device; `QPRHST03` additionally
holds one 200-byte unacknowledged local completion, independent of later membership.
The existing account/history/image bounds still apply. The outer native journal
remains v21; older readers refuse unknown extended records rather than reset them.
After using these records, downgrading to a reader that lacks them is unsupported.

Bootstrap/message/KEM bytes, existing purposes, product ABI 2 and implicit rejection
are unchanged by this native addition. The separate candidate owner ABI and language
packages need their own integration/qualification; this source document does not
claim they already expose renewal or that the candidate protocol is frozen.

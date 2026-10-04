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

The local renewal path currently supports the explicit local-only policy. A required
witness policy returns `AnchorRequired`: the independent witness must gain its own
credential/subject-adoption transaction before that path can be enabled. No failure
selects a local fallback. Peer renewal preserves the owning service's existing
policy/witness checks and cannot be used to renew its local device.

`credential_renewal_status` reports historical progress, never traffic permission:

| Status | Meaning and next step |
| --- | --- |
| `Absent` | No renewal intent has been retained. |
| `Pending` | Intent is durable; journal commit may already have happened. Retry original activation or explicit expired-intent reconciliation. |
| `Committed` | Exact journal completion was observed and enrollment completion persisted. Current expiry or revocation can still deny every operational owner. |
| `ExpiredUncommitted` | The expired target was excluded by authenticated monotonic predecessor history and abandonment persisted. A separate root grant may now be staged from the actual current predecessor. |

An I/O error is not proof of non-commit. Reopen original configuration and use the
same operation. A completion receipt survives later roster/generation updates until
its exact enrollment readback is durable. A completed-but-unacknowledged T1 is
pruned only under the exact prior-completion rule; a pending T2's own receipt is
never mistaken for T1.

## A target expires while Pending

Call `reconcile_expired_credential_renewal(operation, statement, policy, now)` on the
original enrollment. It holds the original configuration and journal leases through
classification, config persistence and authenticated readback; it returns no service.

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

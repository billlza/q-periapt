# Host-authorized enrollment transaction

Status: native reference-host transaction and its same-origin HTTP adapter are
implemented, with browser controls retaining the original host-operation identities.
Complete real browser/installed-client qualification, revocation and complete
root/device replacement are **not connected or qualified
yet**. The remaining requirements below stay open where
the observations do not cover them. This does not define a new cryptographic
protocol, require Passkeys in the SDK, or freeze a product ABI.

## Existing behavior and the missing boundary

The native [`DeviceEnrollment`](../continuity-identity-candidate/src/enrollment.rs)
and independent Python
[`Registration`](../continuity-openssl-peer/REGISTRATION.md) retain the original
device signer and signed request before releasing it. Both can reopen original
client state. `VerifiedEnrollmentRequest::verify` checks possession of both
device signing keys against an independently supplied `EnrollmentIntent`.

`RootSigningKey::issue_enrollment` and `issue_roster` are intentionally stateless
signing primitives. They do not promise durable deduplication or byte-identical
responses. Re-signing the same credential body can produce different signatures
without changing that credential's semantic identity. This is not a defect in
those primitives. A network issuer needs an additional transaction before it
can promise recovery of the exact result of an approved operation.

The host must decide who may enroll a device. For the optional reference
application, a verified Passkey session identifies its existing application
account. An embedding application can instead use its existing login or
independently administered provisioning. Neither a request signature, an
incoming application-account ID nor a caller-supplied root constitutes that
authorization.

The SDK should supply bounded parsing, exact cryptographic binding, controlled
signers and recovery semantics. The host owns the membership decision and its
transactional persistence. No WebAuthn, HTTP or account signup dependency belongs
in the cryptographic core.

## One authoritative decision

The reference host's application-account database is the source of its enrollment
authorization. Store its selected root revision, current complete membership,
pending approvals and issued results in the same transaction domain. Do not
write a separate "success" file after returning a credential, or maintain two
independently advancing issuer roster databases.

`AccountAuthorityStore` is already a retained association and root-replacement
coordinator for SDK consumers. Its initial `associate` accepts an independently
verified device; it cannot establish the issuer's first authorized root from a
login or from a self-presented request. Reuse its established consumer lifecycle
where appropriate, without calling it an account authentication service or
silently bypassing its initial verification.

Private root material remains in the existing role-bound `RootSigningKey`
storage. The host retains the original `SigningKeyId`, exact key-file locator
and wrapping-key association before provisioning. It records the public key
from that original signer before releasing enrollment invitations. File creation
and a database transaction are not atomic together. First-use therefore needs
a retained preparation record and explicit reconciliation of the original
file; an open or creation error must never choose a new identity or call `init`.
Do not put raw root secrets into the account row or return them through HTTP.

An SDK-facing issuer adapter must expose these operations with no dependency on
Passkey types. The reference account service supplies the authenticated account
and authorization result internally. JSON returned by the identity endpoint is
display data, not a reusable authorization capability.

## Original operation binding

The caller first retains a random request correlation ID. Invitation creation
atomically indexes `(authenticated application account, request ID)` to the
host-generated operation. This makes a lost first response recoverable before
the caller has learned the host operation ID. A retry returns the original
invitation without extending its deadline or granting new authority. A closed
operation stays closed. The correlation ID is not authentication.

Before asking a device to generate its request, the host retains a bounded
enrollment invitation with the approved root and device description. Retaining
an invitation does not itself approve an unknown device key. Approval of the
actual request binds all of the following:

- A host-generated operation ID, authenticated application-account ID and the
  host's current root/authorization revision.
- The exact original request bytes, signing-owner identity and
  both device public-key components.
- The exact independently selected device ID, generation, policy family and
  finite credential validity interval.
- The predecessor roster checkpoint and the approved complete membership
  change, including the intended finite successor-roster validity interval.
- The host authorization decision and its finite completion deadline.

No field is taken as trusted merely because it appears inside a signed request.
`VerifiedEnrollmentRequest::verify` compares the request to the separately
approved intent. The original operation ID and the account/root-scoped signing
identity also have uniqueness constraints: a second operation cannot silently
enroll the same original key again or replace another device's generation.

A retry with the same ID and different request bytes or approval parameters is
a conflict. Do not normalize it into the saved operation. If a device wants a
new operation, it must explicitly resolve the old one and obtain new approval;
an HTTP timeout does not establish that the old operation did not commit.

## Commit and response release

| Durable state | Meaning | Allowed next action |
| --- | --- | --- |
| Invited | Independent intent retained; no device key approved | Receive a bounded request and obtain explicit approval |
| Approved | Exact request and complete change approved; no result released | Recheck current authorization and commit that original change |
| Issued | Exact credential, complete roster and result retained atomically | Recover the same result; separately observe current authority |
| Closed | This unissued operation was explicitly cancelled or invalidated | Return its terminal disposition; never revive it implicitly |
| Reapproved | The old decision is closed with a retained link to an explicitly approved successor | Query that exact successor; never silently retarget the old operation |

Schema 3 adds explicit pre-issuance reapproval. Its separate upgrade preserves
all schema-2 rows and private files; schema-2 cancelled records cannot recover
request bodies they never retained. Reapproval accepts only Invited or Approved
operations. For Approved, the incoming bytes must equal the original approval;
for Invited, a fresh proof against the original independently selected device
intent is required. Root, application, family, device ID/generation and credential
interval are unchanged. The successor uses exactly the key proved by the retained
request; an Approved source also preserves its previously approved key. An
unapproved invitation alone never established a device-key identity. The caller independently approves the
current complete roster checkpoint and retains a fresh request correlation ID.

One transaction closes the old decision, records its prior phase and exact
request, advances its signer reservation, and publishes the approved successor
and correlation index. There is no intermediate state permitting both decisions
to issue. Retries recover the original successor even if it subsequently became
historical; they do not extend deadlines, change the selected roster or follow a
later transition automatically. Explicit cancellation targets the successor;
cancelling the old history cannot silently cancel a newer decision. Issued or
explicitly cancelled operations are not reapproval sources.

The new five-minute host-approval deadline is capped by the original credential
end time. Reapproval can refresh an expired host decision while the credential
interval is still current; it cannot extend expired credential validity. This
distinction preserves the native SDK's immutable original enrollment request.
An expired unissued credential requires a separate authorized transition, still
outside this method. Exact request bytes are retained and compared directly;
no parallel digest field is needed for this binding.

The issuer transaction rechecks the current application/root revision,
authorization, approval deadline and predecessor roster. It verifies the exact
request, constructs the credential and full successor roster, and commits
membership, roster version, operation state and exact response bytes together.
Only a successful durable commit permits response release. The roster version
is assigned from the retained predecessor by the issuer; it is not chosen by
the request. Overflow and capacity exhaustion are explicit errors.

Signing may happen before the commit, but no signed material is externally
released then. If the transaction aborts, the old roster remains current. If a
storage error leaves the commit outcome unknown, the owner stops issuing and
requires reopening the same database. It cannot return success, erase the
pending operation, recreate the store or sign a replacement response to hide
the uncertainty.

A missing or rejected original root key is a separate issuer-scoped error.
It refuses that issuer's signing and never generates replacement material, but
does not disable unrelated account authentication or another issuer. Database
commit uncertainty still disables the shared store owner until explicit reopen.
The local regression first reproduced the overly broad store shutdown, then
verified this isolation while retaining the failed key's original state.

After a restart, the client authenticates again as the same application account
and queries the original operation. A new session is allowed; an old cookie is
not. An Approved operation must recheck current authorization before its first
commit. An Issued operation returns its original committed bytes without
performing another membership change. The host must not infer the requester
from a device-key proof or a submitted account name during either path.

Status responses distinguish the original issuance result from the current
root and roster. Another enrollment or revocation may have advanced the roster
since that result was issued. Historical success cannot select today's trusted
checkpoint or restore a revoked device. Root replacement fences pending grants
against the old revision; it never retargets them to the successor root.

Client acceptance still verifies the credential, exact original signer and
description, current independently obtained root/roster expectations, live
policy and trusted time through the existing enrollment APIs. A response cannot
provide its own sole trust anchor. An expired historical response remains
evidence of an operation, not permission to activate a device.

The implementation must bound body sizes, pending approvals, active membership
and retained operations. It must not recover capacity by silently expiring an
unresolved operation's identity. Terminal-history retirement needs an explicit
contract before records can be discarded. HTTP cancellation or disconnection
does not imply a running database commit was cancelled.

## Integration order and required observations

The issuer adapter and database transaction now precede browser integration.
Keep transaction and recovery code separate from the HTTP handlers
and Passkey ceremony state. Use the existing private-file backend and durability
settings. Extending the real account database needs explicit schema admission
and a tested upgrade preserving its existing accounts; do not reset the user's
database to obtain a convenient new schema.

The first end-to-end scenario must use a fresh device identity from an installed
consumer, an explicitly provisioned persistent root, real current time and an
independently delivered trust configuration. It must pass through actual host
authorization and the issuer transaction before client acceptance. Existing
fixture-based registration remains separate evidence.

Required fault and authorization observations include:

- Anonymous, wrong-account and expired-session operations fail without changing
  membership. A valid device signature alone does not grant enrollment.
- A substituted request, device key, generation, policy family, deadline, root
  revision or predecessor under the same operation ID fails as a conflict.
- Crash before commit leaves the original request recoverable with no released
  result. Crash after commit and loss of the response recover byte-identical
  credential/roster/result data and do not advance the roster twice.
- Concurrent approvals cannot overwrite each other's complete rosters. The
  losing predecessor is a visible conflict requiring a new explicit decision.
- A changed authorization or pending root replacement blocks an unissued old
  approval. Recovery of an already issued result never revives its authority.
- A second authorized device joins the same account; the earlier device sees
  the complete updated roster. Revocation and root/device replacement exercise
  the existing original-operation lifecycle instead of creating new state.
- Full/malformed/missing storage and failed synchronization retain the original
  evidence and fail explicitly. Process kill evidence is not a claim about
  hardware power-loss durability.

Schema 4 additionally retains explicit same-key credential extensions in a
bounded table (512 results per database), keyed by account and caller-retained
request identity. Every request selects the original enrollment, exact prior
issuance, current roster predecessor and finite target expiry. A fresh extension
requires current membership of that exact prior certificate; historical signed
issuance authenticates an expired predecessor without treating it as live
permission. The current roster may have a disjoint validity interval, so the
historical verifier uses the predecessor issuance's own signed roster. The
account's current authoritative member set is checked separately.

The root's existing credential-extension primitive preserves the complete device
key, generation, family and validity start. The host replaces the member and
signed roster in the same immediate two-phase transaction as the exact response.
No old operation is rewritten. The new schema is enabled explicitly; old readers
refuse it. Exact retries return retained history even after expiry or suspension;
they do not grant current use. This operation does not issue G, alter protocol
policy or update a client journal. The independent client has a separate
pre-child adoption API; the native enrollment equivalent, browser control and
complete live host/peer recovery path remain open.

The local Rust tests currently cover exact request binding, two-device roster
issuance, conflicting predecessors, original-key reapproval, suspension,
original-key loss, explicit schema upgrades and fourteen actual process kills
across six original commit/provisioning flows. Credential extension adds four
SIGKILL cuts around schema-4 admission and atomic certificate/roster/result
commit. Its HTTP check loses a response body and reopens the same server state.
An explicit historical-signature fixture checks an expired credential with a
disjoint current roster; it is not an elapsed-time production experiment.
The tests use software host authentication and native SDK request/signing
owners. They do not yet cover installed clients, enrollment over the actual
network, deployed host authorization, device revocation/replacement, injected
filesystem synchronization failures or hardware power loss. Real login and the
earlier account-only CI are not evidence for those operations. Deployment, installed
independent endpoints, subsequent traffic/rekey/reconnect, retained-state
security analysis and resource measurements remain part of the full goal.

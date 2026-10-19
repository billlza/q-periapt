# Host-authorized enrollment transaction

Status: implementation contract for the independent reference consumer. The
account application currently implements login and account persistence only.
The transaction below, its transport and its installed-client qualification are
**not implemented or qualified yet**. It does not define a new cryptographic
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

Before asking a device to generate its request, the host retains a bounded
enrollment invitation with the approved root and device description. Retaining
an invitation does not itself approve an unknown device key. Approval of the
actual request binds all of the following:

- A host-generated operation ID, authenticated application-account ID and the
  host's current root/authorization revision.
- The original request bytes, their exact digest, signing-owner identity and
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

Implement the issuer adapter and its database transaction before adding browser
controls. Keep transaction and recovery code separate from the HTTP handlers
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

These are acceptance requirements, not reported test passes. Real login and the
current software-authenticator CI do not satisfy them. Deployment, installed
independent endpoints, subsequent traffic/rekey/reconnect, retained-state
security analysis and resource measurements remain part of the full goal.

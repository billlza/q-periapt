# Candidate account-root preparation and enrollment

The reference host can prepare a separate candidate account root, explicitly
approve its original device request, and issue that device's credential and roster
under the existing application's authenticated account. These operations prepare
the target of a root replacement. They do not select it as the current issuer,
suspend the old issuer or freeze a witness. Complete authenticated root cutover
and client authority selection remain integration requirements.

An administrator explicitly calls `Store::enable_root_preparations` on an existing
schema-7 account store. This atomic schema-8 upgrade adds the preparation and
request-correlation tables. It preserves the account database, Passkeys, enrollment
history and original key files. Opening the database does not upgrade it. Older
readers that do not admit schema 8 refuse it; they must not recreate the database.
The separate `Store::enable_root_successors` schema-8-to-9 upgrade admits a
candidate's enrollment and its retained link to the ordinary operation ledger.
Both migrations are explicit administrative CLI commands:

```text
q-periapt-continuity-reference-app enable-root-preparations /absolute/original/accounts.redb http://localhost:8087
q-periapt-continuity-reference-app enable-root-successors /absolute/original/accounts.redb http://localhost:8087
```

Use the original database and relying-party origin. The server must have released
its store before an administrative upgrade. Existing schema-8 candidates remain
the same objects after upgrade; old readers that do not admit schema 9 refuse it.

## Retain one request before first use

After authenticating through the host application, the caller selects its current
`RootInfo` and retains a `root_preparation::Request` containing:

- A nonzero 32-byte `request_id`, retained before the first attempt.
- The selected predecessor's exact `revision` and `account`.

`Service::prepare_account_root(token, &request)` durably records the operation
and candidate signing identity before creating its files. It returns a
`Preparation` with the original request, stable operation ID and status. Repeating
the same request reconciles the original candidate. Reusing the correlation with
different predecessor fields is refused. A new request must select the current
issuer; a retained request continues to identify its original historical operation.

The host account login authorizes this stage independently of the old root's
private key. Loss of that private key therefore does not block preparing a new
candidate. Existing old-root suspension remains unchanged. `Prepared` describes
the candidate public key and prospective next revision, not a selected authority.
Multiple preparations may describe the same prospective revision; a future
cutover must independently approve one candidate and atomically compare and change
the current application-account association.

## Enroll the selected candidate's target

Retain a `SuccessorRequest` with the candidate's preparation operation and a new
nonzero `request_id`. `Service::invite_root_successor` atomically links one original
invitation to that candidate. The existing `approve_enrollment` and
`issue_enrollment` calls then verify the exact native device proof and commit the
candidate roster together with the original signed response. The ordinary current
root, its roster and its suspension do not change. Losing an HTTP reply does not
select another candidate, device identity or invitation.

Each candidate admits one successor enrollment lineage. A second independent
invitation is refused. Explicit `reapprove_enrollment` can move its original
request and signer reservation to a retained successor approval while the original
credential interval remains valid; candidate linkage and both operation states
commit together. An explicitly cancelled enrollment is terminal. Same-key
`extend_enrollment_credential` updates the candidate's own certificate/roster and
retains exact extension history. The existing current-root checks on retained
session grants, policy approvals and device replacement continue to reject an
unselected candidate.

`Service::root_successor(token, preparation)` reads the retained latest invitation
link. Its `enrollment: null` means no invitation has ever been linked. An absent,
corrupt or foreign-account record is an error. This lookup also recovers the
latest operation ID if another authorized caller reapproved an invitation before
its original reply arrived. It returns historical linkage for closed or issued
operations; query ordinary enrollment status before choosing the next action.

The HTTP routes below inherit the account router's login, Origin, body and worker
bounds. The browser UI does not yet expose these controls.

| POST route | Request |
| --- | --- |
| `/api/enrollment/root-candidate/prepare` | Original `Request` with predecessor and correlation |
| `/api/enrollment/root-candidate/status` | Original preparation `operation` |
| `/api/enrollment/root-candidate/close` | Original preparation `operation` |
| `/api/enrollment/root-candidate/invite` | Original `SuccessorRequest` |
| `/api/enrollment/root-candidate/successor` | Original preparation `operation` |

Use the existing enrollment approval, issue, status, reapproval and extension
routes with the returned invitation. `/status` still returns a **separate current
root observation**, which remains the old root during preparation. Candidate
issuance is verified against its independently selected public key and its own
signed roster; it does not turn that current-root observation into candidate
authorization. [Account-root cutover](ACCOUNT_ROOT_CUTOVER.md) coordinates host
selection with the original native registry and witness. Client-owner fencing
and independent installed-controller integration remain separate.

## Recovery, observation and closure

`Service::account_root_preparation(token, operation)` reads retained public
history. It can report `Prepared` even if the candidate's private files have since
become unavailable. This observation is not proof of current signing capability.
Retrying `prepare_account_root` reopens the original signer and reports a missing,
corrupt or mismatched admitted key as `IssuerUnavailable`; it does not replace it.

`Service::close_account_root_preparation(token, operation)` permanently closes
that candidate operation. An exact retry returns the same closed state. The
preparation cannot then be resumed. Closure atomically closes its latest unissued
enrollment, including a reapproved successor. Issued enrollment and extension
retries remain exact historical results; new issuance and extension are refused.
Closure preserves private files and current issuer state; it is neither key erasure
nor revocation of a certificate through an independently selected external trust
channel. All service calls authenticate before performing work and again
before releasing a result. After restart, log in again to the original account.

The preparation ledger is bounded to 512 retained operations per host store,
including closed entries. Candidate invitations also use the existing 512-operation
enrollment ledger and eight-pending-invitations-per-account bound. Capacity
exhaustion is an explicit failure. Do not
reset the database or discard old operation history to make a request succeed.

## Validation boundary

The tests use real WebAuthn signatures from a software authenticator, native root
signers and real storage. They cover request/account isolation, old-key loss,
candidate-key loss, stable original results, explicit upgrade and permanent
closure. Nine process-kill cuts cover schema publication, preparation retention,
key-file reconciliation and closure. The common root-key reconciler also serves
initial enrollment and retains its existing interruption tests.
Twelve additional process-kill cuts cover schema 9, candidate invitation,
issuance, reapproval, extension and linked closure. Actual loopback HTTP tests use
software Passkeys, lose three response bodies, restart the server and reauthenticate
to recover the original candidate, invitation and signed issuance. A native
device accepts and extends its candidate credential with the original signing
files and installation identity; this is isolated target preparation, not a
completed application-account cutover.

These tests do not qualify a full root replacement or post-compromise recovery.
The [application-account cutover](ACCOUNT_ROOT_CUTOVER.md) has separate host/native
and HTTP regressions. Browser controls and installed independent-client
coordination must still connect original session-owner fencing without transferring
old session secrets or inferring unresolved delivery outcomes.

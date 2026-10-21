# Candidate account-root preparation

The reference host's Rust `Service` can prepare a separate candidate account root
under the existing application's authenticated account. This is the key-creation
stage of root replacement. It does not select a new current issuer, issue a device
credential or roster, suspend the old issuer, freeze a witness, or authorize traffic.
The complete authenticated root cutover remains an integration requirement.

An administrator explicitly calls `Store::enable_root_preparations` on an existing
schema-7 account store. This atomic schema-8 upgrade adds the preparation and
request-correlation tables. It preserves the account database, Passkeys, enrollment
history and original key files. Opening the database does not upgrade it. Older
readers that do not admit schema 8 refuse it; they must not recreate the database.
The HTTP, browser and administrative CLI adapters do not yet expose this stage.

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

## Recovery, observation and closure

`Service::account_root_preparation(token, operation)` reads retained public
history. It can report `Prepared` even if the candidate's private files have since
become unavailable. This observation is not proof of current signing capability.
Retrying `prepare_account_root` reopens the original signer and reports a missing,
corrupt or mismatched admitted key as `IssuerUnavailable`; it does not replace it.

`Service::close_account_root_preparation(token, operation)` permanently closes
that candidate operation. An exact retry returns the same closed state. The
preparation cannot then be resumed. Closure preserves private files and current
issuer state; it is neither key erasure nor cancellation of a previously completed
write. All three service calls authenticate before performing work and again
before releasing a result. After restart, log in again to the original account.

The preparation ledger is bounded to 512 retained operations per host store,
including closed entries. Capacity exhaustion is an explicit failure. Do not
reset the database or discard old operation history to make a request succeed.

## Validation boundary

The tests use real WebAuthn signatures from a software authenticator, native root
signers and real storage. They cover request/account isolation, old-key loss,
candidate-key loss, stable original results, explicit upgrade and permanent
closure. Nine process-kill cuts cover schema publication, preparation retention,
key-file reconciliation and closure. The common root-key reconciler also serves
initial enrollment and retains its existing interruption tests.

These tests do not qualify a full root replacement or post-compromise recovery.
Successor enrollment/authorization, the application-account cutover, installed
independent-client coordination and the
[witness root transaction](WITNESS_ROOT_REPLACEMENT.md) must still be connected
without transferring old session secrets or inferring unresolved delivery outcomes.

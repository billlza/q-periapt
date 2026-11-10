# Retained-state credential grants

Renewing a certificate changes current membership. It does not authorize the
original installation to reopen its retained journal. The account host can issue
the SDK's separate same-key credential grant G after an explicit authenticated
decision. No new cryptographic construction is introduced here.

## Enable the host transaction

Stop the service and preserve its original account database and associated key
files. With the same absolute database path and origin, run:

```sh
q-periapt-continuity-reference-app enable-credential-grants "$database" http://localhost:8087
```

This atomically upgrades schema 4 to schema 5, adding a grant table while retaining
all account, enrollment, reapproval and extension records. An exact repeated
upgrade is a no-op. Older schemas remain readable, but grant issuance requires
schema 5; `serve` never upgrades. Older binaries reject schema 5 rather than
silently ignoring the new records. There is no downgrade or reset operation.

## Select and retain one decision

`POST /api/enrollment/credential-grant` accepts `CredentialGrantRequest` under the
existing authenticated same-origin session. Authentication is checked before the
operation and before returning its response. A submitted device report alone is
not account permission. The caller must retain the entire decision before
submission, including:

- `retained`: the original `qperiapt-retained-credential-request/1` export,
  containing the operation ID and public credential, journal and policy context.
- `original_extension` and `previous_extension`: exact host issuance IDs supplying
  the installation's original and previous credentials. Both fields are required;
  explicit `null` selects the original enrollment issuance.
- `successor_extension`: the separately approved, already-issued extension to
  which this installation may move.
- `target_checkpoint`: the independently selected current account roster.

The server verifies the original enrollment belongs to the logged-in account,
the selected certificates match host records, and their extension ancestry is
consistent. The target certificate must still be the current member under the
same nonsuspended account root. It authenticates the reported predecessor roster
and uses the existing SDK G signer and verifier. It checks actual current time
and the current root again at each durable commit.

The original credential and original policy digest define G's retained-state
scope. The host has no policy-history registry: signing that digest is an explicit
account authorization, not proof that it is the installation's actual policy.
The consumer must check its independently retained policy and original owner.
The report's journal ID, original roster, current policy and current-policy
authorization are retained context; this endpoint does not authenticate all of
that context or add it to G's signature. In particular, the response's `journal`
is correlation metadata. SDK G binds the original storage owner, not a journal
ID. Separate policy/witness renewal requirements remain enforced by the SDK.

## Crash and retry behavior

The host first durably reserves the complete decision as Pending, then signs and
stores the exact response as Issued before releasing it. A signing or final
validation failure can leave Pending. Reopening and submitting the same request
either finishes that decision against its still-current target or returns the
exact previously committed response. A changed target, scope or context under
the same operation is refused. Pending decisions do not reserve the account
roster: an intervening roster update can make them ineligible to finish.

`POST /api/enrollment/credential-grant/status` is an authenticated read of the
complete original request. It returns Absent, Pending, Closed, or Issued with the
exact retained response encoded as base64url. It never signs or resumes a pending
issuance. Absent describes that observation only: a delayed request may still
arrive after the query.

`POST /api/enrollment/credential-grant/cancel` durably closes an exact unresolved
decision, including one whose first dispatch has not arrived yet. It verifies
the original account/enrollment association and retains a Closed record before
acknowledging, so delayed issuance of that operation is refused. Repeating that
cancellation is idempotent. It cannot cancel an issued grant or erase history.
If issuance won the race, query and retain its original result. A corrected or
newly selected request needs a new operation and explicit decision; retry never
silently retargets it.

The browser loads the original public retained-state request and requires
explicit original, previous and target credential selections from known host
issuance records. Preparing a review writes the complete decision before any
network dispatch. Approving issuance and requesting cancellation first persist
their respective local intent markers. After an uncertain result, a dedicated
query control observes the server without signing. Browser backup schema 3 keeps
all earlier schema-1/2 enrollment and extension records and refuses conflicting
imports; it does not reset a record after quota or transport errors.

An Issued response remains retrievable after root suspension, expiry or loss of
the root signing file, with valid account authentication. It is a historical
result, not current runtime permission. Consumers still verify their own current
pins, policy, time, grant identity and original installation before activation.
There are at most 512 retained grants per store; requests are bounded to 64 KiB
of JSON and records to 256 KiB. Capacity exhaustion is explicit; no historical
decisions are evicted or rewritten.

## Current validation boundary

Tests cover actual SDK-owned original installations, an installation whose
certificate was already extended before preparation, two later grant cycles,
account isolation, rejected changed inputs, exact cancellation, and real SIGKILL
at the schema, Pending, Issued and Closed commit boundaries. Loopback HTTP tests
drop the connection before reading the issued body, restart the service, log in
again and recover the original response. Authentication tests use real WebAuthn
signatures from a software authenticator with simulated user verification.

The [native CLI](NATIVE_DEVICE.md#recover-the-original-installation) stages and
activates the exact G. Its tests cover actual credential expiry, a closed stdout
pipe after the durable operation, repeated process reopen and publication under
the recovered credential. A native API test also uses a real TCP witness and
requires independent enrollment and proposal approval before recovery succeeds.
Browser model/controller tests cover lost responses, cancellation races, quota
failures, exact integers, preserved backups and visible pending state. They use
explicit HTTP/storage/DOM substitutes. These tests do not establish real-account
browser recovery, expired established-session traffic recovery,
joint-policy/independent-policy CLI qualification or cross-host installed-package
acceptance.

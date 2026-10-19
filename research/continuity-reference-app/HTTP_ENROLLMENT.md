# Reference-host enrollment over HTTP

This optional local host exposes its existing enrollment transactions. It does
not add an account service, WebAuthn requirement or HTTP dependency to the SDK.
The browser currently exposes login only; enrollment controls and installed
independent-client acceptance remain to be connected and qualified.

The server still binds IPv4 loopback and admits one exact `localhost` origin.
Every request must match the configured Host. Every POST must also carry that
exact Origin and `Content-Type: application/json`. All enrollment routes require
the current HttpOnly host session cookie; no submitted account identifier or
device signature replaces that session. Do not export browser cookies to a
device client. The authorized host must separately approve and transfer the
public invitation, original device proof and issued result through its chosen
trusted workflow.

## Endpoints

All paths below start with `/api/enrollment`. Identifiers are JSON arrays of
exactly 32 bytes, matching the existing reference-host DTOs. `request` is the
original SDK request encoded with canonical, unpadded base64url, at most 8192
decoded bytes. JSON bodies are bounded at 64 KiB and unknown fields are rejected.
Unsigned 64-bit integers in responses and checkpoints must be parsed losslessly;
a browser adapter must not round them through JavaScript `Number`.

| Method and path | Body | Result |
| --- | --- | --- |
| GET `/root` | none | Current root, suspension state and complete roster, if one exists |
| POST `/root/prepare` | `{}` | Explicitly prepare or reopen the same original root |
| POST `/root/suspend` | `{}` | Fence future issuance; this is not device revocation |
| POST `/invite` | `request_id` | Original invitation for this caller-retained correlation identity |
| POST `/approve` | `operation`, `request` | 204 after authorizing this exact device request |
| POST `/issue` | `operation` | Exact committed issuance JSON bytes |
| POST `/status` | `operation` | Invited, Approved, Issued, Closed or Reapproved |
| POST `/cancel` | `operation` | 204 after explicitly closing an unissued operation |
| POST `/reapprove` | `previous`, `request_id`, `predecessor`, `request` | Original approved successor, preserving the device intent and proof |

`predecessor` must be present: null for an explicitly selected empty roster,
otherwise the independently selected
current `{version, digest}` checkpoint. All endpoints use the existing service
authorization and transaction implementation. The adapter does not create roots
on reads, enable schemas, choose correlations, advance clocks or re-sign an
issued result. The existing explicit schema-2/3 upgrades are still required.

## Recovery and authority

Persist a nonzero invitation correlation before sending `/invite`. If a response
is lost, retry that correlation instead of creating another device. Keep the
original device store, wrapping configuration and signed request. Approve that
exact request; signing a newly generated identity is not recovery.

An interrupted HTTP request, worker timeout or disconnected socket does not
prove that a database transaction aborted. Reauthenticate as the same account
after server restart and query/retry the original operation. `/issue` returns
the stored response directly, without parsing and reserializing it. `/status`
returns those historical bytes in base64url alongside a **separate current**
root/roster observation. A later roster or suspension does not change history.

Reapproval uses a separately retained new correlation and an explicitly selected
current predecessor. It can recover an expired host approval or a roster
conflict while the original credential interval remains valid. It cannot extend
an expired credential, substitute a signer, reopen a cancellation or silently
follow a newer successor. Old and new operation identities remain distinguishable.

Current root/roster responses are observations to an authenticated host. They
are not self-authenticating trust anchors for a device. Client acceptance still
requires independently authenticated expectations, current signed policy,
trusted time and the original signing owner. The reference's family fixture in
tests is not evidence of live policy admission or permission to send traffic.

## Regression scope

`src/http/enrollment/tests.rs` uses actual loopback TCP, software WebAuthn
signatures and native SDK device proofs. It covers anonymous and wrong-account
refusal, Origin/body/proof boundaries, exact retries, two-device roster conflicts,
explicit reapproval, cancellation and suspension. One client closes the socket
after the issuance headers without consuming credential/roster body bytes;
status recovery and same-database restart return the retained original result.
Server restart invalidates the old session and fresh authentication is required.

This does not substitute for a physical authenticator, an installed independent
consumer, deployed HTTPS, complete credential renewal/replacement or full 0.2.0
lifecycle admission. The existing transaction tests separately cover SIGKILL
cuts and upgrade/commit recovery; these HTTP tests do not claim new SIGKILL cuts.

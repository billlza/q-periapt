# Continuity reference account application

This is an **optional host-application example**, not a prerequisite for using
Q-Periapt. SDK users do not need to run it, create an account here, or contact a
Q-Periapt account service. An embedding application retains its own authentication
and device-authorization policy; it can also use independently administered trust
provisioning where that matches its deployment model.

This unpublished host application is the starting point for the independent
consumer's real account login and device authorization path. It uses
`webauthn-rs 0.5.5` for Passkey registration and authentication. Authentication
belongs to this application; no WebAuthn or HTTP dependency is added to the
cryptographic core.

The HTTP application provides account creation, explicit login, adding a second
Passkey, logout and reopening the original account database. Its private Rust
service now also provides root preparation, explicit device approval, transactional
issuance, exact original-response recovery and an enrollment suspension fence.
The same-origin [HTTP enrollment adapter](HTTP_ENROLLMENT.md) now exposes those
existing transactions using the host login session. The [browser controls](BROWSER_ENROLLMENT.md)
retain original correlations and support explicit approval/reapproval and recovery.
**Installed independent-client acceptance is not connected yet.** A login session
is not a device credential or permission to send Continuity traffic.

The implementation and remaining integration follow the [host-authorized enrollment transaction](ENROLLMENT_TRANSACTION.md).
It binds original requests, explicit approval, complete membership and durable
response recovery; the document distinguishes requirements from implemented behavior.

## Run locally

Use the pinned Rust 1.98.1 toolchain. The nested Cargo workspace and its committed
lockfile keep the application dependency graph separate from the SDK workspace.
This initial listener supports only an explicit HTTP `localhost` origin and binds
IPv4 loopback. It is a local WebAuthn development profile, not a deployed HTTPS
service. Public deployment requires the separate TLS/cookie/host configuration
and installed-package qualification still to be implemented.

Create a new private directory at a location you control, then explicitly
initialize its database. Existing destinations are never replaced:

```sh
mkdir -m 700 /absolute/path/to/new-private-directory
cargo run --locked --manifest-path research/continuity-reference-app/Cargo.toml -- \
  init /absolute/path/to/new-private-directory/accounts.redb http://localhost:8087
cargo run --locked --manifest-path research/continuity-reference-app/Cargo.toml -- \
  serve /absolute/path/to/new-private-directory/accounts.redb http://localhost:8087
```

Open `http://localhost:8087` in a browser supporting the standard WebAuthn JSON
methods. Choose an account name and create its Passkey through the browser's
system interface. Then perform the separate sign-in ceremony. PINs and biometric
checks stay in the authenticator interface; the application receives public
credential data and signed assertions. An account name is a local application
identifier, not proof of ownership of an email address or real-world identity.

After restarting the service, use `serve` with the same database and origin and
sign in again. Session and unfinished ceremony state are intentionally volatile;
a restart invalidates them while retaining the account and credentials. Missing,
corrupt, busy or differently bound storage returns an error and never runs `init`.
Do not reset an existing account database to recover an interrupted operation.

## Authentication boundary

Enrollment is disabled in schema 1. A host administrator may explicitly run
`enable-enrollment` with the existing database path, unchanged origin and the
base64url-encoded 32-byte family from the application's trusted policy setup.
This atomic schema-2 upgrade retains all accounts and credential associations.
Ordinary `serve` never performs that upgrade. The user's existing local account
database has not been upgraded as part of the implementation tests.

`enable-reapproval` explicitly upgrades an enabled schema-2 store to schema 3,
using the same database path and origin. Opening either version remains read-only
with respect to schema. This adds retained approval transitions without rewriting
old enrollment rows or key files. Older readers refuse schema 3 explicitly.

If an unissued invitation loses a roster race or its host approval expires,
`reapprove_enrollment` takes the original operation, exact signed request, a new
caller-retained correlation ID and the independently selected current roster
checkpoint. It preserves the original device key, metadata and credential
interval, closes the old decision and atomically creates an approved successor.
Querying the old operation reports that exact successor. An uncertain reply is
retried with the same arguments; it never silently follows a later successor.
Explicitly cancelled or already-issued decisions cannot be reapproved. A
schema-2 cancelled record lacks the original request and remains terminal after
upgrade. Expired credentials need a separate authorized replacement/renewal flow,
which this pre-issuance reapproval method does not provide.

The service's invitation API requires a caller-retained random request ID. Retry
that same ID after an uncertain reply, even if the host operation ID was lost.
The local profile uses five-minute approval deadlines and one-hour credentials;
these are reference-host choices, not SDK requirements. It bounds active devices
at 32, pending invitations per account at 8 and retained operations at 512 in the
database. Closed operations retain their identities; no automatic history
deletion recovers capacity. Root suspension stops new/pending issuance, not
already issued device traffic. Device revocation/replacement remains to integrate.

- Challenges remain on the server, expire after three minutes, and are consumed
  once before verification. Browser cookies contain only random lookup tokens.
- New accounts are committed before registration succeeds. Concurrent registration
  cannot replace an already committed account. Credential IDs cannot belong to
  two application accounts.
- Registration itself creates no login session. Login verifies a distinct signed
  assertion with user verification, updates retained credential metadata, and
  issues a fresh fifteen-minute server session.
- Adding another Passkey requires the same live login session at both start and
  finish. It retains the original application account ID and WebAuthn user handle.
- POST requests require the exact configured Origin; all requests require the
  exact Host. Cookies are HttpOnly and SameSite=Strict. The initial loopback-only
  HTTP profile deliberately has no HTTPS deployment mode or proxy-header bypass.
- The private database reuses the SDK host-store's exclusive owner and staged
  non-replacing publication. Writes use immediate, two-phase commits. A storage
  or commit error disables that store instance until explicit reopening.

Passkeys can be synchronized across authenticators. They authenticate the host
account and must not be treated as a Continuity device ID, a hardware attestation,
or proof of post-compromise recovery. The next integration must independently
bind the authenticated account and current authority revision to the exact
original enrollment request, complete device description and approved operation.
Credential/roster publication must survive unknown response outcomes.

## Validation

```sh
cargo test --locked --manifest-path research/continuity-reference-app/Cargo.toml
cargo test --locked --release --manifest-path research/continuity-reference-app/Cargo.toml
cargo clippy --locked --all-targets \
  --manifest-path research/continuity-reference-app/Cargo.toml -- -D warnings
```

The authentication tests use the upstream **software test authenticator**, which makes real
WebAuthn signatures but simulates the user-verification flag. They exercise
challenge replay, wrong origins, expiration, account registration races, original
session binding when adding a credential, account persistence, and the HTTP
boundary. They do not substitute for a real browser/authenticator ceremony,
deployed TLS, installed SDK device enrollment or the full 0.2.0 lifecycle.

Enrollment tests use actual native SDK-generated requests, controlled root
signers and signature/roster verification at the current host time. They cover
two devices, conflicting complete-roster predecessors, wrong accounts/requests,
explicit upgrade, missing original keys and retained results under suspension.
Fourteen real child-process SIGKILL boundaries cover both schema upgrades, root
first use, invitation creation, reapproval and issuance commit. Tests reopen the
original client and check that its signing files and request bytes survive a
roster conflict and a newly authorized decision. Synthetic historical-time
fixtures test expiry rejection; they are not real-time expiry measurements.
Three enrollment HTTP scenarios exercise actual loopback TCP, including an
issuance-body disconnect and same-database restart. This is local component
evidence, not installed cross-host or physical-device acceptance. The child entrypoint is a test dispatcher and does
not count as another recovery scenario.

The same transaction suite runs in debug and release configurations. The
tests execute both the enrollment library and the binary's HTTP router over
actual loopback TCP. A successfully built standalone executable alone is not
installed-client or deployed enrollment evidence.

The browser-model and transport regressions run with
`node --test --test-reporter=tap research/continuity-reference-app/tests/web/*.test.mjs`.
They use explicitly substituted HTTP and storage objects. They verify exact u64
round trips, retained operation recovery, write failures, immutable submitted
proofs, historical/current separation, account-bound imports and response errors.
The Rust TCP suite separately verifies that the actual router serves every
browser module with the expected source and MIME type. These checks do not
establish a complete browser-to-installed-device enrollment ceremony.

Protocol references: [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) and
[webauthn-rs](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/).

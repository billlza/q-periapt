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

The current implementation provides account creation, explicit login, adding a
second Passkey, logout and reopening the original account database. **Device
registration approval and Continuity issuance are not connected yet.** A login
session is not a device credential or permission to send Continuity traffic.

The next integration follows the [host-authorized enrollment transaction](ENROLLMENT_TRANSACTION.md).
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
cargo clippy --locked --all-targets \
  --manifest-path research/continuity-reference-app/Cargo.toml -- -D warnings
```

The tests use the upstream **software test authenticator**, which makes real
WebAuthn signatures but simulates the user-verification flag. They exercise
challenge replay, wrong origins, expiration, account registration races, original
session binding when adding a credential, account persistence, and the HTTP
boundary. They do not substitute for a real browser/authenticator ceremony,
deployed TLS, installed SDK device enrollment or the full 0.2.0 lifecycle.

Protocol references: [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) and
[webauthn-rs](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/).

# Continuity reference account application

This is an **optional host-application example**, not a prerequisite for using
Q-Periapt. SDK users do not need to run it, create an account here, or contact a
Q-Periapt account service. An embedding application retains its own authentication
and device-authorization policy; it can also use independently administered trust
provisioning where that matches its deployment model.

The separate [SDK policy authority](SDK_AUTHORITY.md) creates and retains an
operator-owned SDK root and exact signed policies. The [local policy publisher](POLICY_PUBLISHER.md) uses a controlled
protocol-policy signer and independently supplied signed SDK policy inputs.
Its CLI has no account-login dependency. Issuance and public export are separate
from consumer activation and authenticated trust provisioning.

The [native device consumer](NATIVE_DEVICE.md) provides real-time CLI entry points
for original enrollment, accepted-credential extension, supported roster refresh,
and recoverable public advertisement. It uses the SDK's existing controlled signer
and storage owners with independently supplied host approval and policy pins.
The [native session exchange](NATIVE_SESSION.md) consumes its publication through
the independent implementation and serves owned bootstrap, durable inbox delivery
and rekey control. The explicit [TCP reference service](NETWORK.md) connects
native and independent owners with bounded admission and original-operation retry.

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
Ordinary `serve` never performs that upgrade. Implementation tests use isolated
account databases; upgrading an existing deployment is an explicit host action.

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

`enable-credential-extension` explicitly upgrades schema 3 to schema 4. The
authenticated `extend_enrollment_credential` transaction can then extend the
same device key/generation through the existing SDK root-signing primitive. The
caller selects an original issued enrollment, its exact predecessor issuance,
the current roster checkpoint, a retained request ID and the new finite expiry.
It atomically replaces that member's certificate and roster and retains the exact
response. It preserves original enrollment/account records and never creates a
new device key. A suspended root, removed member, changed predecessor or
retargeted retry is refused. Exact committed retries remain historical results.

The certificate-extension transaction does not issue the
retained-session grant G, update a client installation, extend protocol policy or
authorize old traffic. Replacing the certificate changes its roster membership
commitment; callers must coordinate consumers explicitly. The independent
[client adoption API](../continuity-openssl-peer/ENROLLMENT_CLIENT.md) handles
accepted-but-unprepared state separately. The native candidate and CLI also
support positively tracked Unprepared records. Legacy state reconciliation and
the complete live recovery path remain open. Do not
reset an expired client's original state or substitute this response for G.

`enable-credential-grants` explicitly upgrades schema 4 to schema 5. The separate
authenticated [retained-state grant transaction](RETAINED_GRANTS.md) issues G
only for an exact selected certificate chain and current account roster. Its
pending decision and issued response survive restart. The native CLI can stage,
inspect and activate that exact original operation, with separate witness
proposal/approval when required. The browser separately prepares a reviewable
decision, approves issuance, queries the original result without signing, and
cancels an unissued decision. Its recovery backup preserves the earlier
enrollment and certificate-extension records. Real-account recovery through the
browser and native consumer still needs its separate runtime acceptance.

The native [policy-only consumer](POLICY_RENEWAL.md) exports original P requests,
verifies separate account/policy approvals, adopts the exact local operation and
recovers its historical result. `enable-policy-approvals` explicitly upgrades the
account host from schema 5 to 6, adding a durable, authenticated P decision ledger.
The protected policy publisher supplies the other approval independently.
The browser verifies a public policy bundle before presenting its exact interval
and statement for separate approval. Schema-4 browser backups retain enrollment,
credential renewal, G and P history under the same cache key. Query/cancel and
byte-exact result recovery are integrated. The
[witnessed native P flow](WITNESSED_POLICY_RENEWAL.md) preserves the original
session through authenticated R/P/R in the software-Passkey HTTP workload.
Human browser P acceptance and composed G/P/R with both peers' policy expiry
remain open.

The account host also supports an explicit [device replacement](DEVICE_REPLACEMENT.md).
`enable-device-replacements` upgrades schema 6 to 7 without rewriting old account,
key or issuance records. A signed-in account selects an original issued operation
and exact current roster; a new invitation preserves its device ID and advances
one generation. The replacement must prove possession of fresh classical and PQ
keys. Its credential, replacement roster and exact response commit together.
Schema-5 browser records preserve all earlier operations under the same cache key.
Account issuance and [witness replacement](WITNESS_REPLACEMENT.md) are separate
durable steps; account issuance alone does not retire an old witness journal.

The service's invitation API requires a caller-retained random request ID. Retry
that same ID after an uncertain reply, even if the host operation ID was lost.
The local profile uses five-minute approval deadlines and one-hour credentials;
these are reference-host choices, not SDK requirements. It bounds active devices
at 32, pending invitations per account at 8 and retained operations at 512 in the
database. Closed operations retain their identities; no automatic history
deletion recovers capacity. Root suspension stops new/pending issuance, not
already issued device traffic. The HTTP-to-witness replacement workload now exercises fresh independent device
keys, peer-roster admission, bidirectional messages, rekey and service recovery.
Standalone device revocation, own-account survivor roster refresh and physical
consumer replacement remain separate integration requirements.

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
Fourteen original child-process SIGKILL boundaries cover the first two schema upgrades, root
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

### Required Continuity witness

`q-periapt-continuity-witness` hosts the existing Continuity `AnchorStore`. It is
separate from the policy-agent witness protocol. It requires no Passkey account:
account login remains the responsibility of whichever application authorizes
device enrollment.

Retain a new nonzero 32-byte witness identity before first use, encode it as
unpadded base64url, and use an absolute database path in a private directory:

```sh
q-periapt-continuity-witness init "$WITNESS_DB" "$WITNESS_ID"
q-periapt-continuity-witness export "$WITNESS_DB" "$WITNESS_ID" "$EMPTY_PRIVATE_EXPORT"
q-periapt-continuity-witness serve "$WITNESS_DB" "$WITNESS_ID" 127.0.0.1:9009
```

Initialization retains the original signing identity before publishing its
wrapping key, encrypted signer and witness database. After interrupted `init`,
use `prepare` on the same database and identity. Once ready, missing or corrupt
files fail; neither `prepare` nor `serve` recreates them. Preserve the host
database and its `witness-*.wrap`, `witness-*.signer` and `witness-*.redb` files.
Distribute `witness-pin.json` independently, and select that exact pin in the
signed session policy. Witness storage must remain independent of device
journal snapshots; restoring a witness backup can undermine monotonicity.

Both native-device and independent-session `prepare` commands export
`{"preparation":"RequiresWitnessEnrollment","subject":[...],"head":[...]}`.
Retain that public JSON. It is an inactive genesis, not enrollment or permission.
The operator separately authenticates the exporting device and approves the
exact journal and image digest. A private trusted approval JSON has schema
`qperiapt-witness-enrollment-trust/1`, the independently selected `account`
(`RootInfo`), `device`, `generation`, `journal`, `genesis_head`, signed
`certificate` (base64url), and `policy` containing the existing `pins` and
`materials` objects. Do not populate its trust or approved digest from an
untrusted network request.

```sh
q-periapt-continuity-witness enroll "$WITNESS_DB" "$WITNESS_ID" \
  "$APPROVED_TRUST_JSON" "$DEVICE_PREPARATION_JSON"
```

This local operator command verifies current credential, roster and policy
signatures, the selected device and journal, the exact approved head, and the
policy's required witness. Exact retries do not reset an advanced entry. Ordinary
TCP requests cannot enroll devices or choose trust roots. Concurrent local
operator contention fails explicitly; retry the same approval after the
current operation ends.

The framed TCP carrier authenticates every request and response through the
existing pinned witness protocol; it does not conceal public metadata.
Incomplete connections and operation deadlines use the bounded reference
network service. Lost replies require reconciliation against the original state.
This command surface covers first use and data-plane state progression.
The operator also exposes [device-generation replacement](WITNESS_REPLACEMENT.md)
with exact preparation, atomic commit and historical outcome observation.
The native survivor and witness also expose [own-account roster refresh](ROSTER_REFRESH.md),
preserving the original device, journal and established sessions through an
explicitly approved roster/head transaction, including after independent witnessed
P renewal. The witness also supports [original credential renewal](WITNESSED_CREDENTIAL_RENEWAL.md)
under P0 or an acknowledged independent P. Joint T approval, account-root
replacement and witness replication remain separate operator requirements.

Protocol references: [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) and
[webauthn-rs](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/).

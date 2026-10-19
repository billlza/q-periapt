# Local protocol-policy publisher

`q-periapt-policy-publisher` is a local operator tool in this optional reference
application. It has no login endpoint, Passkey requirement or Q-Periapt account.
An embedding host controls access to its private database and signing files.
The cryptographic SDK does not require this reference tool.
Qualification covers Apple Silicon/macOS and Linux x86_64. Intel Mac is outside
the project's support scope.

The publisher uses the existing native `PolicySigningKey`, protected signing
files, private redb backend and `Runtime::from_signed_policy`. It does not add a
signature implementation. SDK policy trust is supplied independently by the
host: an expected SDK root, exact trusted SDK state, signed document and signature.
The tool verifies them with the real SDK before retaining them. An incoming
distribution bundle cannot establish trust in its own root. This tool does not
generate an SDK root or replace the host's SDK policy authority. The separate
[SDK policy authority](SDK_AUTHORITY.md) can generate and retain an operator's
SDK root and export the four inputs through its own recoverable ledger.

The current independent consumer supports SDK schema 1 with `min_nist_level=3`,
`default_profile="ContextBound"`, `allowed_kems=["ML-KEM-768","X25519"]`,
`allowed_sigs=["ML-DSA-65"]` and an empty `deprecated` list. Its SDK version must
match the independently retained state. Other SDK policies may be valid for native
consumers while remaining unsupported by this independent consumer.

## First use

Build the tool with the pinned repository Rust toolchain:

```text
cargo build --locked --release --manifest-path research/continuity-reference-app/Cargo.toml \
  --bin q-periapt-policy-publisher
```

Choose and retain a nonzero 32-byte publisher ID encoded as unpadded base64url.
It identifies local persistent state; it is not an account or authentication secret.
Place the database beneath an existing private `0700` directory. Use absolute,
canonical paths without symlink components; macOS temporary paths may need the
`/private/var/...` spelling. Inputs are existing private, singly linked, regular
`0600` files admitted by the host-store file API. The four SDK inputs are public
material, but their trusted provisioning/integrity remains the operator's duty.

```text
q-periapt-policy-publisher init /absolute/private/publisher.redb PUBLISHER_ID \
  /absolute/private/sdk-root /absolute/private/sdk-state \
  /absolute/private/sdk-document /absolute/private/sdk-signature
```

The database retains the original SDK inputs and signing-file identity before
creating the wrapping key and protocol signer. `init` refuses an existing
database. If interrupted, use `prepare` with the same database and publisher ID.
It resumes the original preparation; a Ready publisher never replaces missing
keys. Partial/corrupt key files remain errors. The SDK input is fixed in schema 1;
SDK authority/policy replacement requires a separate future explicit transition,
not a second `init` over the old state.

The returned authority contains the policy family and public roots. That family
can be supplied to the account application's existing `enable-enrollment`
command. Account roots and protocol-policy roots are different roles: this
authority output is not the browser's client account-authority profile.

## Issue, recover and export

Prepare a request with explicit choices:

```json
{
  "bootstrap_mode": "reusable_both",
  "valid_from": 1792400000,
  "valid_until": 1792403600,
  "send_budget": 100,
  "anchor": { "kind": "local_only" }
}
```

Those timestamps illustrate the encoding; supply a currently valid interval.
The CLI reads the host OS clock and has no time override. `bootstrap_mode` can
also be `disabled`, which disables new bootstraps; it does not substitute for
existing-session revocation. For `anchor.kind = "required"`, also supply
`identity` as an array of 32 byte values and `key` as the base64url witness public
key. There is no automatic fallback to local-only storage.
Unknown fields are rejected, including witness fields on a `local_only` request.

```text
q-periapt-policy-publisher issue DB PUBLISHER_ID OPERATION_ID REQUEST_JSON EMPTY_EXPORT_DIR
q-periapt-policy-publisher result DB PUBLISHER_ID OPERATION_ID ANOTHER_EMPTY_EXPORT_DIR
q-periapt-policy-publisher authority DB PUBLISHER_ID
```

Each operation ID is another retained nonzero 32-byte base64url value. The owner
assigns increasing protocol-policy versions; callers cannot choose a huge version
by mistake. It commits the original request before signing and the complete signed
result before returning it. Unknown outcomes are reconciled by reopening the same
database and querying/retrying the same operation. A retry cannot change the
interval, budget, bootstrap mode or witness. An unreleased signing attempt may
use new signature randomness after interruption, but must retain the exact signed
body. A committed result is returned byte-for-byte, including after its expiry.

The export directory must be existing, private and empty. It receives
`policy-pins.json`, `policy-materials.json` and `authority.json`. Existing files
are never overwritten. A partial export stays intact; retrieve the same operation
into another empty directory. The original result remains in the database.
Historical result/export needs no private signing key, so lost signer files do
not make already-issued public evidence unreadable. New issuance still fails.

Provision `policy-pins.json` through an authenticated operator channel. Distribute
`policy-materials.json` separately. The independent client's existing `PolicyInputs`
consumes these formats and checks signatures, SDK binding, current validity,
witness requirements and exact version/digest pins. The presence of both files
in one export directory does not authenticate their provisioning channel.
Issuance also does not automatically install or activate a policy in consumers.

## Pending work and limits

Only one signing request can be pending. An expired pending request cannot be
backdated or silently replaced. The operator can explicitly terminate it:

```text
q-periapt-policy-publisher cancel DB PUBLISHER_ID OPERATION_ID
```

Cancellation retains the operation and consumes its assigned version. It cannot
cancel an issued policy; publish a separately authorized successor when needed.
This reference retains at most 512 operations, including cancellations, and never
evicts history to make room. Capacity exhaustion is an explicit error; archival
or storage upgrade is not yet implemented. Local commit ordering does not provide
an attacker-resistant rollback witness. The wrapping key and signing file must
remain protected; no hardware-keystore or cryptographic-erasure claim is made.

SDK/policy-authority replacement, host activation/distribution,
actual browser-authorized independent device enrollment, full session CLI and the
remaining 0.2.0 release requirements remain separate work. The current qualification
uses the native SDK authority CLI and a witness test pin. It does not establish
a deployed consumer trust channel or a running witness service.

## Checks

Rust tests cover exact SDK pins/signatures, monotonic original results, explicit
choices, witness key separation, private-key loss, four key-creation cuts, three
publication cuts and pending-expiry/cancellation. Private test directories and
failed diagnostics are retained. The child dispatcher is counted separately from
behavioral tests.

`tests/policy_interop.py` runs both actual operator CLIs. It creates the SDK root
through the native protected signer, then checks SDK and protocol-policy signatures
using the selected independent OpenSSL implementation. It verifies exact re-export/retry, immutable
requests, version progression, required-witness binding, disabled-bootstrap refusal
and independent pin/material mismatch. Contradictory anchor fields are rejected
before signing or allocating a version. Installed-wheel qualification is separate
from a source import. These checks do not establish user/device authorization,
power-loss recovery, secure erasure, post-compromise secrecy or release readiness.

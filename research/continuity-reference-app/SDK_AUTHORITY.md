# Local SDK policy authority

`q-periapt-sdk-policy-authority` creates an operator's SDK policy root and signs
exact SDK policy documents. Its output feeds the existing protocol-policy
publisher and SDK consumers. It has no account, login or Passkey dependency.
Operators who already use another signing authority can continue supplying its
signed SDK inputs directly. Qualification targets Apple Silicon/macOS and Linux
x86_64; Intel Mac is outside the support scope.

The root is held by a dedicated native `SdkPolicySigningKey`. It reuses the
existing encrypted signing-file and protected-filesystem implementation. Its
role cannot open account, device, witness or protocol-policy key files, and those
roles cannot open its file. The API exposes the SDK's ML-DSA-65 public key and
signs only validated SDK policy documents. It offers no private-key export or
arbitrary-message signing operation. The established SDK signature encoding,
policy schema and 36-byte trusted-state encoding are unchanged.

## First use

Build both operator binaries with the pinned repository Rust toolchain:

```text
cargo build --locked --release --manifest-path research/continuity-reference-app/Cargo.toml \
  --bin q-periapt-sdk-policy-authority --bin q-periapt-policy-publisher
```

Choose an existing private `0700` directory and canonical absolute paths without
symlink components. Retain a nonzero 32-byte authority ID, encoded as unpadded
base64url, before invoking `init`. This public identity identifies the original
ledger; it is not a credential. For example, generate an ID and keep the result
in your operator configuration:

```text
python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode())'
q-periapt-sdk-policy-authority init /absolute/private/sdk-authority.redb AUTHORITY_ID
```

`init` refuses an existing database. The original signing-file identity commits
before key creation. If preparation was interrupted, resume it with:

```text
q-periapt-sdk-policy-authority prepare /absolute/private/sdk-authority.redb AUTHORITY_ID
q-periapt-sdk-policy-authority authority /absolute/private/sdk-authority.redb AUTHORITY_ID
```

The returned `root` is base64url public material. `allocated_version` is the highest
reserved version, including cancelled requests; `pending` identifies the original
unfinished request, if any. A Ready authority never regenerates missing keys.
Keep its wrapping key protected separately from database backups. This is a
trusted-host file backend, not a hardware keystore or an anti-rollback witness.

## Issue and recover the exact policy

Store the intended TOML in a private regular `0600` file. Version 1 is the first
allocation. This explicit profile is supported by the independent consumer:

```toml
schema_version=1
policy_version=1
min_nist_level=3
default_profile="ContextBound"
allowed_kems=["ML-KEM-768","X25519"]
allowed_sigs=["ML-DSA-65"]
deprecated=[]
```

Retain another nonzero 32-byte base64url operation ID before each new request.
Create an empty private export directory, then run:

```text
q-periapt-sdk-policy-authority issue DB AUTHORITY_ID OPERATION_ID POLICY_TOML EMPTY_EXPORT_DIR
q-periapt-sdk-policy-authority result DB AUTHORITY_ID OPERATION_ID ANOTHER_EMPTY_EXPORT_DIR
```

The document must use exactly `allocated_version + 1`. The tool never rewrites
policy bytes, jumps to a caller-selected large version, or reuses an allocated
version. It persists the exact request before signing and the exact signed result
before returning it. After an unknown outcome, reopen the same database and
retrieve or retry that same operation and document. A committed retry returns
identical bytes; a changed document under the same operation is rejected.

The export contains four public files: `sdk-root`, `sdk-state`, `sdk-document`,
and `sdk-signature`. Existing files are never overwritten. Partial exports remain
intact; retrieve the same operation into a different empty directory. Historical
results remain readable without the private signing files. New signing and
preparation still fail if an admitted private key is missing.

To start the separate protocol authority, supply those exact files:

```text
q-periapt-policy-publisher init /absolute/private/protocol.redb PROTOCOL_PUBLISHER_ID \
  /absolute/private/export/sdk-root /absolute/private/export/sdk-state \
  /absolute/private/export/sdk-document /absolute/private/export/sdk-signature
```

Continue with [protocol-policy publication](POLICY_PUBLISHER.md). Provision client
root/state pins through an authenticated operator channel. Generating a signature
or putting a root beside it does not authorize that root for a consumer. Publishing
a successor also does not automatically activate it in an existing SDK store,
protocol publisher or session.

## Cancellation, resource use and recovery limits

Only one request can be pending. If the operator decides not to complete it:

```text
q-periapt-sdk-policy-authority cancel DB AUTHORITY_ID OPERATION_ID
```

Cancellation retains the original operation and consumes its version. Issued
policies cannot be cancelled. A fresh operation must use the next version.

Each document is bounded by the SDK's 64 KiB limit and each stored record by
128 KiB. Operations use indexed reads and retain their full history; no fixed
512-operation ceiling or automatic history eviction is added to the SDK issuer.
The database grows with accepted requests and cancellations. Operators must
provide storage capacity; an I/O/unknown-commit error invalidates the current
instance and requires reopening the original ledger, never resetting it.

The SDK schema still uses `u32` versions. Sequential allocation prevents a
mistaken version jump through this tool; it does not recover a compromised root,
provide infinite versions, or stop an attacker holding the key from signing
outside the ledger. Configure consumer trust and independent recovery separately;
see [SDK root recovery](../../docs/SDK_HOST_STORE.md#independent-online-root-recovery).
This tool does not yet issue recovery authorizations or rotate authorities. It
also does not add expiration fields to the existing SDK schema. Protocol-policy
validity and host freshness requirements remain separate.

Local commit ordering does not defeat rollback of the whole trusted filesystem,
prove power-loss durability, or erase old pages/backups cryptographically. Real
host-authorized enrollment, live consumer renewal/replacement, full session
lifecycle and final 0.2.0 admission remain separate work.

## Verification

Native signer tests cover SDK signature compatibility, role/identity/key
separation, immutable reopening, malformed and stronger-policy refusal, missing
or corrupt files, and closed capabilities. Issuer tests cover exact retries,
version jumps, cancellation, private-key loss, four preparation cuts and three
publication cuts plus a pending-cancellation cut using real killed processes.

The CLI interoperability harness creates the native SDK root, issues two SDK
policies, feeds the first into the separate native protocol publisher, and verifies
both SDK signatures and three protocol policies with the selected independent
OpenSSL implementation. The witness pin remains an explicit test input. These
checks do not authenticate a real user or activate a consumer's trust configuration.

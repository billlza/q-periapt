# Standard TLS interoperability (0.2.0-alpha.1 development)

`q-periapt-rustls` now has an explicit `standard-tls` feature with
`standard::MutualTlsClient` and `MutualTlsServer`. The default private provider
and its `0xFE01`/`0xFE02` groups are retained separately. Choosing the standard
entry point is an explicit application configuration decision, not a fallback
from a failed ContextBound handshake or a projection of its signed policy.

## Enforced transport contract

The standard wrappers keep their upstream configurations private. They allow
only TLS 1.3 and rustls/AWS-LC's existing `X25519MLKEM768` implementation. They do
not change its wire shares, standard group identifier or concatenated secret.
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) defines this construction;
it is not Q-Periapt's 32-byte ContextBound combiner. No new primitive or custom
standard-group arithmetic was introduced.

Both peers require explicit, nonempty certificate trust anchors and certificate
authentication. Client server-name validation and mandatory server client-cert
validation use rustls's standard verifiers. The caller must still authorize a
verified client identity before granting application access; a valid chain alone
does not grant every application permission. TLS certificates in the local
interop test use classical ECDSA signatures. Hybrid key agreement is not a claim
of post-quantum certificate authentication.

Session resumption and early data are disabled in this initial API, so each
connection performs a fresh full handshake. There is no classic-only group,
TLS 1.2 path or automatic retry downgrade. The TLS 1.3 restriction survives Cargo
feature unification that enables `rustls/tls12` for another dependency.

Constructors consume `RootCertStore`, a certificate chain and `PrivateKeyDer`.
Client `connect(ServerName)` and server `accept()` return normal rustls connection
states. The application supplies transport I/O, timeouts, cancellation and
connection budgets. Configuration cloning shares the upstream owner; it does
not regenerate or copy raw hybrid exchange secrets.

This API does not authenticate a Q-Periapt policy digest, device/role statement,
or business context. The separate [reference-connection feature](SDK_CONNECTION.md)
now implements application confirmation on the authenticated channel. The fixed private-provider
`TLS_CONTEXT` string still does not become a per-session policy commitment.

## Reproduce local independent-peer checks

```sh
cargo test --locked -p q-periapt-rustls \
  --features standard-tls,bench-baseline,rustls/tls12
cargo clippy --locked -p q-periapt-rustls --all-targets \
  --features standard-tls,bench-baseline,rustls/tls12 -- -D warnings
cargo build --locked -p q-periapt-rustls --example standard_peer --features standard-tls
sh artifact/python-run.sh artifact/standard_tls_interop.py \
  --openssl /absolute/path/to/openssl --output target/standard-tls-interop-run
```

Use a new output directory per run. OpenSSL must actually expose the required
group; missing capability is a failure, never a skipped success. The script
requires the intended certificate, group or protocol rejection reason for every
negative case; a failed connection or nonzero exit alone does not pass a gate.
The script
uses only loopback endpoints, reserves ephemeral ports through the actual server,
sets process deadlines, and reaps its child processes on failure. OpenSSL's
[`s_client` verification options](https://docs.openssl.org/3.6/man1/openssl-s_client/)
include `-verify_return_error`, hostname verification, explicit trust and client
certificate/key material.

The driver first copies the Rust diagnostic into a run-owned executable and
checks its identity again at completion. Concurrent Cargo feature builds cannot
replace the executable between scenarios. The OpenSSL executable identity and
version are recorded separately; complete transitive package qualification is
still a release gate.

Fixtures are generated test credentials in a mode-0700 directory, with files
created mode 0600. Diagnostic output records public handshake metadata and
application success, never test private keys or OpenSSL's HTTP session page.
CI uploads the sealed diagnostic executable and top-level logs/manifest,
excluding the fixture directory.

The macOS ARM64 run with OpenSSL 3.6.3 passed eight cases: successful application
data in both client/server roles, wrong hostnames in both roles, classic-only
peers in both roles, an anonymous client, and TLS 1.2. Rust integration tests also
cover wrong trust anchors, mismatched identity keys, fragmented TLS records,
full-handshake reuse of immutable configurations, and rejection of private groups.
The first diagnostic failed because macOS accepted sockets inherited nonblocking
mode; explicitly restoring blocking mode before deadline-bounded I/O fixed it.
The failed run and corrected run are retained separately.

The new Ubuntu 26.04 CI job declares these checks against its OpenSSL 3.5 provider;
hosted execution has not occurred. This remains source/local interoperability
evidence. Installed package verification, Linux/device execution, dependency
and CBOM profiles for the AWS-LC path, durable host policy state,
and the Swift/macOS-to-Rust/Linux reference connection
remain in the [readiness ledger](SDK_0_2_RELEASE_READINESS.md).

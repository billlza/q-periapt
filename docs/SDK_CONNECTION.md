# Authenticated SDK connection (0.2.0-alpha.1 development)

The `q-periapt-rustls/reference-connection` feature supplies one bounded TLS and
message engine. C exposes it through additive **ABI 2** functions. Swift's
`QPeriaptClient` and `QPeriaptConnection` drive that engine over Apple Network TCP.
The C library now includes the standard TLS provider; its platform builds,
dependency inventory, size/performance and installed packages still need release
qualification. JVM/JNI/WASM owner APIs have not acquired this connection API.

The local Swift/Rust TCP path uses a [durable policy store](SDK_HOST_STORE.md)
on both peers. The [installed-package qualification](SDK_INSTALLED_CONNECTION.md)
now exercises the complete Swift ZIP and exact Rust crate archives in external
applications on macOS. Native Rust/Linux server execution remains an open gate;
the local result does not establish the required cross-platform acceptance.

## Transport and authority

Endpoints explicitly choose TLS 1.3 with the unmodified standard
`X25519MLKEM768` group, mutual X.509 authentication, and ALPN `qperiapt-sdk/1`.
Resumption, 0-RTT, TLS 1.2 and classic fallback are absent. Both peers pin the
exact peer leaf certificate in addition to normal TLS verification; the client
also checks the explicit server name. There is no trust-on-first-use discovery.

The local SDK runtime must already have verified its ML-DSA-65 signed policy and
the host must persist its rollback state before admitting use. Its ContextBound
policy identity is application metadata confirmed **inside** this explicitly
chosen standard transport. It does not redefine or authorize the standard TLS
combiner or its certificate algorithms. The private `0xFE01`/`0xFE02` providers
and the existing ContextBound KEM bytes are unchanged.

The association accepts only the configured certificate identity with a matching
policy/context statement. That statement does not prove a remote machine is
running the SDK, obeying the policy, or uncompromised. No device attestation,
general multi-user authorization or post-quantum certificate signature claim is
made. Each peer's application must provision its trust root, certificate pin and
application context through a trusted channel.

## Version 1 application bytes

All lengths and sequence integers below are unsigned big-endian. A frame is
`u32(body length) || body`. Body length is 1 through 65,545; the length is checked
before allocating storage. An empty application payload is valid.

| Body kind | Body after its one-byte kind |
| --- | --- |
| `1` client confirmation | `policy(68) || context(32) || client certificate hash(32) || server certificate hash(32) || channel binding(32)` |
| `2` server confirmation | Same fields, required to match local values |
| `3` request | `sequence(8) || payload(0..65536)` |
| `4` response | `sequence(8) || payload(0..65536)` |

`policy` is `SHA256(pinned ML-DSA verification key) || policy version(4) ||
SHA3-256(exact signed policy bytes)(32)`. The latter 36 bytes are the existing
trusted policy state. Certificate hashes are SHA-256 of the exact leaf DER,
ordered by TLS client/server roles, never by local/peer order.

`context` is SHA-256 of `ASCII("QPeriapt-SDK-Connection-v1") || 0x01 ||
u32(application context length) || application context`. `0x01` identifies the
explicit standard TLS transport. This is a new application-protocol commitment,
not a replacement for fields in the pre-existing ContextBound transcript.
Matching commitments rely on the hash's collision resistance.

The channel binding follows [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html):
the TLS exporter label is `EXPORTER-Channel-Binding`, its context is empty and
its output is 32 bytes. It is public channel-binding data, never a traffic key.
One association, including its confirmation and request stream, occupies one
fresh TLS connection. Repeated confirmations are errors; there is no second
authentication instance or renegotiation on that connection. Ending the
association closes TLS. These restrictions implement the RFC's single-instance
boundary; they do not constitute a proof of the new application protocol.

The client confirms first. The server compares all fields before confirming;
the client compares the reply before returning a usable Swift connection.
Unknown kinds, wrong roles, extra confirmations, malformed lengths, early data
and out-of-order/duplicate sequences terminate the engine. Sequences start at 1,
advance with checked arithmetic, and identify only one connection's exchange.
There is one outstanding request, no automatic retry, durable result store or
exactly-once execution promise. A disconnected caller may not know whether a
server performed an application action; the diagnostic therefore only echoes.

## Ownership, bounds and cancellation

Each endpoint allows 1..64 simultaneous connections (default 8). TLS I/O calls
admit at most 16 KiB; application payloads and context are at most 64 KiB.
Handshake plus confirmation, request/response, and idle deadlines default to
10/5/30 seconds. Limits cap at 120/120/300 seconds. Fragmented input never renews
the current handshake/request budget. Native progress reports the next deadline;
the adapter must wake by it even if a peer sends nothing. No background native
thread enforces idle disposal: an unused owner remains bounded by the endpoint
quota until close/drop or the next deadline-checking call.

Rust's engine requires exclusive mutable access. The native registry serializes
calls for one connection without holding its global table lock during crypto.
Fatal TLS/framing/EOF/deadline failures close the engine and remove its native
handle; ordinary busy/shape errors do not destroy a healthy connection. Fixed
ABI checks, alias rejection and output-clearing rules apply to every new call.
`message_size` is a snapshot; hosts must serialize its use with `take_*`.

Swift serializes complete operations with an actor. A second request receives
`ERR_NOT_READY` without cancelling the first. Cancellation aborts Network I/O,
resumes the pending continuation once, and releases the native connection before
the task returns. Native calls are bounded and synchronous; storage remains
borrowed until each finishes. Endpoint/runtime close revokes subsequent native
operations; pending Network I/O observes this on the next call, no later than
its admitted deadline. Swift child wrappers retain parent owner storage.

`shutdown()` queues and drains TLS `close_notify` when no request is active;
`close()` immediately aborts, including an active request. Bare TCP EOF is not
an empty successful response. There is no silent reconnect, replay or downgrade.
After failure the caller explicitly creates a new connection.

Native framing and confirmation buffers have wiping owners. Host private-key
inputs and returned plaintext are the host's responsibility, and closing an
owner cannot erase copies already returned to the application. rustls/AWS-LC
TLS internals and compiler/register copies have separate erasure contracts.
The standard TLS key loader takes the owned DER into its zeroizing input before
any trust-root/configuration failure; `PrivateKeyDer` alone is not a wiping Drop
owner. Opaque handles remain ownership/misuse protection, not process isolation.

## Swift use

On macOS, after explicit first provisioning, recover the configured policy
before constructing an endpoint (the directory and store must already exist):

```swift
let persistent = try await QPeriaptPersistentRuntime.open(
    at: storePath, policy: signedPolicy, signature: policySignature,
    trustRoot: pinnedPolicyRoot)
let client = try QPeriaptClient(
    runtime: persistent.runtime, certificateDER: localCertificate, privateKeyDER: localKey,
    peerCertificateDER: pinnedServerCertificate, applicationContext: association)
let connection = try await client.connect(host: "127.0.0.1", port: 9443,
                                          serverName: "server.example")
let reply = try await connection.request(requestBytes)
try await connection.shutdown()
try client.close()
try await persistent.close()
```

The host protects/erases its private-key input copies. A production host also
handles errors and closes the endpoint on failure; the short example omits the
host's provisioning and application-specific error handling. A cancelled disk
operation may have committed; recovery must reconcile the requested policy.

## Reproduce the current diagnostic

```sh
cargo build --locked --release -p q-periapt-ffi
cargo build --locked -p q-periapt-rustls --examples --features reference-connection
swift build --package-path bindings/swift --product QPeriaptConnectionProbe \
  -Xlinker -L"$PWD/target/release" \
  -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors
probe_bin="$(swift build --package-path bindings/swift --show-bin-path)"
sh artifact/python-run.sh artifact/sdk_connection_interop.py \
  --swift "$probe_bin/QPeriaptConnectionProbe" --output target/connection-run
```

Use a fresh output path. The driver freezes the Rust and Swift executables and
the ABI 2 dylib, requires dyld to report that exact library, and checks hashes
after execution. It retains failures and reaps its children. Test keys remain
in the private fixture directory and are excluded from evidence uploads.

The first nine real TCP scenarios pass locally on macOS ARM64: first/reconnect with
empty/1-byte/64-KiB messages; busy rejection without disrupting the first request;
silent-peer handshake timeout; repeated cancellation at capacity one;
request timeout/cancellation; runtime revocation during a request; wrong context;
and wrong hostname. Both peers use explicit provisioning on the first run and
configured-policy recovery thereafter. Three subsequent cases persist a
revocation, reject an old policy after process restart on each peer, and persist
a newer re-enabling policy followed by
successful fresh connections. Native tests separately cover fragmentation, length/sequence
attacks, replay across fresh TLS sessions, duplicate confirmation, missing ALPN
or confirmation, and a reissued certificate with the same public key.

These results do not qualify Linux, installed packages, mobile devices, external
security review or performance. The CI step is
declared but has not run on a hosted runner. See the [readiness ledger](SDK_0_2_RELEASE_READINESS.md).
